import argparse
import os
import stat
import hashlib
import hmac
import base64
import secrets
import threading
import uuid
import time
import json
import logging
import socket
import re
import ipaddress
import tempfile
import requests
import psutil
import yaml
from pathlib import Path
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import List, Optional

from fastapi import FastAPI, BackgroundTasks, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
import uvicorn


# =================== 常量与路径 ===================
HOME_DIR = Path.home()
# /app/config 是 Docker 挂载路径。Windows 上没有这个约定，强行创建会在当前盘符
# 根目录生成 D:\app\config 这样的垃圾目录，因此非 POSIX 系统直接走临时目录，
# 除非通过 EODO_CONFIG_DIR 显式指定。
DOCKER_CONFIG_DIR = "/app/config"


def _resolve_temp_dir() -> str:
    candidates = []
    if os.environ.get("EODO_CONFIG_DIR"):
        candidates.append(os.environ["EODO_CONFIG_DIR"])
    elif os.name == "posix":
        candidates.append(DOCKER_CONFIG_DIR)
    candidates.append(tempfile.gettempdir())

    for cand in candidates:
        try:
            Path(cand).mkdir(exist_ok=True, parents=True)
            return cand
        except (PermissionError, OSError):
            continue
    fallback = tempfile.gettempdir()
    Path(fallback).mkdir(exist_ok=True, parents=True)
    return fallback


TEMP_DIR = _resolve_temp_dir()
CURRENT_DIR = Path(__file__).parent
STATIC_PATH = CURRENT_DIR / "static"
STATIC_PATH.mkdir(exist_ok=True)

CONFIG_FILENAME = ".eodo.config.yaml"
# 会话有效期 12 小时
SESSION_TTL_SECONDS = 12 * 3600
SESSION_COOKIE = "eodo_session"
PBKDF2_ITERATIONS = 200_000


# =================== 日志与配置 ===================
def mask_ips(text: str) -> str:
    """对日志中的 IP 地址做脱敏，保留前后段便于排障，避免完整地址落盘。"""
    if not text:
        return text
    # IPv6：保留前两段与最后一段
    text = re.sub(
        r'\b([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}:)+([0-9a-fA-F]{1,4})\b',
        r'\1:\2:***:\3', text)
    # IPv4：保留前两段与最后一段
    text = re.sub(r'\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.(\d{1,3})\b', r'\1.\2.*.\3', text)
    return text


# 脱敏开关缓存，避免每条日志都读一次配置文件
_MASK_CACHE = {"ts": 0.0, "enabled": True}
_MASK_GUARD = False


def _masking_enabled() -> bool:
    """读取 LogMaskIP 配置，默认开启。带重入保护，防止与 read_config 的日志调用互相递归。"""
    global _MASK_GUARD
    if _MASK_GUARD:
        return _MASK_CACHE["enabled"]
    if time.time() - _MASK_CACHE["ts"] > 30:
        _MASK_GUARD = True
        try:
            _MASK_CACHE["enabled"] = bool(read_config().get("LogMaskIP", True))
        except Exception:
            pass
        finally:
            _MASK_GUARD = False
        _MASK_CACHE["ts"] = time.time()
    return _MASK_CACHE["enabled"]


class IPMaskingFilter(logging.Filter):
    """日志脱敏过滤器。默认开启，可通过配置 LogMaskIP 关闭。"""

    def filter(self, record):
        if getattr(record, "_masked", False):
            return True
        if not _masking_enabled():
            return True
        try:
            record.msg = mask_ips(record.getMessage())
            record.args = ()
            record._masked = True
        except Exception:
            pass
        return True


def setup_logging(file="task"):
    """日志初始化 - 支持持久化存储到/app/config目录"""
    _logger = logging.getLogger(f"task.{file}")
    _logger.setLevel(logging.INFO)

    # 使用Path对象构建日志文件路径，更健壮的路径处理
    log_file_path = Path(TEMP_DIR) / f"eodo.{file}.log.txt"
    log_file = str(log_file_path)

    try:
        # 尝试创建RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=200 * 1024,  # 200KB
            backupCount=5,        # 增加备份数量到5个
            encoding="utf-8"
        )
        # 配置文件处理器
        formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)
        print(f"日志文件已配置: {log_file}")
    except Exception as e:
        # 如果文件处理器创建失败，仅使用控制台日志
        print(f"警告: 无法创建日志文件 {log_file}: {str(e)}")
        file_handler = None

    # 配置控制台处理器
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.INFO)

    # 清除现有处理器并添加新处理器
    if _logger.hasHandlers():
        _logger.handlers.clear()

    _masker = IPMaskingFilter()
    if file_handler:
        file_handler.addFilter(_masker)
        _logger.addHandler(file_handler)
    console_handler.addFilter(_masker)
    _logger.addHandler(console_handler)

    return _logger

logger = setup_logging("task")
cron_logger = setup_logging("cron")


def get_hostname():
    """获取合法主机名。

    原实现遇到中文等非法字符会直接抛异常导致进程无法启动，
    这里改为安全回退：替换非法字符而不是崩溃。
    """
    pattern = r'[^a-zA-Z0-9_-]'
    name = socket.gethostname().lower()
    safe = re.sub(pattern, '-', name)
    if safe != name:
        print(f"警告: 主机名 {name!r} 含不允许的字符，已回退为 {safe!r}")
    return safe[:60] or "eodo"


hostname = get_hostname()

CONFIG_PATH = os.path.join(str(HOME_DIR), CONFIG_FILENAME)


def read_config():
    """读取YAML配置。配置可能不存在，返回空字典。"""
    config_path = CONFIG_PATH
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            data = yaml.safe_load(file)
            return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as exc:
        logger.error(f"配置文件读取失败: {exc}")
        return {}


def write_config(config: dict):
    """写入配置，并收紧文件权限（密钥明文存储，至少保证仅属主可读）。"""
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
    harden_config_perms()


def harden_config_perms():
    """将配置文件权限收紧为 0600。Windows 上 chmod 支持有限，失败静默忽略。"""
    if os.name != "posix":
        return
    try:
        os.chmod(CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except Exception as exc:
        logger.debug(f"配置文件权限收紧失败: {exc}")


# =================== 认证 ===================
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256$%d$%s$%s" % (
        PBKDF2_ITERATIONS,
        base64.b64encode(salt).decode(),
        base64.b64encode(dk).decode(),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_b64, hash_b64 = stored.split('$')
        if algo != 'pbkdf2_sha256':
            return False
        dk = hashlib.pbkdf2_hmac(
            'sha256', password.encode('utf-8'),
            base64.b64decode(salt_b64), int(iters)
        )
        return hmac.compare_digest(base64.b64encode(dk).decode(), hash_b64)
    except Exception:
        return False


def get_auth_config() -> dict:
    auth = read_config().get("Auth")
    return auth if isinstance(auth, dict) else {}


def auth_is_configured() -> bool:
    return bool(get_auth_config().get("PasswordHash"))


def _session_secret() -> str:
    cfg = read_config()
    auth = cfg.get("Auth")
    if isinstance(auth, dict) and auth.get("SessionSecret"):
        return auth["SessionSecret"]
    # 首次使用时生成并持久化
    secret = secrets.token_urlsafe(32)
    auth = auth if isinstance(auth, dict) else {}
    auth["SessionSecret"] = secret
    cfg["Auth"] = auth
    write_config(cfg)
    return secret


def create_session_token() -> str:
    payload = {"exp": int(time.time()) + SESSION_TTL_SECONDS}
    raw = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    sig = hmac.new(_session_secret().encode(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{sig}"


def verify_session_token(token: str) -> bool:
    if not token or "." not in token:
        return False
    raw, sig = token.rsplit(".", 1)
    expected = hmac.new(_session_secret().encode(), raw.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False
    try:
        payload = json.loads(base64.urlsafe_b64decode(raw.encode()).decode())
        return int(payload.get("exp", 0)) > int(time.time())
    except Exception:
        return False


# 公开路径：无需登录即可访问
PUBLIC_PATHS = {"/login", "/api/login", "/api/setup", "/api/auth-status", "/favicon.ico", "/healthz"}
PUBLIC_PREFIXES = ("/static/vendor/",)


def is_public_path(path: str) -> bool:
    if path in PUBLIC_PATHS:
        return True
    return any(path.startswith(p) for p in PUBLIC_PREFIXES)


def host_matches_origin(host: str, origin: str) -> bool:
    """校验 Origin 头的主机部分与请求的 Host 一致。"""
    try:
        o_host = origin.split("://", 1)[-1].split("/")[0]
        o_hostname = o_host.split(":")[0].lower()
        r_hostname = host.split(":")[0].lower()
        return o_hostname == r_hostname
    except Exception:
        return False


# =================== 腾讯云API类 ===================
class QcloudClient:
    def __init__(self, secret, service='teo', version='2022-09-01'):
        self.service: str = service
        self.host: str = f'{service}.tencentcloudapi.com'
        self.version: str = version
        self.algorithm: str = 'TC3-HMAC-SHA256'
        self.content_type: str = 'application/json; charset=utf-8'
        self.http_request_method: str = 'POST'
        self.canonical_uri: str = '/'
        self.canonical_query_string: str = ''
        self.signed_headers: str = 'content-type;host;x-tc-action'

        self.secret_id = secret.get("SecretId")
        self.secret_key = secret.get("SecretKey")

    def signature(self, action, body) -> dict:
        timestamp: int = int(time.time())
        date: str = datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%d')

        payload = json.dumps(body)

        hashed_request_payload: str = hashlib.sha256(payload.encode('utf-8')).hexdigest()
        canonical_headers: str = f'content-type:{self.content_type}\nhost:{self.host}\nx-tc-action:{action.lower()}\n'
        canonical_request: str = (self.http_request_method + '\n' +
                                  self.canonical_uri + '\n' +
                                  self.canonical_query_string + '\n' +
                                  canonical_headers + '\n' +
                                  self.signed_headers + '\n' +
                                  hashed_request_payload)

        # 拼接待签名字符串
        credential_scope = f'{date}/{self.service}/tc3_request'
        hashed_canonical_request = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        string_to_sign = f"{self.algorithm}\n{timestamp}\n{credential_scope}\n{hashed_canonical_request}"

        # 计算签名
        def sign(key, message):
            return hmac.new(key, message.encode('utf-8'), hashlib.sha256).digest()

        secret_date = sign(('TC3' + self.secret_key).encode('utf-8'), date)
        secret_service = sign(secret_date, self.service)
        secret_signing = sign(secret_service, 'tc3_request')
        signature = hmac.new(secret_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        authorization = (f'{self.algorithm} '
                         f'Credential={self.secret_id}/{credential_scope}, '
                         f'SignedHeaders={self.signed_headers}, '
                         f'Signature={signature}')
        # 发送请求
        headers = {
            'Authorization': authorization,
            'Content-Type': self.content_type,
            'Host': self.host,
            'X-TC-Action': action,
            'X-TC-Version': self.version,
            'X-TC-Timestamp': str(timestamp)
        }
        return headers

    @staticmethod
    def format_record(ip: str, port: Optional[int]) -> str:
        """构造源站记录。IPv6 带端口必须用方括号包裹，否则 API 会拒绝。"""
        ip = str(ip).strip()
        if not port:
            return ip
        if ':' in ip and not ip.startswith('['):
            return f"[{ip}]:{int(port)}"
        return f"{ip}:{int(port)}"

    def modify_origin_group(self, zone_id, origin_group_id, iplist, port=None):
        body = {"ZoneId": zone_id, "GroupId": origin_group_id,
                "Records": [{"Record": self.format_record(ip, port), "Type": "IP_DOMAIN", "Weight": 100}
                            for ip in iplist]}
        response = requests.post(
            f'https://{self.host}', headers=self.signature('ModifyOriginGroup', body), json=body
        ).json()
        error = response.get("Response", {}).get("Error", {})
        return error.get("Message", ""), error.get("Code", "")

    def describe_origin_group(self, zone_id, group_name=None):
        name = group_name or hostname
        body = {"ZoneId": zone_id, "Filters": [{"Name": "origin-group-name", "Values": [name]}]}
        response = requests.post(
            f'https://{self.host}', headers=self.signature('DescribeOriginGroup', body), json=body
        ).json()
        return response.get('Response', {}).get('OriginGroups', {})

    def describe_all_origin_groups(self, zone_id):
        """获取指定ZoneID的所有源站组"""
        body = {"ZoneId": zone_id}
        response = requests.post(
            f'https://{self.host}', headers=self.signature('DescribeOriginGroup', body), json=body
        ).json()
        return response.get('Response', {})

    def create_origin_group(self, zone_id, iplist, group_name=None, port=None):
        name = group_name or hostname
        body = {"ZoneId": zone_id, "Name": name, "Type": "GENERAL",
                "Records": [{"Record": self.format_record(ip, port), "Type": "IP_DOMAIN"}
                            for ip in iplist]}
        response = requests.post(
            f'https://{self.host}', headers=self.signature('CreateOriginGroup', body), json=body
        ).json()
        error = response.get("Response", {}).get("Error", {})
        return error.get("Message", ""), error.get("Code", "")

    def modify_dns_record(self, top_domain, sub_domain, record_type, iplist, record_id):

        body = {
                "Domain": top_domain,
                "SubDomain": sub_domain,
                "RecordType": record_type,
                "RecordId": record_id,
                "RecordLine": "默认",
                "Value": list(iplist)[0],
                "TTL": 600
            }
        requests.post(
            f'https://{self.host}',
            headers=self.signature("ModifyRecord", body),
            json=body
        )

    def create_dns_record(self, top_domain, sub_domain, record_type, iplist):

        body = {
                "Domain": top_domain,
                "RecordType": record_type,
                "RecordLine": "默认",
                "Value": list(iplist)[0],
                "SubDomain": sub_domain,
                "TTL": 600
            }
        response = requests.post(
            f'https://{self.host}', headers=self.signature("CreateRecord", body), json=body
        ).json()
        error = response.get("Response", {}).get("Error", {})
        return error.get("Message", ""), error.get("Code", "")

    def delete_dns_record(self, top_domain, record_id):

        body = {"Domain": top_domain, "RecordId": record_id}
        requests.post(f'https://{self.host}', headers=self.signature("DeleteRecord", body), json=body)

    def delete_acceleration_domain(self, zone_id, domain_name):
        """删除加速域名。参考: https://cloud.tencent.com/document/api/1552/86341"""
        body = {"ZoneId": str(zone_id).strip(), "DomainName": str(domain_name).strip()}
        try:
            response = requests.post(
                f'https://{self.host}',
                headers=self.signature("DeleteAccelerationDomain", body),
                json=body
            ).json()
        except Exception as e:
            return f"请求异常: {e}", "Exception"
        error = response.get("Response", {}).get("Error", {})
        return error.get("Message", ""), error.get("Code", "")

    def create_acceleration_domain(self, zone_id, domain_name, origin_type="IP_DOMAIN", origin_group_id=None, origin_address=None, ipv6_status="follow", origin_protocol="FOLLOW", http_origin_port=80, https_origin_port=443):
        """创建加速域名
        参考文档: https://cloud.tencent.com/document/api/1552/86338
        """
        try:
            # 参数验证
            if not zone_id or not domain_name:
                return "ZoneId和DomainName不能为空", "MissingParameters"

            if origin_type == "ORIGIN_GROUP" and not origin_group_id:
                return "源站组ID不能为空", "MissingOriginGroupId"
            if origin_type == "IP_DOMAIN" and not origin_address:
                return "源站地址不能为空", "MissingOriginAddress"

            # 构建请求体
            body = {
                "ZoneId": str(zone_id).strip(),
                "DomainName": str(domain_name).strip(),
                "IPv6Status": ipv6_status,
                "OriginProtocol": origin_protocol
            }

            # 设置端口
            if origin_protocol in ["FOLLOW", "HTTP"]:
                body["HttpOriginPort"] = http_origin_port
            if origin_protocol in ["FOLLOW", "HTTPS"]:
                body["HttpsOriginPort"] = https_origin_port

            # 设置源站信息
            origin_value = origin_group_id if origin_type == "ORIGIN_GROUP" else origin_address
            body["OriginInfo"] = {
                "OriginType": origin_type,
                "Origin": str(origin_value).strip()
            }

            # 发送请求
            response = requests.post(
                f'https://{self.host}',
                headers=self.signature("CreateAccelerationDomain", body),
                json=body
            )

            # 处理HTTP响应
            if response.status_code != 200:
                error_msg = f"HTTP请求失败，状态码: {response.status_code}"
                logger.error(f"创建加速域名失败: {error_msg}")
                return error_msg, f"HTTP_{response.status_code}"

            # 解析响应
            response_json = response.json()

            # 检查是否有错误
            if "Response" in response_json:
                error = response_json["Response"].get("Error", {})
                if error:
                    error_msg = error.get("Message", "未知错误")
                    error_code = error.get("Code", "UnknownError")
                    logger.error(f"创建加速域名失败: {error_msg} (错误码: {error_code})")
                    return error_msg, error_code
                # 腾讯云API响应可能不包含AccelerationDomain字段，但只要没有错误且有RequestId，就应该认为成功
                elif "RequestId" in response_json["Response"]:
                    # 成功创建
                    logger.info(f"加速域名创建成功: {domain_name}")
                    return "", ""
                else:
                    # 响应格式异常
                    error_msg = f"响应格式异常，缺少RequestId字段"
                    logger.error(f"创建加速域名失败: {error_msg}")
                    return error_msg, "InvalidResponse"
            else:
                # 响应格式异常
                error_msg = f"响应格式异常，缺少Response字段"
                logger.error(f"创建加速域名失败: {error_msg}")
                return error_msg, "InvalidResponse"

        except Exception as e:
            # 捕获所有异常
            error_msg = f"创建加速域名时发生异常: {str(e)}"
            logger.debug(error_msg)
            return error_msg, "Exception"

    def describe_dns_record(self, top_domain, sub_domain, record_type):

        body = {
                "Domain": top_domain,
                "Subdomain": sub_domain,
                "RecordType": record_type,
            }
        responses = requests.post(
            f'https://{self.host}',
            headers=self.signature("DescribeRecordList", body),
            json=body
        ).json().get('Response').get('RecordList', [])
        return responses


# =================== 工具类 ===================
class IPv4Tool:
    """处理IPv4地址的工具类"""
    def __init__(self, custom_ip_list=None):
        self.custom_ip_list = custom_ip_list or []

    def get_ipv4_list(self):
        """获取IPv4地址列表，包括自定义IPv4地址"""
        ipv4_list = []

        # 添加用户自定义的IPv4地址
        if self.custom_ip_list:
            for custom_ip in self.custom_ip_list:
                try:
                    # 验证是否为有效的IPv4地址
                    ipaddress.IPv4Address(custom_ip)
                    ipv4_list.append(custom_ip)
                except ValueError:
                    logger.warning(f"无效的IPv4地址: {custom_ip}")

        return set(ipv4_list)


# 本地连通性探测目标：公共 DNS 的 IPv6 地址，只用于建立 TCP 握手验证出栈可达性。
# 不会把本机地址上报给任何第三方。
PROBE_TARGETS = [
    ("2400:3200::1", 53),        # AliDNS
    ("2400:3200:baba::1", 53),   # AliDNS
    ("2606:4700:4700::1111", 53),  # Cloudflare DNS
    ("2001:4860:4860::8888", 53),  # Google DNS
    ("2402:4e00::", 53),         # DNSPod
]


class IPv6Tool:
    def __init__(self, select_iface="", task_id="", ipv6_regex="", custom_ip_list=None,
                 use_third_party_probe=False):
        self.task_id = task_id
        self.ipv6_regex = ipv6_regex
        self.custom_ip_list = custom_ip_list or []
        self.use_third_party_probe = use_third_party_probe
        self.public_ipv6:set[str]|None = self.get_ipv6_list(select_iface)

    def get_ipv6_list(self, select_iface=""):
        # 首先获取所有公网IPv6地址（不进行连通性测试）
        all_ipv6_list = []
        addrs = psutil.net_if_addrs()
        for iface, addr_list in addrs.items():
            if select_iface and iface != select_iface:
                continue
            for addr in addr_list:
                ip = addr.address.split('%')[0]
                if addr.family == socket.AF_INET6 and self.is_public_ipv6(ip):
                    all_ipv6_list.append(ip)

        # 按字母顺序排序
        sorted_ipv6_list = sorted(all_ipv6_list)

        # 如果没有找到IPv6地址，直接返回None
        if not sorted_ipv6_list:
            logger.info(f"[{self.task_id}] 未找到公网IPv6地址")
            return None

        logger.info(f"[{self.task_id}] 共找到 {len(sorted_ipv6_list)} 个公网IPv6地址")

        # 根据用户是否选择了IPv6地址决定不同的检查逻辑
        if self.ipv6_regex:
            selected_ip = None

            # 处理索引格式 @1, @2 等
            if self.ipv6_regex.startswith('@'):
                try:
                    index = int(self.ipv6_regex[1:]) - 1  # 转为0-based索引
                    if 0 <= index < len(sorted_ipv6_list):
                        selected_ip = sorted_ipv6_list[index]
                        logger.info(f"[{self.task_id}] 通过索引 {self.ipv6_regex} 选择IPv6地址")
                        # 对于用户选择的地址，不需要进行连通性测试，直接返回该地址
                        # 因为网卡自动获得的地址可能会有更新，我们只需要检查这个位置的地址是否存在
                        return set([selected_ip])
                    else:
                        logger.warning(f"[{self.task_id}] 索引 {self.ipv6_regex} 超出范围，索引范围应为 @1 到 @{len(sorted_ipv6_list)}")
                except ValueError:
                    logger.warning(f"[{self.task_id}] 无效的索引格式: {self.ipv6_regex}，正确格式应为 @1, @2 等")
            # 处理正则表达式格式
            else:
                try:
                    pattern = re.compile(self.ipv6_regex)
                    selected_ip = next((ip for ip in sorted_ipv6_list if pattern.search(ip)), None)
                    if selected_ip:
                        logger.info(f"[{self.task_id}] 通过正则表达式匹配到IPv6地址")
                        # 对于用户通过正则选择的地址，直接返回
                        return set([selected_ip])
                    else:
                        logger.warning(f"[{self.task_id}] 未能通过正则表达式 '{self.ipv6_regex}' 匹配到任何IPv6地址")
                except re.error:
                    logger.warning(f"[{self.task_id}] 无效的正则表达式: {self.ipv6_regex}")

            logger.warning(f"[{self.task_id}] IPv6地址选择失败，将回退到连通性测试方式")

        # 用户没有选择IPv6地址或选择失败，对所有地址进行连通性测试
        logger.info(f"[{self.task_id}] 正在对所有IPv6地址进行连通性测试")
        reachable = []
        for ip in sorted_ipv6_list:
            if self.public_ipv6_check(ip):
                reachable.append(ip)

        if not reachable:
            logger.warning(f"[{self.task_id}] 所有IPv6地址都无法通过连通性测试")
            return None
        else:
            logger.info(f"[{self.task_id}] 共有 {len(reachable)} 个IPv6地址通过了连通性测试")
            return set(reachable)

    @staticmethod
    def is_public_ipv6(ip):
        try:
            addr = ipaddress.IPv6Address(ip)
            return not (addr.is_link_local or addr.is_private or addr.is_loopback or addr.is_unspecified)
        except ValueError:
            return False  # 非法IP，就认为不是公网

    @staticmethod
    def local_connectivity_check(ip: str, timeout: int = 4) -> bool:
        """绑定指定源地址发起出栈 TCP 连接，验证该地址具备外网连通性。

        相比原先请求 ipw.cn / ping6.network，这种方式不会把本机公网地址
        上报给任何第三方。IPv6 通常无 NAT，能出栈即意味着可入站。
        """
        for target, port in PROBE_TARGETS:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                # 关键：绑定到待验证的源地址，确保测的是这个地址而非默认路由
                sock.bind((ip, 0))
                sock.connect((target, port))
                return True
            except OSError:
                continue
            except Exception:
                continue
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
        return False

    def third_party_probe(self, ip):
        """可选的第三方探测（默认关闭）。

        警告：会把本机公网 IPv6 明文发送给第三方站点，仅在本地探测不可用时使用。
        """
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/89.0.4389.90 Safari/537.36"

        def ipw_cn():
            try:
                res = requests.get(
                    f"https://ipw.cn/api/ping/ipv6/{ip}/1/all",
                    headers={"User-Agent": user_agent},
                    timeout=5
                )
                return '"lossPacket":0' in res.text
            except Exception as e:
                logger.debug(e)
                return False

        def ping6_network():
            try:
                res = requests.get(
                    f"https://ping6.network/index.php?host={ip.replace(':', '%3A')}",
                    headers={"User-Agent": user_agent},
                    timeout=15
                )
                return ', 0% packet loss' in res.text
            except Exception as e:
                logger.debug(e)
                return False

        logger.warning(f"[{self.task_id}] 正在使用第三方站点探测，本机地址会被发送给 ipw.cn / ping6.network")
        return ipw_cn() or ping6_network()

    def public_ipv6_check(self, ip):
        """连通性检测：默认本地出栈测试，可选回退到第三方探测。"""
        if self.local_connectivity_check(ip):
            return True
        if self.use_third_party_probe:
            return self.third_party_probe(ip)
        return False


# =================== 钉钉通知类 ===================
class Dingtalk:
    def __init__(self, webhook):
        self.webhook = webhook

    def notice_no_public_ipv6(self):
        if not self.webhook:
            return
        requests.post(
            self.webhook,
            json={
                "markdown": {
                    "title": "无法获取IP",
                    "text": f"> 信息：{hostname}无法获取公网IPv6，跳过此次更新。"
                },
                "msgtype": "markdown"
            })

    def notice_eo_result(self, site_tag:str, zone_id:str, public_ipv6:List[str], message:str):
        if not self.webhook:
            return
        ipv6_text = [f"- {item}\n" for item in public_ipv6]

        ipv6_content = '\n'.join(ipv6_text)
        requests.post(
            self.webhook,
            json={
                "markdown": {
                    "title": "EdgeOne源站更新",
                    "text": f"### EdgeOne源站更新\n\n"
                            f"**标签：** {site_tag}\n\n"
                            f"**站点：** {zone_id}\n\n"
                            f"**信息：** {message}\n\n"
                            f"**IPV6：** \n\n{ipv6_content}"
                }, "msgtype": "markdown"}
        )

    def notice_dns_result(self, domain:str, public_ipv6:List[str], message:str):
        if not self.webhook or not public_ipv6:
            return
        requests.post(
            self.webhook,
            json={
                "markdown": {
                    "title": "DNS解析更新",
                    "text": f"### DNS解析更新\n\n"
                            f"**域名：** {domain}\n\n"
                            f"**信息：** {message}\n\n"
                            f"**IPV6：** {public_ipv6[0]}"
                }, "msgtype": "markdown"}
        )


# =================== 任务处理 ===================
def get_origin_group_name(config: dict) -> str:
    """源站组名，优先使用用户自定义，回退到主机名。"""
    name = (config.get("OriginGroupName") or "").strip()
    return name or hostname


def update_task(task_id=""):
    config = read_config()
    # 获取自定义IP列表，如果配置中不存在则为空列表
    custom_ip_list = config.get("CustomIPList", [])
    # 确保custom_ip_list是列表类型
    if not isinstance(custom_ip_list, list):
        custom_ip_list = []

    use_third_party = bool(config.get("UseThirdPartyProbe", False))

    # 分离IPv4和IPv6处理
    ipv4_tool = IPv4Tool(custom_ip_list=custom_ip_list)
    ipv6_tool = IPv6Tool(
        select_iface=config.get("SelectIface"),
        task_id=task_id,
        ipv6_regex=config.get("IPv6Regex"),
        use_third_party_probe=use_third_party,
    )

    # 获取IPv4和IPv6地址列表
    ipv4_addresses = ipv4_tool.get_ipv4_list()
    ipv6_addresses = ipv6_tool.public_ipv6 or set()

    # 合并所有地址
    all_addresses = ipv4_addresses.union(ipv6_addresses)

    dingtalk = Dingtalk(config.get('DingTalkWebhook'))
    eo_zones = config.get("EdgeOneZoneId")
    domains = config.get('DnsPodRecord')
    qcloud_secret = config.get('TencentCloud')
    origin_port = parse_origin_port(config.get("OriginPort"))
    group_name = get_origin_group_name(config)

    if not all_addresses:
        logger.info(f"[{task_id}] 无法获取任何IP地址，跳过后续所有步骤。")
        dingtalk.notice_no_public_ipv6()
        return
    else:
        # 记录包含自定义IP的完整地址列表（日志已脱敏）
        if custom_ip_list:
            logger.info(f"[{task_id}] 获取IP地址成功（包含 {len(custom_ip_list)} 个自定义IP）")
        else:
            logger.info(f"[{task_id}] 获取IP地址成功，共 {len(all_addresses)} 个地址")

    if eo_zones:
        eo_client = QcloudClient(secret=qcloud_secret, service='teo', version='2022-09-01')
        # 写入源站组时带上端口，用于和已有记录做比对
        desired_records = {QcloudClient.format_record(ip, origin_port) for ip in all_addresses}

        for zone in eo_zones:
            origin_groups = eo_client.describe_origin_group(zone, group_name)

            if len(origin_groups) >= 1:
                group_id = origin_groups[0].get('GroupId')
                old_list = [i.get('Record') for i in origin_groups[0].get('Records')]
                old_list.sort()
                records = set(old_list)

                if desired_records == records:
                    logger.info(f"[{task_id}] IP 地址列表未发生变更，站点 {zone} 的源站组 {group_name} 无需更新。")
                else:
                    logger.info(f"[{task_id}] 源站地址发生变更，正在更新站点 {zone} 的源站组 {group_name}")
                    error_msg, error_code = eo_client.modify_origin_group(
                        zone, group_id, all_addresses, port=origin_port)
                    error_msg = f"成功更新站点 {zone} 的源站组 {group_name} 。" if not error_code and not error_msg else error_msg
                    logger.info(f"[{task_id}] {error_msg} {error_code}")
                    dingtalk.notice_eo_result(group_name, zone, list(all_addresses), error_msg)
            else:
                logger.info(f"[{task_id}] 站点 {zone} 的源站组 {group_name} 尚未创建。")
                error_msg, error_code = eo_client.create_origin_group(
                    zone, all_addresses, group_name=group_name, port=origin_port)
                error_msg = f"成功创建站点 {zone} 的源站组 {group_name} 。" if not error_code and not error_msg else error_msg
                logger.info(f"[{task_id}] {error_msg} {error_code}")
                dingtalk.notice_eo_result(group_name, zone, list(all_addresses), error_msg)

    if domains:
        dnspod = QcloudClient(secret=qcloud_secret, service='dnspod', version='2021-03-23')

        for domain in domains:
            try:
                sub_domain, record_type, top_domain = domain.split('|')
            except ValueError:
                logger.error(f"[{task_id}] DnsPod 记录配置格式错误，应为 子域名|记录类型|主域名：{domain}")
                continue
            fqdn = '.'.join([sub_domain, top_domain])
            records = dnspod.describe_dns_record(top_domain, sub_domain, record_type)
            record_counts = len(records)

            for record in records:
                if record["Value"] not in list(all_addresses):
                    logger.info(f"[{task_id}] 站点 {fqdn} 存在已过期的解析记录，正在删除。")
                    dnspod.delete_dns_record(top_domain, record['RecordId'])
                    record_counts -= 1

            if record_counts >= 1:
                logger.info(f"[{task_id}] 站点 {fqdn} 查询到至少存在一条有效解析记录, 跳过解析更改。")
            else:
                logger.info(f"[{task_id}] 站点 {fqdn} 不存在可用的解析记录，正在新建解析。")
                error_msg, error_code = dnspod.create_dns_record(top_domain, sub_domain, record_type, all_addresses)
                error_msg = f"成功更新解解析记录 {fqdn} " if not error_code and not error_msg else error_msg
                logger.info(f"[{task_id}] {error_msg} {error_code}")
                dingtalk.notice_dns_result(fqdn, list(all_addresses), error_msg)


def parse_origin_port(value) -> Optional[int]:
    """解析回源端口配置，非法值返回 None（即不指定端口，用默认 80/443）。"""
    if value in (None, "", 0, "0"):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        logger.warning(f"回源端口配置无效: {value!r}，将使用默认端口")
        return None
    if not (1 <= port <= 65535):
        logger.warning(f"回源端口超出范围: {port}，将使用默认端口")
        return None
    return port


# 存储上一次的IP地址列表用于变化检测
last_ip_addresses = set()
last_status = {"id":"", "result":"等待"}


def run_task_in_background():
    task_id = str(uuid.uuid4())
    try:
        cron_logger.info(f"[{task_id}] 启动")

        # 检查IP地址是否发生变化
        global last_ip_addresses
        current_addresses = get_current_ip_addresses()

        if current_addresses != last_ip_addresses:
            cron_logger.info(f"[{task_id}] IP地址发生变化，执行更新任务")
            update_task(task_id=task_id)
            last_ip_addresses = current_addresses
            cron_logger.info(f"[{task_id}] 结束")
            last_status.update({"id": task_id, "result": "结束"})
        else:
            cron_logger.info(f"[{task_id}] IP地址未发生变化，跳过更新")
            last_status.update({"id": task_id, "result": "跳过"})

    except Exception as e:
        logger.debug(e)
        cron_logger.error(f"[{task_id}] 异常")
        last_status.update({"id": task_id, "result": "异常"})


def get_current_ip_addresses():
    """获取当前的IP地址列表（IPv4 + IPv6）"""
    try:
        config = read_config()
        custom_ip_list = config.get("CustomIPList", [])
        if not isinstance(custom_ip_list, list):
            custom_ip_list = []

        # 处理IPv4地址
        ipv4_tool = IPv4Tool(custom_ip_list)
        ipv4_addresses = ipv4_tool.get_ipv4_list()

        # 处理IPv6地址（这里只做网卡枚举，不做连通性测试，避免每轮都发起连接）
        addrs = psutil.net_if_addrs()
        select_iface = config.get("SelectIface") or ""
        ipv6_addresses = set()
        for iface, addr_list in addrs.items():
            if select_iface and iface != select_iface:
                continue
            for addr in addr_list:
                ip = addr.address.split('%')[0]
                if addr.family == socket.AF_INET6 and IPv6Tool.is_public_ipv6(ip):
                    ipv6_addresses.add(ip)

        # 合并地址列表
        return ipv4_addresses.union(ipv6_addresses)
    except Exception as e:
        logger.error(f"获取当前IP地址失败: {str(e)}")
        return set()


def load_interval(default_interval=15):
    cfgfile = CONFIG_PATH
    if os.path.exists(cfgfile):
        with open(cfgfile, "r", encoding="utf-8") as f:
            try:
                config = yaml.safe_load(f)
                if isinstance(config, dict):
                    interval = int(config.get("IntervalMin", 15))
                    if interval < 1: interval = 1
                    return interval
            except Exception as e:
                logger.debug(e)
    return default_interval  # 默认值


class TaskScheduler:
    def __init__(self, interval_min=15):
        self.interval_min = interval_min
        self.scheduler_thread = None
        self.scheduler_stop_flag = threading.Event()
        self.lock = threading.Lock()

    def scheduler_loop(self):
        while not self.scheduler_stop_flag.is_set():
            run_task_in_background()
            for _ in range(self.get_interval() * 60):
                if self.scheduler_stop_flag.is_set():
                    return
                time.sleep(1)

    def get_interval(self):
        with self.lock:
            return self.interval_min

    def set_interval(self, interval_min):
        if interval_min < 1:
            interval_min = 1
        with self.lock:
            self.interval_min = interval_min

    def start_scheduler(self):
        if self.scheduler_thread is None or not self.scheduler_thread.is_alive():
            self.scheduler_thread = threading.Thread(target=self.scheduler_loop, daemon=True)
            self.scheduler_thread.start()

    def restart_scheduler(self, interval_min):
        self.scheduler_stop_flag.set()
        self.scheduler_thread = None
        self.set_interval(interval_min)
        self.scheduler_stop_flag.clear()
        self.start_scheduler()


# 声明全局定时器
scheduler:TaskScheduler = None


# =================== FastAPI 路由 ===================
app = FastAPI()


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """统一处理 CSRF 防护与会话鉴权。"""
    path = request.url.path
    method = request.method.upper()

    # ---- CSRF 防护 ----
    # 写操作必须携带 JSON，杜绝 text/plain 简单请求跨站改写配置
    if method in ("POST", "PUT", "DELETE", "PATCH"):
        ctype = (request.headers.get("content-type") or "").lower()
        if not ctype.startswith("application/json"):
            return JSONResponse(
                {"success": False, "message": "Content-Type 必须为 application/json"},
                status_code=415)
        origin = request.headers.get("origin")
        if origin and not host_matches_origin(request.headers.get("host", ""), origin):
            logger.warning(f"拦截跨站请求: Origin={origin} Host={request.headers.get('host')}")
            return JSONResponse({"success": False, "message": "跨站请求已被拒绝"}, status_code=403)

    # ---- 鉴权 ----
    if is_public_path(path):
        return await call_next(request)

    if not verify_session_token(request.cookies.get(SESSION_COOKIE, "")):
        if path.startswith("/api/"):
            return JSONResponse({"success": False, "message": "未登录"}, status_code=401)
        return RedirectResponse(url="/login", status_code=302)

    return await call_next(request)


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return FileResponse(str(STATIC_PATH / "login.html"))


# 提供静态文件服务
app.mount("/static", StaticFiles(directory=str(STATIC_PATH)), name="static")


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
async def read_root():
    return FileResponse(str(STATIC_PATH / "index.html"))


@app.get('/api/auth-status')
def api_auth_status():
    return {"configured": auth_is_configured()}


@app.post('/api/setup')
async def api_setup(request: Request):
    """首次启动时设置管理密码。仅在未设置过密码时可用。"""
    if auth_is_configured():
        return {"success": False, "message": "密码已设置，如需重置请删除配置文件中的 Auth 段"}
    data = await request.json()
    password = (data.get("password") or "").strip()
    if len(password) < 8:
        return {"success": False, "message": "密码至少 8 位"}
    cfg = read_config()
    cfg["Auth"] = {
        "PasswordHash": hash_password(password),
        "SessionSecret": secrets.token_urlsafe(32),
    }
    write_config(cfg)
    resp = JSONResponse({"success": True, "message": "密码已设置"})
    resp.set_cookie(SESSION_COOKIE, create_session_token(), httponly=True,
                    samesite="lax", max_age=SESSION_TTL_SECONDS, path="/")
    return resp


@app.post('/api/login')
async def api_login(request: Request):
    data = await request.json()
    password = (data.get("password") or "")
    stored = get_auth_config().get("PasswordHash", "")
    if not stored:
        return {"success": False, "message": "尚未设置密码"}
    if not verify_password(password, stored):
        logger.warning("登录失败：密码错误")
        return {"success": False, "message": "密码错误"}
    resp = JSONResponse({"success": True, "message": "登录成功"})
    resp.set_cookie(SESSION_COOKIE, create_session_token(), httponly=True,
                    samesite="lax", max_age=SESSION_TTL_SECONDS, path="/")
    return resp


@app.post('/api/logout')
async def api_logout():
    resp = JSONResponse({"success": True, "message": "已退出"})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.get('/api/status')
def api_status():
    # 简单读取
    log_file = f"{TEMP_DIR}/eodo.cron.log.txt"
    if not os.path.exists(log_file):
        return last_status
    with open(log_file, 'r', encoding='utf-8') as f:
        for line in reversed(f.readlines()):
            if "] " in line:
                tid = line.split("]")[0].split("[")[-1]
                if "异常" in line:
                    return {"id": tid, "result": "异常", "time": line[:19]}
                if "结束" in line:
                    return {"id": tid, "result": "结束", "time": line[:19]}
                if "跳过" in line:
                    return {"id": tid, "result": "跳过", "time": line[:19]}
                if "启动" in line:
                    return {"id": tid, "result": "启动", "time": line[:19]}
    return last_status


@app.post('/api/run-task')
def api_run(background_tasks: BackgroundTasks):
    background_tasks.add_task(run_task_in_background)
    return {"msg": "已触发"}


@app.get('/api/iface')
def api_iface():
    return list(psutil.net_if_addrs().keys())


@app.get('/api/ipv6-addresses')
def api_ipv6_addresses(iface: str = None):
    """获取指定网络接口的IPv6地址列表"""
    ipv6_addresses = []
    addrs = psutil.net_if_addrs()

    # 如果指定了接口且存在
    if iface and iface in addrs:
        interfaces = [iface]
    else:
        # 否则返回所有接口
        interfaces = addrs.keys()

    for interface in interfaces:
        for addr in addrs[interface]:
            ip = addr.address.split('%')[0]
            if addr.family == socket.AF_INET6 and IPv6Tool.is_public_ipv6(ip):
                ipv6_addresses.append(ip)

    return sorted(ipv6_addresses)


def _public_config(cfg: dict) -> dict:
    """返回给前端的配置：剔除 Auth 段，避免密钥哈希与会话密钥外泄。"""
    if not isinstance(cfg, dict):
        return {}
    return {k: v for k, v in cfg.items() if k != "Auth"}


@app.get('/api/config')
def get_config():
    if not os.path.exists(CONFIG_PATH):
        return {}
    return _public_config(read_config())


# 允许前端提交的字段白名单，避免任意键注入
ALLOWED_CONFIG_KEYS = {
    "TencentCloud", "EdgeOneZoneId", "DnsPodRecord", "DingTalkWebhook",
    "SelectIface", "IPv6Regex", "CustomIPList", "IntervalMin",
    "OriginPort", "OriginGroupName", "UseThirdPartyProbe", "LogMaskIP",
}


@app.post('/api/config')
async def post_config(request: Request):
    data = await request.json()
    if not isinstance(data, dict):
        return {"success": False, "message": "配置格式错误"}

    # 只允许白名单内的键，并保留服务端管理的 Auth 段
    filtered = {k: v for k, v in data.items() if k in ALLOWED_CONFIG_KEYS}
    existing = read_config()
    filtered["Auth"] = existing.get("Auth", {})

    interval = filtered.get("IntervalMin", None)
    write_config(filtered)

    # 如果带了 IntervalMin，同步到调度器
    if interval is not None:
        try:
            scheduler.restart_scheduler(int(interval))
        except Exception as e:
            logger.debug(e)
    return {"msg": "配置已保存"}


@app.get('/api/logs')
def get_logs():
    log_file = f"{TEMP_DIR}/eodo.task.log.txt"
    if os.path.exists(log_file):
        lines = open(log_file, encoding="utf-8").readlines()[-100:]
        return {"logs": "".join(lines)}
    return {"logs": ""}


@app.delete('/api/logs')
def clear_logs():
    """真正清除日志文件。原实现只在前端改 DOM 文本，服务端文件并未删除。"""
    cleared = []
    for name in ("task", "cron"):
        path = Path(TEMP_DIR) / f"eodo.{name}.log.txt"
        try:
            if path.exists():
                path.write_text("", encoding="utf-8")
                cleared.append(path.name)
        except Exception as e:
            logger.debug(f"清除日志失败 {path}: {e}")
    return {"success": True, "message": f"已清除 {len(cleared)} 个日志文件"}


@app.post('/api/interval')
async def set_interval(request: Request):
    data = await request.json()
    try:
        val = int(data.get("interval", 15))
    except (TypeError, ValueError):
        return {"success": False, "message": "周期必须为整数"}
    if val < 1: val = 1
    # 修改调度器周期
    if scheduler is None:
        return {"msg": "调度器未初始化，请重启应用"}
    scheduler.restart_scheduler(val)
    # 保存到配置文件
    config = read_config()
    config["IntervalMin"] = val
    write_config(config)
    return {"msg": "已设置周期间隔"}


@app.get("/api/accel-domains")
def get_accel_domains():
    try:
        # 从配置文件中读取已保存的加速域名列表
        config = read_config()
        accel_domains = config.get("AccelDomains", [])
        if not isinstance(accel_domains, list):
            accel_domains = []
        return {"success": True, "domains": accel_domains}
    except Exception as e:
        logger.error(f"获取加速域名列表失败: {str(e)}")
        return {"success": False, "message": str(e)}


@app.get("/api/origin-groups/{zone_id}")
async def get_origin_groups(zone_id: str):
    """获取指定ZoneID的源站组列表"""
    try:
        # 加载配置
        config = read_config()

        # 检查是否有腾讯云密钥配置
        if not config.get("TencentCloud") or not config["TencentCloud"].get("SecretId") or not config["TencentCloud"].get("SecretKey"):
            logger.error("请先配置腾讯云密钥")
            return {"success": False, "message": "请检查腾讯云SecretId和SecretKey配置是否正确"}

        # 创建QcloudClient实例
        client = QcloudClient(config["TencentCloud"])

        # 调用API获取源站组列表
        response = client.describe_all_origin_groups(zone_id)

        # 检查是否有错误
        if "Error" in response:
            logger.error("获取源站组失败：密钥或 ZoneID 可能不正确")
            # 统一错误提示格式
            return {"success": False, "message": f"请检查SecretId、SecretKey和EdgeOne站点配置的ZoneID是否正确"}

        # 格式化返回数据
        origin_groups = response.get("OriginGroups", [])
        groups_data = [{
            "groupId": group.get("GroupId"),
            "name": group.get("Name"),
            "type": group.get("Type")
        } for group in origin_groups]

        return {"success": True, "originGroups": groups_data}
    except Exception as e:
        logger.error(f"获取源站组列表失败: {str(e)}")
        # 统一异常情况下的错误提示
        return {"success": False, "message": f"获取源站组失败，请检查SecretId、SecretKey和EdgeOne站点配置的ZoneID是否正确"}


def _save_accel_domain_to_config(zone_id, domain_name, data):
    """将加速域名保存到配置文件"""
    config = read_config()

    # 构建加速域名配置
    accel_domain = {
        "zoneId": zone_id,
        "domainName": domain_name,
        "originProtocol": data.get("originProtocol", "FOLLOW"),
        "originType": data.get("originType", "ip")
    }

    # 根据类型添加对应的源站信息
    if data.get("originType") == "group":
        accel_domain["originGroupId"] = data.get("originGroupId")
    else:
        accel_domain["originAddress"] = data.get("originAddress")

    # 获取现有列表并检查重复
    accel_domains = config.get("AccelDomains", [])
    if not isinstance(accel_domains, list):
        accel_domains = []
    for domain in accel_domains:
        if isinstance(domain, dict) and domain.get("domainName") == domain_name and domain.get("zoneId") == zone_id:
            raise ValueError("该加速域名已存在")

    # 添加新记录
    accel_domains.append(accel_domain)
    config["AccelDomains"] = accel_domains

    # 保存配置
    write_config(config)


@app.post("/api/create-accel-domain")
async def create_accel_domain(request: Request):
    try:
        data = await request.json()
        zone_id = data.get("zoneId")
        domain_name = data.get("domainName")
        origin_type_param = data.get("originType", "ip")  # "group" 或 "ip"
        origin_group_id = data.get("originGroupId")
        origin_address = data.get("originAddress")
        # 基本验证
        if not zone_id or not domain_name:
            return {"success": False, "message": "站点ZoneID和加速域名不能为空"}

        # 源站验证
        if origin_type_param == "group" and not origin_group_id:
            return {"success": False, "message": "源站组ID不能为空"}
        if origin_type_param == "ip" and not origin_address:
            return {"success": False, "message": "源站地址不能为空"}

        # 加载配置
        config = read_config()
        qcloud_secret = config.get('TencentCloud')
        if not qcloud_secret or not qcloud_secret.get("SecretId") or not qcloud_secret.get("SecretKey"):
            return {"success": False, "message": "未配置腾讯云密钥"}
        # 创建客户端并调用
        client = QcloudClient(qcloud_secret)

        # 转换origin_type参数
        origin_type = "ORIGIN_GROUP" if origin_type_param == "group" else "IP_DOMAIN"

        # 调用客户端方法
        error_msg, error_code = client.create_acceleration_domain(
            zone_id=zone_id,
            domain_name=domain_name,
            origin_type=origin_type,
            origin_group_id=origin_group_id,
            origin_address=origin_address,
            ipv6_status=data.get("ipv6Status", "follow"),
            origin_protocol=data.get("originProtocol", "FOLLOW"),
            http_origin_port=data.get("httpOriginPort", 80),
            https_origin_port=data.get("httpsOriginPort", 443)
        )
        if error_msg:
            return {"success": False, "message": f"创建加速域名失败: {error_msg}"}

        # 保存到配置文件中
        _save_accel_domain_to_config(zone_id, domain_name, data)

        return {"success": True, "message": "创建加速域名成功"}

    except ValueError as e:
        return {"success": False, "message": str(e)}
    except Exception as e:
        logger.error(f"创建加速域名失败: {str(e)}")
        return {"success": False, "message": "创建加速域名失败，请检查配置信息"}


@app.post("/api/delete-accel-domain")
async def delete_accel_domain(request: Request):
    """删除加速域名。原前端已调用此接口但后端从未实现。"""
    try:
        data = await request.json()
        zone_id = (data.get("zoneId") or "").strip()
        domain_name = (data.get("domainName") or "").strip()
        if not zone_id or not domain_name:
            return {"success": False, "message": "站点ZoneID和加速域名不能为空"}

        config = read_config()
        qcloud_secret = config.get('TencentCloud')

        # 先从本地配置移除，避免密钥缺失时记录无法清理
        domains = config.get("AccelDomains", [])
        if not isinstance(domains, list):
            domains = []
        remaining = [d for d in domains
                     if not (isinstance(d, dict)
                             and d.get("domainName") == domain_name
                             and d.get("zoneId") == zone_id)]
        removed_local = len(remaining) != len(domains)
        config["AccelDomains"] = remaining

        remote_msg = ""
        if qcloud_secret and qcloud_secret.get("SecretId") and qcloud_secret.get("SecretKey"):
            client = QcloudClient(qcloud_secret)
            error_msg, error_code = client.delete_acceleration_domain(zone_id, domain_name)
            if error_code:
                # 远端删除失败时不写本地，保持两边一致
                logger.error(f"删除加速域名失败: {error_msg} {error_code}")
                return {"success": False, "message": f"删除加速域名失败: {error_msg}"}
        else:
            remote_msg = "（未配置密钥，仅从本地列表移除）"

        write_config(config)
        if not removed_local:
            return {"success": True, "message": f"本地无该记录{remote_msg}"}
        return {"success": True, "message": f"已删除加速域名 {domain_name}{remote_msg}"}
    except Exception as e:
        logger.error(f"删除加速域名失败: {str(e)}")
        return {"success": False, "message": "删除加速域名失败"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, default=54321, help='Web UI 端口')
    parser.add_argument('--host', type=str, default=os.environ.get("EODO_HOST", "127.0.0.1"),
                        help='监听地址。默认仅本机回环；容器内用 EODO_HOST=0.0.0.0 配合 '
                             'docker -p 127.0.0.1:54321:54321 暴露。')
    args = parser.parse_args()

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        logger.warning(f"监听地址为 {args.host}，管理面板将暴露给可访问该地址的所有客户端，"
                       f"请确保已设置登录密码且网络可达范围可控。")

    if not auth_is_configured():
        logger.warning("尚未设置管理密码，请访问 Web 界面完成初始化。")

    global scheduler
    scheduler = TaskScheduler(interval_min=load_interval())
    scheduler.start_scheduler()
    uvicorn.run(app, host=args.host, port=args.port)


# 在模块加载时初始化scheduler，避免uvicorn重载时丢失
if __name__ == "__main__":
    main()
else:
    # 当作为模块导入时也初始化scheduler
    scheduler = TaskScheduler(interval_min=load_interval())
    scheduler.start_scheduler()
