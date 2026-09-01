# DDNS-EdgeOne 安全审计

审计对象：`eodo` v0.1.14（`src/eodo/app.py` + `src/eodo/static/index.html` + `Dockerfile`）
审计范围：认证授权、密钥管理、供应链、信息泄露、部署配置
结论：**不建议在公网可达的机器上按当前 README 的方式部署。**

---

## P0 · 致命（可直接导致云账号失陷）

### 1. 管理面板零认证 + 监听 0.0.0.0

`app.py:1005`

```python
uvicorn.run(app, host="0.0.0.0", port=args.port)
```

全站无任何登录、token、Basic Auth、IP 白名单。而 README:32 推荐：

```bash
docker run -d --network=host ... 2799214854/edgeone-dynamic-origin
```

`--network=host` 让 54321 端口直接监听宿主机全部网卡。**这个项目的目标部署场景恰恰是"拥有公网 IPv6 的机器"**，于是控制台直接暴露在公网 IPv6 上。

后果（一条命令即可完成）：

```bash
curl http://[目标公网IPv6]:54321/api/config
# 直接返回 SecretId + SecretKey 明文
```

`app.py:803-809` 的 `GET /api/config` 把整个 YAML 原样吐出，包含密钥、ZoneId、钉钉 Webhook。
拿到的是**腾讯云永久密钥**，通常具备 EdgeOne、DNSPod、COS、CVM 等全量资源操作权限。

**修复**：默认绑定 `127.0.0.1`；必须远程访问时加 Basic Auth / 单密码登录，并配合防火墙或 SSH 隧道。

---

### 2. CSRF —— 即使只绑 127.0.0.1 也能从外网打进来

`app.py:811-825` 的 `POST /api/config` 使用 `await request.json()`，FastAPI 不校验 Content-Type，
因此浏览器可用 `text/plain` 的简单请求跨站 POST，**不触发 CORS 预检**。无 CSRF token、无 Origin/Referer 校验。

受害者只要在用浏览器时访问了任意恶意页面，该页面即可静默改写本机配置：

| 注入字段 | 后果 |
|---|---|
| `CustomIPList` | 把源站 IP 改到攻击者服务器 → 回源流量被劫持、内容被中间人 |
| `EdgeOneZoneId` | 更新指向攻击者的站点 |
| `DingTalkWebhook` | 通知改投攻击者，掩盖痕迹 |
| `TencentCloud` | 覆写密钥，导致服务中断或持久化后门 |
| `IntervalMin: 1` | 每分钟高频调用腾讯云 API，触发限流 / 产生费用 |

**修复**：校验 `Origin` / `Sec-Fetch-Site` 头；POST/PUT/DELETE 强制 `Content-Type: application/json`；加 CSRF token。

---

## P1 · 高危

### 3. 密钥明文落盘，无权限保护

`app.py:110` 配置文件路径：`~/.eodo.config.yaml`（Docker 下为 `/app/config` 挂载卷）。
`app.py:817-818` 用 `yaml.dump(data, f)` 明文写入，无加密、无 `chmod 600`。

同机任何其他用户、容器、备份脚本、日志采集 agent 均可读取。该文件又在 Docker 挂载卷中，
极易随目录整体备份/同步而外泄。

**修复**：写文件后 `os.chmod(path, 0o600)`；Linux 上优先放 `~/.config/eodo/`；
考虑改用环境变量注入密钥，不落盘。

### 4. 前端供应链：unpkg `@latest` 且无 SRI

`index.html:7` 和 `index.html:289`：

```html
<link href="https://unpkg.com/@tabler/core@latest/dist/css/tabler.min.css" rel="stylesheet"/>
<script src="https://unpkg.com/@tabler/core@latest/dist/js/tabler.min.js"></script>
```

未锁定版本、未加 `integrity` 属性。`@tabler/core` 一旦被投毒，或 unpkg 遭劫持 / DNS 污染，
注入的 JS 将在管理页面上下文中执行——而该页面能调用 `/api/config` 读到明文密钥。

同时每个页面加载都依赖外网 CDN，离线不可用。

**修复**：固定具体版本（如 `@tabler/core@1.0.0`），加 SRI `integrity` + `crossorigin`；
更稳妥的做法是把 CSS/JS 打包进镜像本地托管。

### 5. 主动把源站公网 IP 报给第三方

`app.py:456-494` 的 `public_ipv6_check()` 将本机公网 IPv6 明文拼进 URL，GET 给 `ipw.cn`、`ping6.network`：

```python
requests.get(f"https://ipw.cn/api/ping/ipv6/{ip}/1/all")
requests.get(f"https://ping6.network/index.php?host={ip.replace(':', '%3A')}")
```

本项目存在的意义就是让源站跟随动态 IP 隐藏在 EdgeOne 之后，却又把源站真实地址持续上报第三方，
等于给"绕过 CDN 直击源站"提供了一份现成的情报源。

**修复**：默认改为本地连通性检测（绑定源地址发起连接），把第三方探测设为可选且默认关闭。

---

## P2 · 中低危

### 6. 日志接口无鉴权泄露内网信息
`app.py:827-833` `GET /api/logs` 返回最近 100 行 `eodo.task.log.txt`，含完整 IPv6、ZoneId、源站组名（= 主机名）、更新结果。
日志文件写在 `/app/config` 或系统临时目录，无权限控制、无脱敏。

### 7. "清除日志"是假功能
`index.html:603-607` 只修改了前端 DOM 文本，后端根本没有清除接口。点击后日志仍在服务器上，属于误导。

### 8. 全站明文 HTTP
SecretKey 以明文 JSON 在网络上传输。localhost 尚可接受，公网 IPv6 暴露场景即为明文过公网。

### 9. 配置写入无任何校验
`POST /api/config` 直接 `yaml.dump(data)` 整个请求体，不过滤字段、不校验类型。
`POST /api/interval` 可设 `interval=1`，造成高频 API 调用。

### 10. SecretKey 被拉进浏览器 DOM
`index.html:429-430` 的 `fetchConfig()` 把 SecretKey 取回填进 `type=password` 输入框。
`password` 只遮蔽显示，值仍在 DOM 与内存中，页面脚本或浏览器扩展均可读取。
建议只回传掩码，保存时若为空则表示不修改。

### 11. 未授权的服务端 API 代理
`app.py:870-907` `GET /api/origin-groups/{zone_id}` 用存储的密钥代调腾讯云 API，无鉴权无频率限制，
可被用于枚举 ZoneId、刷 API 配额。

### 12. 模块级 hostname 校验会导致启动崩溃
`app.py:98-106` `get_hostname()` 在 import 时对含非 `[a-zA-Z0-9_-]` 字符的主机名直接 `raise`。
中文 Windows 主机名（如 `DESKTOP-张三`）会导致程序根本起不来。

### 13. Docker 镜像以 root 运行且残留编译工具链
Dockerfile 无 `USER` 指令，容器以 root 运行；
`apk add gcc python3-dev musl-dev linux-headers` 未做多阶段构建清理，生产镜像中留下完整编译器，
便于攻击者落地编译 exp。配合 `--network=host` + 挂载卷，一旦 RCE 即为宿主机 root。

### 14. 依赖未锁定
`requirements.txt` 为范围约束（`fastapi>=0.110,<1.0`），`pyproject.toml` 更是完全无版本约束，
无 hash 锁定。构建时拉取当时最新版，存在供应链投毒空间且不可复现。

### 15. Docker 部署建议不安全
README 推荐的 `--network=host` 应改为 bridge 网络 + 显式绑定回环：
`-p 127.0.0.1:54321:54321`。

### 16. GitHub Actions 泄露用户名
`.github/workflows/docker-publish.yml` 中
`echo "Docker Hub username: ${{ secrets.DOCKER_USERNAME }}"` 会把用户名打进公开日志。
该 "Verify Docker Hub credentials" 步骤本身多余，建议直接删除。
（密钥传递使用 `--password-stdin`，做法正确。）

---

## 修复优先级

| 顺序 | 动作 | 成本 |
|---|---|---|
| 1 | 默认监听 `127.0.0.1`，Docker 改 `-p 127.0.0.1:54321:54321` | 极低 |
| 2 | 加登录密码 / Basic Auth | 低 |
| 3 | 配置写入后 `chmod 600` | 极低 |
| 4 | 前端依赖固定版本 + SRI，或本地托管 | 低 |
| 5 | 关闭第三方 IP 探测（默认本地检测） | 中 |
| 6 | CSRF 防护（Origin 校验 + 强制 JSON Content-Type） | 低 |
| 7 | 日志脱敏、补真正的清除接口或移除按钮 | 低 |
| 8 | Dockerfile 加 `USER`、多阶段构建 | 中 |

---

## 已确认无问题的部分

- Git 历史中**未发现真实密钥泄露**（已检索全部提交中 `SecretKey` / `SecretId` / `AKID` / `access_token`，均为代码与占位值）。
- 配置读取使用 `yaml.safe_load()`，未使用 `yaml.load()`，无反序列化 RCE 风险。
- 腾讯云 TC3-HMAC-SHA256 签名实现正确，签名不落日志。
- 无命令注入、SQL 注入、路径穿越（无 `os.system` / `eval` / 用户可控文件路径拼接）。
