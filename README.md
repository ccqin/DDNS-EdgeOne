# EdgeOne Dynamic Origin

### 原版构建arm镜像时会报错，修改了docker基础镜像为python:alpine3.20，配置了安装必要的系统依赖和镜像加速，修改了时区，使两个架构构建正常。

EdgeOne 是腾讯云的边缘安全加速平台。该脚本为其提供动态更新源站组 IP 的功能。
此功能特别适用于那些 IP 地址可能会变化的源站，确保 CDN 始终能够正确地获取最新的内容。比如仅有动态 IPV6 地址的服务器，
也能够长期稳定部署WEB服务，而不必使用 frp / ngork 等内网端口转发工具。

注意，若要使用该脚本，在 EdgeOne 中的加速域名必须使用源站组配置源站。

### 使用方法

#### windows
1. 安装 `pip install eodo`
2. 运行 `eodo -p 54321`以启动。 -p 54321 表示 web 管理界面监听端口为 54321。
3. 在 `http://localhost:54321` 中配置必要的配置项。

#### ubuntu
1. 安装 `pip3 install eodo -U --break-system-packages`
2. 运行 `export PATH="$HOME/.local/bin:$PATH" && source ~/.bashrc` 将 ~/.local/bin 加入 PATH
3. 运行 `eodo -p 54321`以启动。  -p 54321 表示 web 管理界面监听端口为 54321。
4. 在 `http://localhost:54321` 中配置必要的配置项。

#### Docker
##### 有两种运行方式：
1. 可以直接拉取构建好的镜像运行
   ```bash
   docker pull 2799214854/edgeone-dynamic-origin
   ```
   运行容器（**推荐绑定回环 + 显式端口映射，不要使用 `--network=host`**）：
   ```bash
   docker run -d -p 127.0.0.1:54321:54321 -v eodo-config:/app/config --restart always --name edgeone-dynamic-origin 2799214854/edgeone-dynamic-origin
   ```
   浏览器访问 `http://localhost:54321` 进行配置。

2. 本地构建镜像运行：
   ```bash
   docker build -t eodo:latest .
   ```
   运行容器：
   ```bash
   docker run -d -p 127.0.0.1:54321:54321 -v eodo-config:/app/config --restart always --name eodo eodo:latest
   ```
   浏览器访问 `http://localhost:54321` 进行配置。

> 使用 bind mount 挂载配置目录（如 `-v /path/to/config:/app/config`）时，请确保宿主目录对 uid 1000 可写：
> `chown -R 1000:1000 /path/to/config`。配置文件（含腾讯云密钥，权限 0600）保存在挂载卷内，
> 容器重建后不丢失。

### 安全说明

- **首次启动请立即设置管理密码**：面板第一次可访问时任何人都可能抢先设置密码，
  部署后请尽快完成初始化。
- **默认仅监听本机回环地址**：需要远程访问时，推荐通过 SSH 隧道
  （`ssh -L 54321:127.0.0.1:54321 服务器`）或反向代理（Nginx/Caddy）加 TLS 后再暴露，
  避免管理密码与配置明文过公网。
- 登录连续失败 5 次将按来源 IP 锁定 15 分钟；修改密码会使所有已登录会话失效。
- 腾讯云 SecretKey 在管理页仅以掩码回显（`****` + 末 4 位），保存时留空或保持掩码即不修改。
- 日志中的公网 IP 默认脱敏，可在高级设置中关闭（不建议）。

### WEB 界面
![img.png](img.png)

#### 说明

持久化运行可用 nssm 或 systemd 配置服务。
