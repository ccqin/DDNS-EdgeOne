# ---- 构建阶段：安装依赖（编译工具链不进入最终镜像） ----
FROM python:alpine3.20 AS builder

COPY requirements.txt ./

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories \
    && apk add --no-cache gcc python3-dev musl-dev linux-headers \
    && pip config set global.index-url https://mirrors.ustc.edu.cn/pypi/simple \
    && pip install --no-cache-dir --prefix=/install -r requirements.txt

# ---- 运行阶段：仅包含运行时依赖 ----
FROM python:alpine3.20

# 时区 Asia/Shanghai
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories \
    && apk add --no-cache tzdata \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone \
    && apk del tzdata

COPY --from=builder /install /usr/local

WORKDIR /app
COPY src ./src
COPY README.md img.png ./

# 非 root 运行；固定 uid 1000 便于宿主机对挂载目录授权（chown 1000 或 chmod）
RUN addgroup -S eodo && adduser -S -u 1000 -G eodo eodo \
    && mkdir -p /app/config \
    && chown -R eodo:eodo /app
USER eodo

VOLUME ["/app/config"]

ENV PYTHONUNBUFFERED=1
# 配置文件落在挂载卷内，容器重建后密钥与密码配置不丢失
ENV CONFIG_PATH="/app/config/eodo.config.yaml"
# 容器内绑定全部接口是标准做法，实际暴露面由 docker -p 端口映射控制
# （推荐 -p 127.0.0.1:54321:54321，远程访问走反向代理 + TLS）
ENV EODO_HOST="0.0.0.0"

EXPOSE 54321

CMD ["python", "src/eodo/app.py", "-p", "54321"]
