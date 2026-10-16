#!/usr/bin/env bash
# ============================================================
# 药商帮平台服务端启动脚本（Linux / Render 等托管平台通用）
# 纯 Python 标准库实现，无需安装任何第三方依赖
# 用法：
#   bash start.sh                        # 默认 8000 端口
#   PORT=8080 bash start.sh              # 指定端口（Render 等平台会传入 $PORT）
#   ALLOW_ORIGIN=https://你的前端域名 bash start.sh
# ============================================================
set -e
cd "$(dirname "$0")"

# 端口：优先取平台注入的 PORT 环境变量，默认 8000
PORT=${PORT:-8000}
# 监听地址：容器内默认 0.0.0.0，本地调试可改 127.0.0.1
HOST=${HOST:-0.0.0.0}
# CORS 白名单：药商帮线上前端域名（可逗号分隔追加多个）
ALLOW_ORIGIN=${ALLOW_ORIGIN:-"https://4kr6wnmg5r83z.doubaoapps.com"}

echo "[start] 药商帮平台服务启动中... port=$PORT host=$HOST allow_origin=$ALLOW_ORIGIN"
exec python3 server.py --port "$PORT" --host "$HOST" --allow-origin "$ALLOW_ORIGIN"
