#!/usr/bin/env bash
# deepseek-harness 外部工具包装：pman_http <site> <method> <path> [json_body]
# 环境变量：PM_DAEMON=http://127.0.0.1:9777  PM_TOKEN=<pm token issue deepseek 的输出>
set -euo pipefail
site="$1"; method="$2"; path="$3"; body="${4:-}"
if [ -n "$body" ]; then
  pm call --daemon "${PM_DAEMON:-http://127.0.0.1:9777}" --token "${PM_TOKEN:?}" \
    --site "$site" --method "$method" --path "$path" --json "$body"
else
  pm call --daemon "${PM_DAEMON:-http://127.0.0.1:9777}" --token "${PM_TOKEN:?}" \
    --site "$site" --method "$method" --path "$path"
fi
