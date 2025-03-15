#!/bin/bash

# 确保脚本在正确的目录下执行
cd "$(dirname "$0")"

# 激活虚拟环境（如果存在）
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

echo "启动作业管理系统服务器..."

# 计数器
COUNT=0
MAX_RESTARTS=5

while [ $COUNT -lt $MAX_RESTARTS ]; do
    echo "$(date) - 启动服务器 (尝试 $((COUNT+1))/$MAX_RESTARTS)"
    
    # 运行Flask应用，获取退出状态
    python app.py
    EXIT_STATUS=$?
    
    # 如果是正常退出（CTRL+C），则不重启
    if [ $EXIT_STATUS -eq 130 ]; then
        echo "$(date) - 服务器被用户终止，不再重启"
        break
    fi
    
    # 记录崩溃信息
    echo "$(date) - 服务器异常退出，状态码: $EXIT_STATUS"
    
    # 重启前等待几秒
    sleep 5
    
    # 增加计数器
    COUNT=$((COUNT+1))
    
    if [ $COUNT -eq $MAX_RESTARTS ]; then
        echo "$(date) - 达到最大重启次数 ($MAX_RESTARTS)，不再重启"
    fi
done

echo "服务器已停止"

# 如果使用了虚拟环境，取消激活
if [ -n "$VIRTUAL_ENV" ]; then
    deactivate
fi 