#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查Python版本
echo -e "${YELLOW}检查Python版本...${NC}"
if command -v python3 &>/dev/null; then
    python3 --version
else
    echo -e "${RED}错误: 未找到Python3${NC}"
    exit 1
fi

# 检查虚拟环境
echo -e "${YELLOW}检查虚拟环境...${NC}"
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}创建虚拟环境...${NC}"
    python3 -m venv .venv
fi

# 激活虚拟环境
echo -e "${YELLOW}激活虚拟环境...${NC}"
source .venv/bin/activate || {
    echo -e "${RED}错误: 无法激活虚拟环境${NC}"
    exit 1
}

# 安装依赖
echo -e "${YELLOW}安装依赖...${NC}"
pip install -r requirements.txt || {
    echo -e "${RED}错误: 安装依赖失败${NC}"
    exit 1
}

# 创建必要的目录
echo -e "${YELLOW}创建必要的目录...${NC}"
mkdir -p uploads logs instance

# 检查端口占用
echo -e "${YELLOW}检查端口3000是否被占用...${NC}"
if lsof -Pi :3000 -sTCP:LISTEN -t >/dev/null ; then
    echo -e "${RED}警告: 端口3000已被占用${NC}"
    echo -e "${YELLOW}尝试关闭已有的Python进程...${NC}"
    pkill -f "python app.py"
    sleep 2
fi

# 启动应用
echo -e "${GREEN}启动应用...${NC}"
echo -e "${GREEN}请访问 http://localhost:3000${NC}"
python app.py 