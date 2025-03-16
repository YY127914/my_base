@echo off
echo 检查Python版本...
python --version 2>NUL
if errorlevel 1 (
    echo 错误: 未找到Python
    pause
    exit /b 1
)

echo 检查虚拟环境...
if not exist ".venv" (
    echo 创建虚拟环境...
    python -m venv .venv
)

echo 激活虚拟环境...
call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo 错误: 无法激活虚拟环境
    pause
    exit /b 1
)

echo 安装依赖...
pip install -r requirements.txt
if errorlevel 1 (
    echo 错误: 安装依赖失败
    pause
    exit /b 1
)

echo 创建必要的目录...
if not exist "uploads" mkdir uploads
if not exist "logs" mkdir logs
if not exist "instance" mkdir instance

echo 检查端口3000是否被占用...
netstat -ano | find "3000" | find "LISTENING"
if not errorlevel 1 (
    echo 警告: 端口3000已被占用
    echo 尝试关闭已有的Python进程...
    taskkill /F /IM python.exe /FI "WINDOWTITLE eq app.py"
    timeout /t 2
)

echo 启动应用...
echo 请访问 http://localhost:3000
python app.py

pause 