from flask import Flask
import socket

app = Flask(__name__)

@app.route('/')
def hello():
    return f'Hello, World! Server running on {socket.gethostname()}'

if __name__ == '__main__':
    print("正在启动服务器...")
    print(f"主机名: {socket.gethostname()}")
    print(f"IP 地址: {socket.gethostbyname(socket.gethostname())}")
    app.run(host='0.0.0.0', port=3000, debug=True) 