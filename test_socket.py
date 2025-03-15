import socket

def test_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('127.0.0.1', port))
        print(f"端口 {port} 可用")
        sock.close()
        return True
    except socket.error as e:
        print(f"端口 {port} 不可用: {e}")
        return False

# 测试几个不同的端口
ports = [3000, 8080, 5000]
for port in ports:
    test_port(port) 