from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return 'Hello, World!'

if __name__ == '__main__':
    print("启动测试服务器...")
    app.run(host='127.0.0.1', port=8080, debug=True) 