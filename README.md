# 作业管理系统

这是一个基于Python Flask框架的作业管理系统，支持教师发布作业和学生提交作业的功能。系统具有完善的安全特性和用户友好的界面。

## 功能特点

- 用户认证（教师/学生）
- 作业发布和管理
- 作业提交和文件上传（自动重命名为姓名_学号格式）
- 作业查看和评分
- 个人中心
- 完善的安全防护机制

## 技术栈

- Python 3.8+
- Flask 3.0.2
- SQLAlchemy 2.0.28
- Bootstrap 5
- SQLite
- Bleach（XSS防护）
- Flask-Login（用户认证）
- Flask-WTF（表单处理和CSRF保护）

## 系统要求

- Python 3.8 或更高版本
- pip（Python包管理器）
- Git（版本控制）
- 现代浏览器（Chrome、Firefox、Safari等）

## 安装说明

1. 克隆仓库：
```bash
git clone https://github.com/YY127914/my_base.git
cd my_base
```

2. 创建虚拟环境：
```bash
# Linux/Mac
python3 -m venv .venv
source .venv/bin/activate

# Windows
python -m venv .venv
.venv\Scripts\activate
```

3. 安装依赖：
```bash
pip install -r requirements.txt
```

4. 创建必要的目录：
```bash
mkdir -p uploads logs instance
```

5. 初始化数据库：
```bash
python app.py
```

## 运行应用

1. 确保虚拟环境已激活
2. 运行应用：
```bash
python app.py
```
3. 访问 http://localhost:3000 使用系统

## 目录结构

```
my_base/
├── app.py                 # 主应用文件
├── security_enhancements.py   # 安全增强模块
├── requirements.txt       # 项目依赖
├── README.md             # 项目说明文档
├── .gitignore           # Git忽略文件配置
├── instance/            # 数据库目录
│   └── homework.db      # SQLite数据库文件
├── logs/                # 日志目录
├── static/              # 静态文件
│   ├── css/
│   ├── js/
│   └── img/
├── templates/           # HTML模板
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   └── ...
└── uploads/            # 文件上传目录
```

## 使用说明

1. 注册账号：
   - 学生注册：使用"学号+姓名"格式（如：23209140xxx+姓名）
   - 教师注册：选择"教师账号"选项

2. 登录系统：
   - 使用注册时的用户名和密码
   - 学生使用"学号+姓名"格式登录

3. 教师功能：
   - 发布新作业
   - 查看学生提交
   - 评分和反馈
   - 下载学生提交的文件

4. 学生功能：
   - 查看作业列表
   - 提交作业（文件会自动重命名为"姓名_学号"格式）
   - 查看提交历史
   - 查看个人成绩

## 注意事项

- 文件上传限制：
  - 单个文件大小不超过5MB
  - 支持的文件类型：txt, pdf, png, jpg, jpeg, gif, doc, docx, py, zip, rar
  
- 安全特性：
  - CSRF保护
  - XSS防护
  - SQL注入防护
  - 文件上传安全检查
  - 会话保护
  - 请求速率限制

- 建议使用现代浏览器访问系统
- 定期备份instance目录下的数据库文件

## 常见问题

1. 如果遇到数据库错误，请确保instance目录存在并有写入权限
2. 如果文件上传失败，请检查uploads目录权限
3. 如果遇到权限问题，请确保logs目录可写

## 许可证

MIT License

## 联系方式

如有问题，请提交Issue或发送邮件至：[您的邮箱]
