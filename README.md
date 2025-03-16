# 作业管理系统

这是一个基于python Flask框架的作业管理系统，支持教师发布作业和学生提交作业的功能。

## 功能特点

- 用户认证（教师/学生）
- 作业发布和管理
- 作业提交和文件上传
- 作业查看和评分
- 个人中心

## 技术栈

- Python 3.x
- Flask
- SQLAlchemy
- Bootstrap 5
- SQLite

## 安装说明

1. 克隆仓库：
```bash
git clone https://github.com/YY127914/my_base.git
cd 作业管理系统
```

2. 创建虚拟环境：
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# 或
.venv\Scripts\activate  # Windows
```

3. 安装依赖：
```bash
pip install -r requirements.txt
```

4. 初始化数据库：
```bash
python app.py
```

5. 运行应用：
```bash
python app.py
```

访问 http://localhost:3000 即可使用系统。

## 使用说明

1. 注册账号（选择教师或学生身份）
2. 登录系统
3. 教师可以：
   - 发布新作业
   - 查看学生提交
4. 学生可以：
   - 查看作业列表
   - 提交作业
   - 查看提交历史

## 注意事项

- 请确保上传文件大小不超过5MB
- 支持的文件类型：txt, pdf, png, jpg, jpeg, gif, doc, docx, py, zip, rar
- 建议使用现代浏览器访问系统

