# 导入所需的库
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
from werkzeug.exceptions import HTTPException
import traceback
from sqlalchemy.sql import text
import time
import re
import uuid
import hashlib
from flask_wtf.csrf import CSRFProtect
import logging
from logging.handlers import RotatingFileHandler
import bleach  # 用于HTML净化，防止XSS攻击

# 创建Flask应用
app = Flask(__name__)
# 配置应用的密钥和数据库
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'dev'  # 优先使用环境变量中的密钥
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///homework.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB 最大文件大小

# 优化数据库连接池配置
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'pool_recycle': 60,  # 每60秒回收连接
    'pool_pre_ping': True,
    'pool_timeout': 30
}

# 添加稳定性配置
app.config['PRESERVE_CONTEXT_ON_EXCEPTION'] = False  # 提高错误处理稳定性
app.config['TESTING'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True  # 便于调试

# 添加缓存配置
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 300  # 静态文件缓存5分钟
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # 会话最长持续2小时

# 安全配置
app.config['SESSION_COOKIE_SECURE'] = False  # 开发环境中关闭此项，生产环境设为True
app.config['SESSION_COOKIE_HTTPONLY'] = True  # 防止JavaScript访问cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # 防止CSRF攻击
app.config['REMEMBER_COOKIE_SECURE'] = False  # 开发环境中关闭此项，生产环境设为True
app.config['REMEMBER_COOKIE_HTTPONLY'] = True
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)

# CSRF保护
csrf = CSRFProtect(app)

# 配置日志系统
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=5)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('应用启动')

# 导入安全增强模块
from security_enhancements import (
    setup_security_for_app, 
    sanitize_html, 
    validate_input, 
    record_login_attempt,
    rate_limited,
    audit_trail,
    require_role
)

# 初始化安全增强功能
setup_security_for_app(app)

# 允许的文件扩展名
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'py', 'zip', 'rar'}

# 创建上传文件夹
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
    app.logger.info(f"创建上传目录: {app.config['UPLOAD_FOLDER']}")

# 初始化数据库和登录管理
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# 全局错误处理，避免应用崩溃
@app.errorhandler(Exception)
def handle_exception(e):
    db.session.rollback()  # 回滚未完成的事务
    if isinstance(e, HTTPException):
        return render_template('error.html', error=str(e)), e.code
    else:
        app.logger.error(f"未处理的异常: {str(e)}")
        app.logger.error(traceback.format_exc())
        return render_template('error.html', error="服务器内部错误"), 500


# 添加安全相关的HTTP头
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'public, max-age=300'
    return response


# 请求前钩子，用于数据库连接检查
@app.before_request
def check_db_connection():
    try:
        # 检查数据库连接是否有效
        db.session.execute(text('SELECT 1'))
        
        # 防止会话固定攻击 - 修复regenerate方法
        if '_fresh' in session and session.get('_fresh'):
            # Flask的session没有regenerate方法，我们使用替代方式
            session_data = dict(session)
            session.clear()
            for key, value in session_data.items():
                session[key] = value
            
    except Exception as e:
        app.logger.error(f"数据库连接错误: {str(e)}")
        # 尝试重新连接
        db.session.remove()


# 请求限速功能（防止暴力破解）
request_history = {}

@app.before_request
def limit_request_rate():
    if request.endpoint in ['login', 'register']:
        ip = request.remote_addr
        now = time.time()
        
        # 清理旧记录
        for old_ip in list(request_history.keys()):
            if now - request_history[old_ip]['timestamp'] > 3600:  # 1小时
                del request_history[old_ip]
        
        # 检查请求频率 - 提高阈值，从10次改为20次
        if ip in request_history:
            if request_history[ip]['count'] > 20 and now - request_history[ip]['timestamp'] < 300:  # 5分钟内超过20次
                app.logger.warning(f"检测到可能的暴力破解尝试，IP: {ip}")
                return render_template('error.html', error="请求过于频繁，请稍后再试"), 429
            
            request_history[ip]['count'] += 1
            request_history[ip]['timestamp'] = now
        else:
            request_history[ip] = {'count': 1, 'timestamp': now}


# 请求后钩子，确保释放资源
@app.teardown_request
def teardown_request(exception=None):
    if exception:
        db.session.rollback()
    db.session.remove()  # 确保释放数据库连接


# 定时任务：自动清理过期会话和连接
def cleanup_task():
    with app.app_context():
        try:
            # 清理过期会话
            if db.session.execute(text('SELECT 1')).scalar():
                app.logger.info("定时清理任务执行中...")
                # 实际生产环境可添加更多清理代码
                db.session.commit()
        except Exception as e:
            app.logger.error(f"清理任务错误: {str(e)}")
            db.session.rollback()


# 检查文件扩展名是否被允许
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# 文件自动重命名函数
def rename_file(file, user_id):
    # 获取文件扩展名
    if '.' in file.filename:
        ext = file.filename.rsplit('.', 1)[1].lower()
    else:
        ext = ""
    
    # 获取用户信息
    user = User.query.get(user_id)
    if not user:
        app.logger.warning(f"重命名文件失败：找不到用户ID {user_id}")
        return secure_filename(file.filename)  # 如果找不到用户，使用原始文件名
    
    # 从用户名中提取姓名和学号
    # 支持两种格式："姓名_学号" 和 "学号+姓名"
    name = ""
    student_id = ""
    
    app.logger.info(f"开始从用户名提取信息: {user.username}")
    
    # 先尝试匹配"姓名_学号"格式
    name_id_match = re.match(r'^([\u4e00-\u9fa5a-zA-Z]+)_(\d+)$', user.username)
    if name_id_match:
        name = name_id_match.group(1)
        student_id = name_id_match.group(2)
        app.logger.info(f"匹配到姓名_学号格式")
    else:
        # 尝试匹配"学号+姓名"格式
        id_name_match = re.match(r'^(\d+)([\u4e00-\u9fa5a-zA-Z]+)$', user.username)
        if id_name_match:
            student_id = id_name_match.group(1)
            name = id_name_match.group(2)
            app.logger.info(f"匹配到学号+姓名格式")
        else:
            # 如果不匹配，单独提取姓名和学号
            name_match = re.search(r'([\u4e00-\u9fa5a-zA-Z]+)', user.username)
            id_match = re.search(r'(\d+)', user.username)
            
            name = name_match.group(1) if name_match else "用户"
            student_id = id_match.group(1) if id_match else str(user_id)
            app.logger.info(f"使用通用正则提取")
    
    app.logger.info(f"文件重命名：从用户名 '{user.username}' 提取姓名='{name}'，学号='{student_id}'")
    
    # 生成新文件名：姓名_学号.扩展名
    base_filename = f"{name}_{student_id}"
    
    # 添加随机字符串确保唯一性
    random_suffix = uuid.uuid4().hex[:8]
    # 注意：不在这里添加扩展名，将在下一步组装完整文件名
    new_filename = f"{base_filename}_{random_suffix}"
    
    # 记录生成的基础文件名
    app.logger.info(f"生成的基础文件名: {new_filename}")
    
    # 返回带扩展名的完整文件名
    final_filename = f"{new_filename}.{ext}" if ext else new_filename
    app.logger.info(f"最终生成的文件名: {final_filename}")
    return secure_filename(final_filename)


# 数据模型定义
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # 用户ID
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)  # 用户名
    password_hash = db.Column(db.String(120), nullable=False)  # 密码哈希
    is_teacher = db.Column(db.Boolean, default=False)  # 是否为教师
    last_login = db.Column(db.DateTime)  # 上次登录时间
    login_ip = db.Column(db.String(45))  # 登录IP
    submissions = db.relationship('Submission', backref='user', lazy=True)  # 用户的提交记录
    
    # 用于密码重置
    reset_token = db.Column(db.String(100))
    reset_token_expiry = db.Column(db.DateTime)


class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # 作业ID
    title = db.Column(db.String(100), nullable=False, index=True)  # 作业标题
    description = db.Column(db.Text, nullable=False)  # 作业描述
    deadline = db.Column(db.DateTime, nullable=False, index=True)  # 截止日期
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)  # 创建时间
    submissions = db.relationship('Submission', backref='assignment', lazy=True)  # 作业的提交记录


class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # 提交ID
    content = db.Column(db.Text, nullable=True)  # 提交内容
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)  # 提交时间
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)  # 用户ID
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignment.id'), nullable=False, index=True)  # 作业ID
    files = db.relationship('SubmissionFile', backref='submission', lazy=True)  # 提交的文件


class SubmissionFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # 文件ID
    filename = db.Column(db.String(255), nullable=False, index=True)  # 文件名
    original_filename = db.Column(db.String(255), nullable=False)  # 原始文件名
    file_type = db.Column(db.String(50), nullable=False)  # 文件类型
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)  # 上传时间
    file_size = db.Column(db.Integer)  # 文件大小（字节）
    file_hash = db.Column(db.String(64))  # 文件哈希值，用于校验
    submission_id = db.Column(db.Integer, db.ForeignKey('submission.id'), nullable=False, index=True)  # 提交ID


# 用户加载函数
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# 优化主页路由
@app.route('/')
def index():
    try:
        if current_user.is_authenticated:
            # 使用延迟加载和分页
            assignments = Assignment.query.order_by(Assignment.deadline.desc()).limit(10).all()
        else:
            assignments = []
        return render_template('index.html', assignments=assignments)
    except Exception as e:
        app.logger.error(f"主页加载错误: {str(e)}")
        return render_template('error.html', error=str(e)), 500


# 登录路由
@app.route('/login', methods=['GET', 'POST'])
@rate_limited(limit=10, period=300)  # 5分钟内最多10次登录尝试
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # 验证输入
        if not validate_input(username, max_length=80, required=True) or \
           not validate_input(password, required=True):
            flash('无效的用户名或密码格式', 'danger')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        # 记录登录尝试
        ip = request.remote_addr
        success = user and check_password_hash(user.password_hash, password)
        if not record_login_attempt(ip, success):
            # 如果登录失败次数过多，返回特殊错误
            app.logger.warning(f"IP {ip} 登录尝试次数过多")
            return render_template('error.html', error="登录尝试次数过多，请稍后再试"), 429

        if success:
            # 记录登录信息
            user.last_login = datetime.utcnow()
            user.login_ip = request.remote_addr
            db.session.commit()
            
            login_user(user)
            app.logger.info(f"用户 {user.username} 登录成功")
            
            # 防止会话固定攻击 - 替代 session.regenerate()
            session_data = dict(session)
            session.clear()
            for key, value in session_data.items():
                session[key] = value
            
            return redirect(url_for('index'))
        
        app.logger.warning(f"登录失败: 用户名={username}, IP={request.remote_addr}")
        flash('用户名或密码错误', 'danger')
    return render_template('login.html')


# 注册路由
@app.route('/register', methods=['GET', 'POST'])
@rate_limited(limit=10, period=300)  # 5分钟内最多10次注册尝试，从5次改为10次
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_teacher = request.form.get('is_teacher') == 'on'

        # 添加用户名格式验证
        if not validate_input(username, pattern=r'^[\u4e00-\u9fa5a-zA-Z0-9_]+$', max_length=80, required=True):
            flash('用户名只能包含中文、英文字母、数字和下划线', 'danger')
            return redirect(url_for('register'))
            
        # 添加密码强度验证 - 修复min_length参数
        if len(password) < 8 or not validate_input(password, required=True) or \
           not re.search(r'[A-Z]', password) or \
           not re.search(r'[a-z]', password) or \
           not re.search(r'[0-9]', password):
            flash('密码必须至少8个字符，并包含大小写字母和数字', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('用户名已存在', 'warning')
            return redirect(url_for('register'))

        # 安全地创建用户
        try:
            user = User(
                username=username,
                password_hash=generate_password_hash(password),
                is_teacher=is_teacher,
                last_login=datetime.utcnow(),
                login_ip=request.remote_addr
            )
            db.session.add(user)
            db.session.commit()
            
            app.logger.info(f"新用户注册: {username}, IP={request.remote_addr}")
            flash('注册成功，请登录', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"注册错误: {str(e)}")
            flash('注册过程中发生错误，请重试', 'danger')
            return redirect(url_for('register'))
            
    return render_template('register.html')


# 登出路由
@app.route('/logout')
@login_required
def logout():
    app.logger.info(f"用户 {current_user.username} 退出")
    # 清除用户会话
    logout_user()
    # 完全清除会话数据
    session.clear()
    # 显示登出成功消息
    flash('您已成功退出登录', 'success')
    return redirect(url_for('index'))


# 创建新作业路由
@app.route('/assignment/new', methods=['GET', 'POST'])
@login_required
def new_assignment():
    if not current_user.is_teacher:
        flash('只有教师可以创建作业')
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        deadline_str = request.form.get('deadline')
        
        # 输入验证
        if not title or not description or not deadline_str:
            flash('请填写所有必填字段', 'danger')
            return redirect(url_for('new_assignment'))
            
        try:
            deadline = datetime.strptime(deadline_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash('日期格式无效', 'danger')
            return redirect(url_for('new_assignment'))
            
        assignment = Assignment(
            title=title,
            description=description,
            deadline=deadline
        )
        db.session.add(assignment)
        db.session.commit()
        
        app.logger.info(f"教师 {current_user.username} 创建了新作业: {title}")
        flash('作业创建成功', 'success')
        return redirect(url_for('index'))
    return render_template('new_assignment.html')


# 提交作业路由
@app.route('/assignment/<int:id>/submit', methods=['GET', 'POST'])
@login_required
@audit_trail('submit_assignment')
def submit_assignment(id):
    assignment = Assignment.query.get_or_404(id)
    if request.method == 'POST':
        content = request.form.get('content')
        files = request.files.getlist('files')  # 获取多个文件
        
        # XSS防护：清理内容
        if content:
            content = sanitize_html(content)
        
        # 验证所有文件大小总和
        total_size = 0
        for file in files:
            if file and file.filename:
                file.seek(0, os.SEEK_END)
                size = file.tell()
                file.seek(0)
                total_size += size
                
        if total_size > app.config['MAX_CONTENT_LENGTH']:
            flash(f'文件总大小不能超过{app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)}MB', 'danger')
            return redirect(url_for('submit_assignment', id=id))

        # 文件类型验证
        for file in files:
            if file and file.filename:
                if not allowed_file(file.filename):
                    flash(f'不支持的文件类型: {file.filename}', 'danger')
                    return redirect(url_for('submit_assignment', id=id))
                    
                # 检查文件名安全性
                if not validate_input(file.filename, max_length=255):
                    flash('文件名无效或过长', 'danger')
                    return redirect(url_for('submit_assignment', id=id))

        # 创建提交记录
        try:
            submission = Submission(
                content=content,
                user_id=current_user.id,
                assignment_id=id
            )
            db.session.add(submission)
            db.session.commit()
            
            app.logger.info(f"用户 {current_user.username} 创建了新提交: 作业ID={id}")

            # 处理文件上传
            uploaded_files = 0
            for file in files:
                if file and file.filename and allowed_file(file.filename):
                    try:
                        # 保存原始文件名
                        original_filename = secure_filename(file.filename)
                        app.logger.info(f"开始处理文件: {original_filename}")
                        
                        # 使用自动重命名函数
                        new_filename = rename_file(file, current_user.id)
                        app.logger.info(f"生成重命名后文件名: {new_filename}")
                        
                        # 添加提交ID确保唯一性
                        unique_filename = f"{submission.id}_{new_filename}"
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                        
                        # 保存文件
                        file.seek(0, os.SEEK_END)
                        file_size = file.tell()
                        file.seek(0)
                        
                        # 计算文件哈希
                        file_hash = hashlib.sha256(file.read()).hexdigest()
                        file.seek(0)
                        
                        # 检查病毒特征（仅简单检测，实际项目应使用专业工具）
                        if file_size < 10 * 1024 * 1024 and is_text_file(file):
                            file_content = file.read().decode('utf-8', errors='ignore')
                            file.seek(0)
                            
                            # 简单的恶意代码标记检测（实际应用中应使用更完善的方法）
                            malicious_patterns = [
                                r'eval\((.*?)\)', r'system\((.*?)\)', r'exec\((.*?)\)', 
                                r'os\.system', r'subprocess\.',  r'__import__\('
                            ]
                            for pattern in malicious_patterns:
                                if re.search(pattern, file_content):
                                    app.logger.warning(f"潜在恶意代码检测到于文件: {original_filename}")
                                    flash(f'文件 {original_filename} 包含潜在的不安全代码', 'danger')
                                    return redirect(url_for('submit_assignment', id=id))
                        
                        # 保存文件到磁盘
                        file.save(file_path)
                        app.logger.info(f"文件已保存: {file_path}")
                        uploaded_files += 1
                        
                        # 提取名称和学号显示在提交记录中
                        # 不使用自动生成的文件名，而是明确使用姓名_学号格式
                        # 获取用户信息，确保能显示正确的姓名和学号
                        user = User.query.get(current_user.id)
                        name = ""
                        student_id = ""
                        
                        # 从用户名提取姓名和学号，与rename_file函数类似的逻辑
                        name_id_match = re.match(r'^([\u4e00-\u9fa5a-zA-Z]+)_(\d+)$', user.username)
                        if name_id_match:
                            name = name_id_match.group(1)
                            student_id = name_id_match.group(2)
                        else:
                            id_name_match = re.match(r'^(\d+)([\u4e00-\u9fa5a-zA-Z]+)$', user.username)
                            if id_name_match:
                                student_id = id_name_match.group(1)
                                name = id_name_match.group(2)
                            else:
                                name_match = re.search(r'([\u4e00-\u9fa5a-zA-Z]+)', user.username)
                                id_match = re.search(r'(\d+)', user.username)
                                name = name_match.group(1) if name_match else "用户"
                                student_id = id_match.group(1) if id_match else str(user.id)
                        
                        # 生成显示用的文件名，采用"姓名_学号.扩展名"格式
                        if '.' in new_filename:
                            file_ext = new_filename.rsplit('.', 1)[1]
                            display_name = f"{name}_{student_id}.{file_ext}"
                        else:
                            display_name = f"{name}_{student_id}"
                            
                        app.logger.info(f"提交记录中显示名称: {display_name}")
                        
                        # 创建提交文件记录
                        submission_file = SubmissionFile(
                            filename=unique_filename,  # 实际保存的文件名（用于存储）
                            original_filename=display_name,  # 显示的文件名（修改为重命名格式）
                            file_type=new_filename.rsplit('.', 1)[1].lower() if '.' in new_filename else "",
                            file_size=file_size,
                            file_hash=file_hash,
                            submission_id=submission.id
                        )
                        db.session.add(submission_file)
                    except Exception as e:
                        app.logger.error(f"文件上传错误: {str(e)}")
                        app.logger.error(traceback.format_exc())
                        flash(f'文件 {file.filename} 上传失败，请重试', 'danger')
                        continue

            db.session.commit()
            
            # 提供更具体的成功消息
            if uploaded_files > 0:
                flash(f'作业提交成功，已上传 {uploaded_files} 个文件（自动重命名为姓名_学号格式）', 'success')
            else:
                flash('作业提交成功', 'success')
                
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"提交作业错误: {str(e)}")
            app.logger.error(traceback.format_exc())
            flash('提交过程中发生错误，请重试', 'danger')
            return redirect(url_for('submit_assignment', id=id))
            
    return render_template('submit_assignment.html', assignment=assignment, now=datetime.utcnow())


# 检查文件是否为文本文件
def is_text_file(file):
    """检查文件是否为文本文件"""
    try:
        # 保存当前文件指针位置
        pos = file.tell()
        
        # 读取开头的1024字节来判断
        header = file.read(1024)
        
        # 尝试解码为utf-8，如果失败则可能不是文本文件
        header.decode('utf-8', errors='strict')
        
        # 恢复文件指针位置
        file.seek(pos)
        return True
    except:
        # 恢复文件指针位置
        file.seek(pos)
        return False


# 下载上传文件路由
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    try:
        # 安全检查：确保用户有权限访问此文件
        submission_file = SubmissionFile.query.filter_by(filename=filename).first_or_404()
        submission = Submission.query.get(submission_file.submission_id)
        
        if not current_user.is_teacher and submission.user_id != current_user.id:
            app.logger.warning(f"未授权的文件访问尝试: 用户={current_user.username}, 文件={filename}")
            flash('您没有权限访问此文件', 'danger')
            return redirect(url_for('index'))
            
        # 防止目录遍历攻击
        if '..' in filename or filename.startswith('/'):
            app.logger.warning(f"疑似目录遍历攻击尝试: 用户={current_user.username}, 文件路径={filename}")
            abort(404)
        
        # 验证文件存在
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.isfile(file_path) or not os.path.exists(file_path):
            app.logger.warning(f"请求不存在的文件: {filename}")
            abort(404)
            
        # 记录下载
        app.logger.info(f"用户 {current_user.username} 下载文件: {filename}")
        
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename,
            as_attachment=True,
            download_name=submission_file.original_filename
        )
    except Exception as e:
        app.logger.error(f"文件访问错误: {str(e)}")
        flash('文件访问失败，请稍后重试', 'danger')
        return redirect(url_for('index'))


# 查看提交记录路由
@app.route('/submissions/<int:assignment_id>')
@login_required
@require_role('is_teacher')  # 使用自定义装饰器验证用户角色
def view_submissions(assignment_id):
    # 使用延迟加载和分页
    assignment = Assignment.query.get_or_404(assignment_id)
    # 添加排序和限制，防止数据库过载
    submissions = Submission.query.filter_by(assignment_id=assignment_id)\
        .order_by(Submission.submitted_at.desc())\
        .limit(20)\
        .all()
    return render_template('view_submissions.html', assignment=assignment, submissions=submissions)


# 学生查看自己的提交记录详情
@app.route('/my-submissions')
@login_required
def my_submissions():
    # 获取学生所有的提交记录
    submissions = Submission.query.filter_by(user_id=current_user.id)\
        .order_by(Submission.submitted_at.desc())\
        .all()
    
    # 按作业分组组织提交记录
    assignments_dict = {}
    for submission in submissions:
        if submission.assignment_id not in assignments_dict:
            assignments_dict[submission.assignment_id] = {
                'assignment': submission.assignment,
                'submissions': []
            }
        assignments_dict[submission.assignment_id]['submissions'].append(submission)
    
    return render_template('my_submissions.html', assignments_dict=assignments_dict)


# 学生查看单个提交详情
@app.route('/my-submission/<int:submission_id>')
@login_required
def view_my_submission(submission_id):
    # 获取提交记录，确保只能查看自己的记录
    submission = Submission.query.get_or_404(submission_id)
    
    # 验证是否是当前用户的提交
    if submission.user_id != current_user.id:
        flash('您没有权限查看此提交记录', 'danger')
        return redirect(url_for('my_submissions'))
    
    return render_template('view_my_submission.html', submission=submission)


# 个人中心路由
@app.route('/profile')
@login_required
def profile():
    # 使用延迟加载和分页
    submissions = Submission.query.filter_by(user_id=current_user.id) \
        .order_by(Submission.submitted_at.desc()) \
        .limit(10) \
        .all()
    return render_template('profile.html', user=current_user, submissions=submissions)


# 404错误处理
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error="页面未找到"), 404


# 413错误处理(请求实体过大)
@app.errorhandler(413)
def request_entity_too_large(error):
    return render_template('error.html', error=f"上传文件过大，最大允许{app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)}MB"), 413


# 健康检查路由
@app.route('/health')
def health_check():
    return {'status': 'healthy'}, 200


# 会话监控钩子
@app.before_request
def session_management():
    # 检查会话是否已过期
    if 'user_id' in session and 'last_active' in session:
        last_active = datetime.fromisoformat(session['last_active'])
        now = datetime.utcnow()
        # 如果超过30分钟不活动，则自动登出
        if (now - last_active).total_seconds() > 1800:  # 30分钟
            app.logger.info(f"用户会话超时自动登出: {session.get('user_id')}")
            logout_user()
            session.clear()
            flash('您的会话已过期，请重新登录', 'warning')
            return redirect(url_for('login'))
        
        # 更新最后活动时间
        session['last_active'] = datetime.utcnow().isoformat()

    # 为登录用户设置初始会话数据
    if current_user.is_authenticated and 'last_active' not in session:
        session['last_active'] = datetime.utcnow().isoformat()
        session.permanent = True  # 使会话持久化


# 主程序入口
if __name__ == '__main__':
    print("正在初始化数据库...")
    with app.app_context():
        db.create_all()
        # 创建数据库索引
        db.session.execute(text('CREATE INDEX IF NOT EXISTS idx_user_username ON user(username)'))
        db.session.execute(text('CREATE INDEX IF NOT EXISTS idx_assignment_deadline ON assignment(deadline)'))
        db.session.execute(text('CREATE INDEX IF NOT EXISTS idx_submission_user ON submission(user_id)'))
        db.session.execute(text('CREATE INDEX IF NOT EXISTS idx_submission_assignment ON submission(assignment_id)'))
        db.session.commit()
    print("数据库初始化完成")

    # 启动定时清理任务
    import threading

    cleanup_thread = threading.Thread(target=lambda: (time.sleep(300), cleanup_task()))
    cleanup_thread.daemon = True
    cleanup_thread.start()

    print("启动服务器...")
    print("请访问 http://127.0.0.1:3000")
    print("或访问 http://localhost:3000")
    print("请确保您的用户名符合'姓名_学号'格式以便系统正确识别")
    print("\n其他设备访问说明：")
    print("1. 确保设备和服务器在同一个局域网内")
    print("2. 使用服务器的IP地址访问")
    print("3. 如果无法访问，请检查防火墙设置")
    print("\n长时间运行提示：")
    print("1. 如果长时间无响应，请重启服务器")
    print("2. 保持终端窗口打开")
    app.run(
        host='0.0.0.0',  # 允许所有IP访问
        port=3000,
        debug=True,
        threaded=True,  # 启用多线程
        use_reloader=True  # 启用自动重载
    ) 