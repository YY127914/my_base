from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
from werkzeug.exceptions import HTTPException
import traceback
from sqlalchemy.sql import text
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///homework.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB 最大文件大小
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
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 会话有效期1小时
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'py', 'zip', 'rar'}

# 创建上传文件夹
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
    print(f"创建上传目录: {app.config['UPLOAD_FOLDER']}")

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

# 请求前钩子，用于数据库连接检查
@app.before_request
def check_db_connection():
    try:
        # 检查数据库连接是否有效
        db.session.execute(text('SELECT 1'))
    except Exception as e:
        app.logger.error(f"数据库连接错误: {str(e)}")
        # 尝试重新连接
        db.session.remove()

# 请求后钩子，确保释放资源
@app.teardown_request
def teardown_request(exception=None):
    if exception:
        db.session.rollback()
    db.session.remove()  # 确保释放数据库连接

# 优化响应头中间件
@app.after_request
def add_header(response):
    if 'Cache-Control' not in response.headers:
        response.headers['Cache-Control'] = 'public, max-age=300'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response

# 定时任务：自动清理过期会话和连接
def cleanup_task():
    with app.app_context():
        try:
            # 清理过期会话
            if db.session.execute(text('SELECT 1')).scalar():
                print("定时清理任务执行中...")
                # 实际生产环境可添加更多清理代码
                db.session.commit()
        except Exception as e:
            print(f"清理任务错误: {str(e)}")
            db.session.rollback()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 数据模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(120), nullable=False)
    is_teacher = db.Column(db.Boolean, default=False)
    submissions = db.relationship('Submission', backref='user', lazy=True)

class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    deadline = db.Column(db.DateTime, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    submissions = db.relationship('Submission', backref='assignment', lazy=True)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=True)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignment.id'), nullable=False, index=True)
    files = db.relationship('SubmissionFile', backref='submission', lazy=True)

class SubmissionFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False, index=True)
    original_filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    submission_id = db.Column(db.Integer, db.ForeignKey('submission.id'), nullable=False, index=True)

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
        print(f"主页加载错误: {str(e)}")
        return render_template('error.html', error=str(e)), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('用户名或密码错误')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_teacher = request.form.get('is_teacher') == 'on'
        
        if User.query.filter_by(username=username).first():
            flash('用户名已存在')
            return redirect(url_for('register'))
            
        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            is_teacher=is_teacher
        )
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/assignment/new', methods=['GET', 'POST'])
@login_required
def new_assignment():
    if not current_user.is_teacher:
        flash('只有教师可以创建作业')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        assignment = Assignment(
            title=request.form.get('title'),
            description=request.form.get('description'),
            deadline=datetime.strptime(request.form.get('deadline'), '%Y-%m-%dT%H:%M')
        )
        db.session.add(assignment)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('new_assignment.html')

@app.route('/assignment/<int:id>/submit', methods=['GET', 'POST'])
@login_required
def submit_assignment(id):
    assignment = Assignment.query.get_or_404(id)
    if request.method == 'POST':
        content = request.form.get('content')
        files = request.files.getlist('files')  # 获取多个文件
        
        submission = Submission(
            content=content,
            user_id=current_user.id,
            assignment_id=id
        )
        db.session.add(submission)
        db.session.commit()
        
        # 处理文件上传
        for file in files:
            if file and allowed_file(file.filename):
                try:
                    filename = secure_filename(file.filename)
                    # 使用提交ID和原始文件名创建唯一文件名
                    unique_filename = f"{submission.id}_{filename}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                    file.save(file_path)
                    print(f"文件已保存: {file_path}")
                    
                    submission_file = SubmissionFile(
                        filename=unique_filename,
                        original_filename=filename,
                        file_type=filename.rsplit('.', 1)[1].lower(),
                        submission_id=submission.id
                    )
                    db.session.add(submission_file)
                except Exception as e:
                    print(f"文件上传错误: {str(e)}")
                    flash(f'文件 {filename} 上传失败，请重试')
                    continue
        
        db.session.commit()
        flash('作业提交成功')
        return redirect(url_for('index'))
    return render_template('submit_assignment.html', assignment=assignment)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    try:
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            filename,
            as_attachment=True
        )
    except Exception as e:
        print(f"文件访问错误: {str(e)}")
        flash('文件访问失败，请稍后重试')
        return redirect(url_for('index'))

# 优化提交查看路由
@app.route('/submissions/<int:assignment_id>')
@login_required
def view_submissions(assignment_id):
    if not current_user.is_teacher:
        flash('只有教师可以查看所有提交')
        return redirect(url_for('index'))
    
    # 使用延迟加载和分页
    assignment = Assignment.query.get_or_404(assignment_id)
    submissions = Submission.query.filter_by(assignment_id=assignment_id).limit(20).all()
    return render_template('view_submissions.html', assignment=assignment, submissions=submissions)

# 优化个人中心路由
@app.route('/profile')
@login_required
def profile():
    # 使用延迟加载和分页
    submissions = Submission.query.filter_by(user_id=current_user.id)\
        .order_by(Submission.submitted_at.desc())\
        .limit(10)\
        .all()
    return render_template('profile.html', user=current_user, submissions=submissions)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error="页面未找到"), 404

@app.route('/health')
def health_check():
    return {'status': 'healthy'}, 200

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
    print("或访问 http://192.168.10.109:3000")
    print("\n其他设备访问说明：")
    print("1. 确保设备和服务器在同一个局域网内")
    print("2. 使用服务器的IP地址访问：http://192.168.10.109:3000")
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