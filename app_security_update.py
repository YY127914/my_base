# 导入security_enhancements模块，使用我们刚刚创建的安全功能
from security_enhancements import (
    setup_security_for_app, 
    sanitize_html, 
    validate_input, 
    record_login_attempt,
    rate_limited,
    audit_trail,
    require_role
)

# ========== 在app.py主文件中添加以下代码 ==========

# 在初始化部分，添加安全模块设置

# 应用程序初始化后立即设置安全功能
setup_security_for_app(app)

# ========== 修改登录路由，增加安全功能 ==========

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
            
            # 防止会话固定攻击
            session.regenerate()
            return redirect(url_for('index'))
        
        app.logger.warning(f"登录失败: 用户名={username}, IP={request.remote_addr}")
        flash('用户名或密码错误', 'danger')
    return render_template('login.html')

# ========== 修改注册路由，增加安全功能 ==========

@app.route('/register', methods=['GET', 'POST'])
@rate_limited(limit=5, period=300)  # 5分钟内最多5次注册尝试
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
            
        # 添加密码强度验证
        if not validate_input(password, min_length=8, required=True) or \
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

# ========== 修改提交作业路由，增加安全功能 ==========

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
        
        # CSRF保护 - 由Flask-WTF的CSRF令牌提供
        
        # 验证所有文件大小总和
        total_size = 0
        for file in files:
            if file:
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
            for file in files:
                if file and file.filename and allowed_file(file.filename):
                    try:
                        # 保存原始文件名
                        original_filename = secure_filename(file.filename)
                        
                        # 使用自动重命名函数
                        new_filename = rename_file(file, current_user.id)
                        
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
                                'eval\(.*\)', 'system\(.*\)', 'exec\(.*\)', 
                                'os\.system', 'subprocess\.', '__import__\('
                            ]
                            for pattern in malicious_patterns:
                                if re.search(pattern, file_content):
                                    app.logger.warning(f"潜在恶意代码检测到于文件: {original_filename}")
                                    flash(f'文件 {original_filename} 包含潜在的不安全代码', 'danger')
                                    return redirect(url_for('submit_assignment', id=id))
                        
                        file.save(file_path)
                        app.logger.info(f"文件已保存: {file_path}")
                        
                        # 创建提交文件记录
                        submission_file = SubmissionFile(
                            filename=unique_filename,
                            original_filename=original_filename,
                            file_type=unique_filename.rsplit('.', 1)[1].lower() if '.' in unique_filename else "",
                            file_size=file_size,
                            file_hash=file_hash,
                            submission_id=submission.id
                        )
                        db.session.add(submission_file)
                    except Exception as e:
                        app.logger.error(f"文件上传错误: {str(e)}")
                        flash(f'文件 {file.filename} 上传失败，请重试', 'danger')
                        continue

            db.session.commit()
            flash('作业提交成功', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"提交作业错误: {str(e)}")
            flash('提交过程中发生错误，请重试', 'danger')
            return redirect(url_for('submit_assignment', id=id))
            
    return render_template('submit_assignment.html', assignment=assignment, now=datetime.utcnow())

# ========== 添加辅助函数 ==========

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

# ========== 修改查看文件路由，增加安全功能 ==========

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

# ========== 为教师视图添加安全功能 ==========

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