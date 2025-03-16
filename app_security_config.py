import re
import hashlib
import bleach
from datetime import datetime, timedelta
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, send_from_directory
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

# ========== 添加到app.py配置部分 ==========

# 安全配置
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'set-a-strong-secret-key-in-production'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # 会话有效期2小时
app.config['SESSION_COOKIE_SECURE'] = True  # 仅通过HTTPS发送cookie
app.config['SESSION_COOKIE_HTTPONLY'] = True  # 防止JavaScript访问cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # 防止CSRF攻击
app.config['WTF_CSRF_ENABLED'] = True  # 启用CSRF保护
app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # CSRF令牌有效期（秒）
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 最大上传文件大小5MB

# 文件上传配置
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 允许的文件类型
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar', 'py', 'java', 'c', 'cpp', 'js', 'html', 'css', 'md'}

# 日志配置
if not os.path.exists('logs'):
    os.makedirs('logs')
file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('应用启动')

# CSRF保护实例化
csrf = CSRFProtect(app)

# ========== 添加到app.py工具函数部分 ==========

def allowed_file(filename):
    """检查文件类型是否允许上传"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def rename_file(file, user_id):
    """重命名上传的文件为安全格式"""
    # 获取原始文件名和扩展名
    if file and file.filename:
        original_filename = secure_filename(file.filename)
        # 获取文件扩展名
        if '.' in original_filename:
            ext = original_filename.rsplit('.', 1)[1].lower()
        else:
            ext = ''
            
        # 获取用户信息
        user = User.query.get(user_id)
        if user:
            # 使用用户名和ID创建新文件名
            if hasattr(user, 'student_id') and user.student_id:
                new_filename = f"{user.username}_{user.student_id}"
            else:
                new_filename = f"{user.username}_{user_id}"
                
            # 添加时间戳确保唯一性
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            new_filename = f"{new_filename}_{timestamp}"
            
            # 添加原始扩展名
            if ext:
                new_filename = f"{new_filename}.{ext}"
                
            return new_filename
    
    # 如果有问题，返回安全的默认文件名
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    return f"file_{user_id}_{timestamp}" 