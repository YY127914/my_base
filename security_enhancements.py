'''
网站安全性增强模块
包含各种安全功能，如SQL注入防护、XSS防护、暴力破解防护等
'''

import re
import time
import ipaddress
from functools import wraps
from flask import request, abort, session, g
import html
import bleach
import datetime
import hashlib
import logging
from urllib.parse import urlparse

# 全局封禁IP列表
BANNED_IPS = set()
# IP失败尝试记录
LOGIN_ATTEMPTS = {}
# 操作频率限制
RATE_LIMITS = {}
# 敏感操作记录
SENSITIVE_OPS = {}

# 配置bleach允许的标签和属性（用于XSS防护）
ALLOWED_TAGS = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 'em', 
                'i', 'li', 'ol', 'pre', 'strong', 'ul', 'h1', 'h2', 'h3', 'p']
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title'],
    'abbr': ['title'],
    'acronym': ['title'],
}

class SecurityViolation(Exception):
    """安全违规异常"""
    pass

def setup_security_for_app(app):
    """设置应用的安全配置和中间件"""
    # 配置安全头
    @app.after_request
    def add_security_headers(response):
        # 内容安全策略头 (CSP)
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "  # 允许内联脚本用于表单验证
            "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "   # 允许内联样式
            "img-src 'self' data:; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "block-all-mixed-content"
        )
        # 其他安全头
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        # 防止特征指纹识别
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), payment=()'
        return response
    
    # 自动HTTPS重定向（生产环境）
    @app.before_request
    def enforce_https():
        if not app.debug and not app.testing and request.url.startswith('http://'):
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)
    
    # 防止会话固定攻击
    @app.before_request
    def session_protection():
        if 'user_id' in session and session.get('_fresh'):
            # 会话已登录且是新会话，重新生成会话ID
            session.regenerate()
            # 设置会话访问时间用于活动检测
            session['last_active'] = datetime.datetime.utcnow().isoformat()
    
    # 活动监控中间件
    @app.before_request
    def activity_monitoring():
        current_time = datetime.datetime.utcnow()
        
        # IP地址检查
        ip = request.remote_addr
        if ip in BANNED_IPS:
            app.logger.warning(f"已封禁IP尝试访问: {ip}")
            abort(403)  # 拒绝访问
            
        # 清理过期记录
        clean_expired_records(current_time)
        
        # 记录请求，用于异常检测
        if request.endpoint:
            # 监控特定端点的访问频率
            record_request(ip, request.endpoint, current_time)

    # 添加日志记录中间件
    @app.before_request
    def log_request_info():
        # 记录请求的基本信息
        app.logger.info(f"请求: {request.method} {request.path} - IP: {request.remote_addr}")
        # 记录访问的URL参数（去除敏感信息）
        params = {k: v for k, v in request.args.items() if not is_sensitive_param(k)}
        if params:
            app.logger.debug(f"URL参数: {params}")
            
    # 将安全上下文添加到g对象
    @app.before_request
    def setup_security_context():
        g.security = {
            'sanitize_html': sanitize_html,
            'validate_input': validate_input,
            'check_rate_limit': check_rate_limit,
            'record_sensitive_operation': record_sensitive_operation
        }
    
    # 数据库操作完成后清理
    @app.teardown_appcontext
    def cleanup_security(exception=None):
        if exception:
            app.logger.error(f"安全上下文处理异常: {str(exception)}")

    # 设置错误处理
    @app.errorhandler(SecurityViolation)
    def handle_security_violation(e):
        app.logger.warning(f"安全违规: {str(e)}")
        return render_template('error.html', error="安全违规，操作被拒绝"), 403

# 辅助函数

def clean_expired_records(current_time):
    """清除过期的安全记录"""
    # 清除60分钟前的登录失败记录
    expiry = current_time - datetime.timedelta(minutes=60)
    for ip in list(LOGIN_ATTEMPTS.keys()):
        if LOGIN_ATTEMPTS[ip]['timestamp'] < expiry:
            del LOGIN_ATTEMPTS[ip]
    
    # 清除频率限制记录
    for key in list(RATE_LIMITS.keys()):
        if RATE_LIMITS[key]['timestamp'] < current_time - datetime.timedelta(minutes=10):
            del RATE_LIMITS[key]
    
    # 清除敏感操作记录
    for key in list(SENSITIVE_OPS.keys()):
        if SENSITIVE_OPS[key]['timestamp'] < current_time - datetime.timedelta(hours=24):
            del SENSITIVE_OPS[key]

def is_sensitive_param(param_name):
    """检查参数名是否敏感"""
    sensitive_patterns = ['password', 'token', 'secret', 'key', 'auth', 'credential']
    return any(pattern in param_name.lower() for pattern in sensitive_patterns)

def record_request(ip, endpoint, timestamp):
    """记录请求，用于异常检测"""
    key = f"{ip}:{endpoint}"
    if key not in RATE_LIMITS:
        RATE_LIMITS[key] = {
            'count': 1,
            'timestamp': timestamp
        }
    else:
        # 如果是旧记录，重置
        if (timestamp - RATE_LIMITS[key]['timestamp']) > datetime.timedelta(minutes=1):
            RATE_LIMITS[key] = {
                'count': 1,
                'timestamp': timestamp
            }
        else:
            RATE_LIMITS[key]['count'] += 1

def check_rate_limit(ip, endpoint, limit=30):
    """检查访问频率"""
    key = f"{ip}:{endpoint}"
    if key in RATE_LIMITS and RATE_LIMITS[key]['count'] > limit:
        if ip not in BANNED_IPS and RATE_LIMITS[key]['count'] > limit * 2:
            # 如果超出限制太多，临时封禁IP
            BANNED_IPS.add(ip)
            # 记录到系统日志
            logging.warning(f"IP地址 {ip} 因超出频率限制被临时封禁")
        return False
    return True

def record_sensitive_operation(user_id, operation, ip):
    """记录敏感操作"""
    key = f"{user_id}:{operation}"
    timestamp = datetime.datetime.utcnow()
    
    if key not in SENSITIVE_OPS:
        SENSITIVE_OPS[key] = {
            'count': 1,
            'timestamp': timestamp,
            'ips': [ip]
        }
    else:
        SENSITIVE_OPS[key]['count'] += 1
        SENSITIVE_OPS[key]['timestamp'] = timestamp
        if ip not in SENSITIVE_OPS[key]['ips']:
            SENSITIVE_OPS[key]['ips'].append(ip)
    
    # 检查异常，比如用户从多个IP执行敏感操作
    if len(SENSITIVE_OPS[key]['ips']) > 3:
        logging.warning(f"用户 {user_id} 的 {operation} 操作来自多个IP: {SENSITIVE_OPS[key]['ips']}")
        return False
    
    return True

def record_login_attempt(ip, success):
    """记录登录尝试"""
    current_time = datetime.datetime.utcnow()
    
    if ip not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip] = {
            'count': 0,
            'success': 0,
            'timestamp': current_time
        }
    
    # 更新计数
    LOGIN_ATTEMPTS[ip]['count'] += 1
    if success:
        LOGIN_ATTEMPTS[ip]['success'] += 1
    LOGIN_ATTEMPTS[ip]['timestamp'] = current_time
    
    # 检查失败次数
    fail_count = LOGIN_ATTEMPTS[ip]['count'] - LOGIN_ATTEMPTS[ip]['success']
    if fail_count >= 5:  # 5次失败尝试
        # 临时封禁IP
        BANNED_IPS.add(ip)
        logging.warning(f"IP地址 {ip} 因多次登录失败被封禁")
        return False
    
    return True

# 验证函数

def sanitize_html(html_content):
    """清理HTML内容，防止XSS攻击"""
    return bleach.clean(
        html_content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip=True
    )

def validate_input(value, pattern=None, max_length=None, required=False):
    """验证输入值是否符合安全规则"""
    # 检查是否为空
    if required and (value is None or value.strip() == ''):
        return False
    
    # 如果值为空且不是必需的，就无需进一步验证
    if value is None or value.strip() == '':
        return True
    
    # 检查长度
    if max_length and len(value) > max_length:
        return False
    
    # 检查模式
    if pattern and not re.match(pattern, value):
        return False
    
    return True

def validate_url(url, allowed_schemes=None, allowed_domains=None):
    """验证URL是否安全"""
    if not url:
        return False
    
    try:
        parsed = urlparse(url)
        
        # 检查URL方案
        if allowed_schemes and parsed.scheme not in allowed_schemes:
            return False
        
        # 检查域名
        if allowed_domains and parsed.netloc not in allowed_domains:
            return False
        
        return True
    except:
        return False

# 安全装饰器

def require_role(role):
    """验证用户角色"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or not hasattr(current_user, role) or not getattr(current_user, role):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def rate_limited(limit=30, period=60):
    """限制请求频率"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            endpoint = request.endpoint
            
            if not check_rate_limit(ip, endpoint, limit):
                abort(429)  # 请求过多
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def audit_trail(operation):
    """记录审计跟踪"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 先检查操作是否允许
            if current_user.is_authenticated:
                if not record_sensitive_operation(current_user.id, operation, request.remote_addr):
                    abort(403)  # 操作被拒绝
            
            # 执行原始函数
            result = f(*args, **kwargs)
            
            # 记录到审计日志
            logging.info(f"审计: 用户 {current_user.id if current_user.is_authenticated else 'anonymous'} "
                         f"执行 {operation} 操作，IP: {request.remote_addr}")
            
            return result
        return decorated_function
    return decorator 