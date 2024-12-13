from flask import Flask, request, jsonify
import logging
import functools

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# 역할 기반 접근 제어 데코레이터
def role_required(allowed_roles):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            # NGINX Ingress Controller에서 전달된 헤더 확인
            user_groups = request.headers.get('X-Groups', '').split(',')
            user_email = request.headers.get('X-Email', '')
            user_name = request.headers.get('X-User-Name', '')

            # 권한 검증 로직
            if any(role in user_groups for role in allowed_roles):
                app.logger.info(f"Access granted for {user_email} to endpoint")
                return f(user_name=user_name, *args, **kwargs)
            else:
                app.logger.warning(f"Access denied for {user_email}")
                return jsonify({"error": "Insufficient permissions"}), 403
        return wrapper
    return decorator

# 사용자 관리 엔드포인트
@app.route('/api/users', methods=['GET'])
@role_required(['admin', 'user-manager'])
def list_users(user_name):
    return jsonify({
        "users": [
            {"id": 1, "name": "Admin User"},
            {"id": 2, "name": "Regular User"}
        ],
        "message": f"Logged in as: {user_name}"
    })

# 관리자 전용 엔드포인트
@app.route('/api/admin', methods=['GET'])
@role_required(['admin'])
def admin_dashboard(user_name):
    return jsonify({
        "admin_data": "Sensitive administrative information",
        "message": f"Logged in as: {user_name}"
    })

# 일반 사용자 엔드포인트
@app.route('/api/profile', methods=['GET'])
@role_required(['user'])
def user_profile(user_name):
    return jsonify({
        "profile": "User profile information",
        "message": f"Logged in as: {user_name}"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)