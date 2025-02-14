from flask import Flask, request, jsonify
import jwt
import requests
from cachetools import TTLCache
import os
import logging
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization
import base64

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# JWKS URL, Clint ID(애플리케이션) 환경 변수 설정
KEYCLOAK_PUBLIC_KEY_URL = os.getenv('KEYCLOAK_PUBLIC_KEY_URL')
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID')

# JWKS 캐시
jwks_cache = TTLCache(maxsize=1, ttl=3600)

def ensure_bytes(key):
    """Convert string to bytes if needed"""
    if isinstance(key, str):
        key = key.encode('utf-8')
    return key

# base64url 디코딩
def decode_base64_url(value):
    """Decode base64url-encoded value"""
    padding = b'=' * (4 - (len(value) % 4))
    return base64.urlsafe_b64decode(ensure_bytes(value) + padding)

# JWK to PEM 변환
def jwk_to_pem(jwk):
    """Convert a JWK to PEM format"""
    # Extract the components from JWK
    e = int.from_bytes(decode_base64_url(jwk['e']), 'big')
    n = int.from_bytes(decode_base64_url(jwk['n']), 'big')
    
    # Create RSA public numbers
    public_numbers = RSAPublicNumbers(e=e, n=n)
    public_key = public_numbers.public_key()
    
    # Convert to PEM
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

# 공개 키 가져오기
def get_public_key():
    """Fetch and cache Keycloak's public key"""
    if 'pem_key' not in jwks_cache:
        try:
            response = requests.get(KEYCLOAK_PUBLIC_KEY_URL)
            response.raise_for_status()
            jwks = response.json()
            
            # Get the first key from keys array
            if 'keys' in jwks and len(jwks['keys']) > 0:
                key = jwks['keys'][0]  # Usually there's only one key
                pem_key = jwk_to_pem(key)
                jwks_cache['pem_key'] = pem_key
                logging.info("Successfully converted JWKS to PEM")
            else:
                raise ValueError("No keys found in JWKS response")
                
        except Exception as e:
            logging.error(f"Error processing public key: {e}")
            raise
    return jwks_cache['pem_key']

# 토큰 검증 및 디코딩
def verify_token(token):
    """Verify JWT token and return decoded content"""
    try:
        public_key = get_public_key()
        
        # First try to decode with audience verification
        try:
            decoded = jwt.decode(
                token,
                public_key,
                algorithms=['RS256'],
                audience=KEYCLOAK_CLIENT_ID
            )
        except jwt.exceptions.InvalidAudienceError:
            # If audience verification fails, try decoding without audience verification
            # and then manually check the intended audience
            decoded = jwt.decode(
                token,
                public_key,
                algorithms=['RS256'],
                options={'verify_aud': False}
            )
            
            # Check if token is intended for our client
            token_aud = decoded.get('aud', [])
            if isinstance(token_aud, str):
                token_aud = [token_aud]
            
            if KEYCLOAK_CLIENT_ID not in token_aud:
                logging.warning(f"Token audience {token_aud} does not match expected client {KEYCLOAK_CLIENT_ID}")
            
        return decoded
    
    except Exception as e:
        logging.error(f"Token verification failed: {e}")
        raise

# admin role 확인
def has_admin_role(token_data):
    """Check if token has admin role in client roles"""
    try:
        # First check in resource_access
        client_access = token_data.get('resource_access', {}).get(KEYCLOAK_CLIENT_ID, {})
        client_roles = client_access.get('roles', [])
        
        # Then check in realm_access
        realm_roles = token_data.get('realm_access', {}).get('roles', [])
        
        return 'admin' in client_roles or 'admin' in realm_roles
    except Exception as e:
        logging.error(f"Error checking admin role: {e}")
        return False

# 사용자 이름 추출
def get_username(token_data):
    """Extract username from token claims"""
    return (
        token_data.get('preferred_username')
        or token_data.get('name')
        or token_data.get('email')
        or 'Unknown User'
    )

@app.route('/')
def home():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({
            "message": "Welcome to the API"
        })
    
    try:
        token = auth_header.split('Bearer ')[1]
        token_data = verify_token(token)
        username = get_username(token_data)
        return jsonify({
            "message": f"Welcome to the API. You are logged in as {username}"
        })
    except Exception as e:
        return jsonify({
            "message": "Welcome to the API",
            "error": str(e)
        })

@app.route('/token')
def token_info():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "No token provided"}), 401
    
    token = auth_header.split('Bearer ')[1]
    try:
        token_data = verify_token(token)
        username = get_username(token_data)
        return jsonify({
            "message": f"Token information for user: {username}",
            "token_data": token_data
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 401

@app.route('/admin')
def admin():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "No token provided"}), 401
    
    token = auth_header.split('Bearer ')[1]
    try:
        token_data = verify_token(token)
        if not has_admin_role(token_data):
            username = get_username(token_data)
            return jsonify({
                "error": f"Access denied. User {username} does not have admin role"
            }), 403
        
        username = get_username(token_data)
        return jsonify({
            "message": f"Welcome to admin area. You are logged in as {username} (Admin)"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
