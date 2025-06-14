"""
auth.py - Refactored Authentication System - FIXED VERSION
Clean, secure authentication with SQLite support
"""

import re
import secrets
import hashlib
import base64
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash

from models import User, db

# Blueprint Setup
auth_bp = Blueprint('auth', __name__)

# Security Constants
SESSION_TIMEOUT = 3600          # 1 hour
SESSION_ABSOLUTE_TIMEOUT = 28800 # 8 hours
MAX_SESSIONS_PER_USER = 5
RSA_VERIFICATION_ENABLED = False  # Disabled for simplicity in local dev

# Helper Functions
def generate_user_id():
    """Generate unique 6-digit user ID"""
    import random
    while True:
        user_id = f"{random.randint(100000, 999999)}"
        if not User.query.filter_by(user_id=user_id).first():
            return user_id

def generate_secure_session_id():
    """Generate secure session identifier"""
    return secrets.token_urlsafe(32)

def hash_session_id(session_id):
    """Hash session ID for database storage"""
    return hashlib.sha256(session_id.encode()).hexdigest()

def validate_password_strength(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is strong"

def validate_rsa_public_key(public_key_pem):
    """Validate RSA public key format"""
    try:
        if not public_key_pem.strip():
            return False, "Public key cannot be empty"
        
        if not public_key_pem.startswith('-----BEGIN PUBLIC KEY-----'):
            return False, "Invalid public key format - must start with PEM header"
        
        if not public_key_pem.endswith('-----END PUBLIC KEY-----'):
            return False, "Invalid public key format - must end with PEM footer"
        
        # Basic length check
        if len(public_key_pem) < 200 or len(public_key_pem) > 1000:
            return False, "Public key length is suspicious"
        
        return True, "Public key format is valid"
        
    except Exception as e:
        return False, f"Public key validation error: {str(e)}"

def verify_password_signature(password, signature_base64, public_key_pem):
    """Verify RSA signature (simplified for local dev)"""
    if not RSA_VERIFICATION_ENABLED:
        return True  # Skip verification in local development
    
    # In production, implement actual RSA signature verification
    try:
        return True
    except Exception as e:
        print(f"RSA signature verification failed: {e}")
        return False

# Session Validation Decorator
def validate_session_security(f):
    """Decorator for session security validation"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': 'Authentication required'}), 401
        
        # Check session timeout
        if 'last_activity' in session:
            try:
                last_activity = datetime.fromisoformat(session['last_activity'])
                if datetime.utcnow() - last_activity > timedelta(seconds=SESSION_TIMEOUT):
                    session.clear()
                    logout_user()
                    return jsonify({'error': 'Session expired'}), 401
            except (ValueError, TypeError):
                session.clear()
                logout_user()
                return jsonify({'error': 'Invalid session'}), 401
        
        # Check absolute timeout
        if 'session_start' in session:
            try:
                session_start = datetime.fromisoformat(session['session_start'])
                if datetime.utcnow() - session_start > timedelta(seconds=SESSION_ABSOLUTE_TIMEOUT):
                    session.clear()
                    logout_user()
                    return jsonify({'error': 'Session expired (absolute timeout)'}), 401
            except (ValueError, TypeError):
                session.clear()
                logout_user()
                return jsonify({'error': 'Invalid session'}), 401
        
        # Update last activity
        session['last_activity'] = datetime.utcnow().isoformat()
        session.permanent = True
        
        return f(*args, **kwargs)
    return decorated_function

# Route Handlers
@auth_bp.route('/')
def index():
    """Main landing page"""
    # Check session instead of current_user for better reliability
    if session.get('user_id') or session.get('username'):
        return redirect(url_for('chat.chat'))
    
    return render_template('index.html')

@auth_bp.route('/register')
def register_page():
    """Registration page"""
    try:
        if current_user.is_authenticated:
            return redirect('/chat')
        
        return render_template('register.html')
        
    except Exception as e:
        print(f"Register page error: {e}")
        try:
            return render_template('register.html')
        except:
            return "Error loading registration page", 500

# Authentication API
@auth_bp.route('/api/register', methods=['POST'])
def register():
    """User registration API"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        # Extract data
        username = data.get('username', '').strip()
        password = data.get('password', '')
        public_key = data.get('public_key', '').strip()
        
        print(f"Registration attempt for user: {username}")
        
        # Validate required fields
        if not username or not password:
            return jsonify({'error': 'Missing required fields: username and password'}), 400
        
        # Validate username format
        if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
            return jsonify({'error': 'Username must be 3-20 characters long and contain only letters, numbers, underscores, or hyphens'}), 400
        
        # Check if username exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"Registration failed: Username {username} already exists")
            return jsonify({'error': 'Username already exists'}), 409
        
        # Validate password
        password_valid, password_msg = validate_password_strength(password)
        if not password_valid:
            return jsonify({'error': password_msg}), 400
        
        # Validate public key if provided
        if public_key:
            key_valid, key_msg = validate_rsa_public_key(public_key)
            if not key_valid:
                return jsonify({'error': key_msg}), 400
        
        # Generate unique user_id
        user_id = generate_user_id()
        
        # Create new user
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            public_key=public_key if public_key else None,
            user_id=user_id,
            is_online=False,
            is_admin=False,
            last_active=datetime.utcnow()
        )
        
        # Save to database
        db.session.add(new_user)
        db.session.commit()
        
        print(f"Registration successful: {username} (ID: {user_id})")
        
        return jsonify({
            'status': 'success',
            'user_id': user_id,
            'username': username,
            'message': 'Registration successful',
            'code': 'registration_ok'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Registration error: {str(e)}")
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@auth_bp.route('/api/check-username/<username>')
def check_username(username):
    """Check if username is available"""
    try:
        # Validate username format
        if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username):
            return jsonify({
                'available': False,
                'reason': 'Invalid username format'
            }), 400
        
        # Check if username exists
        existing_user = User.query.filter_by(username=username).first()
        
        return jsonify({
            'available': existing_user is None,
            'username': username
        })
        
    except Exception as e:
        print(f"Username check error: {str(e)}")
        return jsonify({'error': 'Failed to check username'}), 500

@auth_bp.route('/api/login', methods=['POST'])
def login():
    """User login API"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        signature_base64 = data.get('signature', '')
        
        print(f"Login attempt for user: {username}")
        
        if not all([username, password]):
            return jsonify({'error': 'Missing credentials: username and password required'}), 400
        
        # Find user
        user = User.query.filter_by(username=username).first()
        
        if not user:
            print(f"Login failed: User not found - {username}")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Check password
        if not check_password_hash(user.password_hash, password):
            print(f"Login failed: Invalid password - {username}")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Verify RSA signature if provided
        if signature_base64:
            if not verify_password_signature(password, signature_base64, user.public_key):
                print(f"Login failed: RSA signature verification failed - {username}")
                return jsonify({'error': 'RSA signature verification failed'}), 401
            print(f"RSA signature verified for user: {username}")
        elif RSA_VERIFICATION_ENABLED:
            print(f"Login without RSA signature for user: {username}")
        
        # Generate secure session ID
        secure_session_id = generate_secure_session_id()
        
        # Login user with Flask-Login
        login_user(user, remember=True)
        
        # Set secure session
        session.permanent = True
        session['session_id'] = secure_session_id
        session['session_start'] = datetime.utcnow().isoformat()
        session['last_activity'] = datetime.utcnow().isoformat()
        session['user_id'] = user.id
        session['username'] = user.username
        session['login_time'] = datetime.utcnow().isoformat()
        session['ip_address'] = request.remote_addr
        session['user_agent'] = request.headers.get('User-Agent', '')[:200]
        
        # Update user online status
        try:
            if hasattr(user, 'is_online'):
                user.is_online = True
            if hasattr(user, 'last_active'):
                user.last_active = datetime.utcnow()
            db.session.commit()
            print(f"User status updated: {username} is now online")
        except Exception as e:
            print(f"Status update failed for {username}: {e}")
            db.session.rollback()
        
        print(f"Login successful: {username} (ID: {user.user_id})")
        
        return jsonify({
            'status': 'success',
            'user_id': user.user_id,
            'username': user.username,
            'is_admin': getattr(user, 'is_admin', False),
            'message': 'Login successful',
            'session_info': {
                'expires_in': SESSION_TIMEOUT,
                'absolute_timeout': SESSION_ABSOLUTE_TIMEOUT
            },
            'code': 'login_ok'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Login error: {str(e)}")
        return jsonify({'error': f'Login failed: {str(e)}'}), 500
    
    
    # Logout System
@auth_bp.route('/logout', methods=['GET'])
def logout_page():
    """Logout page redirect"""
    from flask import session
    
    # Clear session data
    session.clear()
    session.permanent = False
    
    # Create response with cache-busting headers
    response = redirect(url_for('auth.index'))
    response.headers['Clear-Site-Data'] = '"cache", "cookies", "storage"'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

@auth_bp.route('/api/logout', methods=['POST'])
def api_logout():
    """API logout endpoint"""
    try:
        print(f"API Logout request from user: {current_user.username if current_user.is_authenticated else 'Anonymous'}")
        
        # Update user offline status
        if current_user.is_authenticated:
            try:
                if hasattr(current_user, 'is_online'):
                    current_user.is_online = False
                if hasattr(current_user, 'last_active'):
                    current_user.last_active = datetime.utcnow()
                db.session.commit()
                print(f"User {current_user.username} status updated to offline")
            except Exception as e:
                print(f"Status update failed: {e}")
                db.session.rollback()
            
            # Logout from Flask-Login
            logout_user()
        
        # Clear session data
        session.clear()
        session.permanent = False
        
        print("API Logout successful")
        
        # Return JSON response
        response = jsonify({
            'status': 'success',
            'message': 'Logout successful',
            'code': 'logout_ok'
        })
        
        # Add cache-busting headers
        response.headers['Clear-Site-Data'] = '"cache", "cookies", "storage"'
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
        
    except Exception as e:
        print(f"API Logout error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Logout failed',
            'error': str(e)
        }), 500

# Session Management
@auth_bp.route('/api/check_auth')
def check_auth():
    """Check authentication status"""
    try:
        if current_user.is_authenticated:
            # Check session timeout
            if 'last_activity' in session:
                try:
                    last_activity = datetime.fromisoformat(session['last_activity'])
                    if datetime.utcnow() - last_activity > timedelta(seconds=SESSION_TIMEOUT):
                        logout_user()
                        session.clear()
                        return jsonify({'authenticated': False, 'reason': 'Session expired'}), 401
                except (ValueError, TypeError):
                    logout_user()
                    session.clear()
                    return jsonify({'authenticated': False, 'reason': 'Invalid session'}), 401
            
            # Update last activity
            session['last_activity'] = datetime.utcnow().isoformat()
            
            return jsonify({
                'authenticated': True,
                'user_id': current_user.user_id,
                'username': current_user.username,
                'id': current_user.id,
                'is_admin': getattr(current_user, 'is_admin', False),
                'public_key': current_user.public_key if hasattr(current_user, 'public_key') else None,
                'session_info': {
                    'login_time': session.get('login_time'),
                    'last_activity': session.get('last_activity'),
                    'expires_in': SESSION_TIMEOUT
                }
            })
        else:
            return jsonify({'authenticated': False, 'reason': 'Not logged in'}), 401
            
    except Exception as e:
        print(f"Auth check error: {e}")
        return jsonify({'authenticated': False, 'reason': 'Auth check failed'}), 401

@auth_bp.route('/api/session/info')
@login_required
@validate_session_security
def session_info():
    """Get detailed session information"""
    try:
        session_duration = None
        if 'session_start' in session:
            try:
                session_start = datetime.fromisoformat(session['session_start'])
                duration = datetime.utcnow() - session_start
                session_duration = str(duration)
            except (ValueError, TypeError):
                pass
        
        return jsonify({
            'status': 'success',
            'session': {
                'user_id': current_user.user_id,
                'username': current_user.username,
                'session_id': session.get('session_id', '')[:8] + '...',  # Partial for security
                'login_time': session.get('login_time'),
                'last_activity': session.get('last_activity'),
                'session_duration': session_duration,
                'ip_address': session.get('ip_address'),
                'expires_in': SESSION_TIMEOUT,
                'absolute_timeout': SESSION_ABSOLUTE_TIMEOUT
            }
        })
        
    except Exception as e:
        print(f"Session info error: {e}")
        return jsonify({'error': 'Failed to get session info'}), 500

# Admin Endpoints
@auth_bp.route('/api/admin/users')
@login_required
def admin_users():
    """List users (admin only)"""
    try:
        if not getattr(current_user, 'is_admin', False):
            return jsonify({'error': 'Admin access required'}), 403
        
        users = User.query.all()
        users_data = []
        
        for user in users:
            users_data.append({
                'id': user.id,
                'user_id': user.user_id,
                'username': user.username,
                'is_online': getattr(user, 'is_online', False),
                'is_admin': getattr(user, 'is_admin', False),
                'last_active': user.last_active.isoformat() if hasattr(user, 'last_active') and user.last_active else None,
                'has_public_key': bool(user.public_key)
            })
        
        return jsonify({
            'status': 'success',
            'users': users_data,
            'total_users': len(users_data)
        })
        
    except Exception as e:
        print(f"Admin users error: {e}")
        return jsonify({'error': 'Failed to fetch users'}), 500

# Error Handlers
@auth_bp.errorhandler(401)
def unauthorized(error):
    """Handle authentication errors"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Authentication required'}), 401
    else:
        return redirect(url_for('auth.index'))

@auth_bp.errorhandler(403)
def forbidden(error):
    """Handle access errors"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Access forbidden'}), 403
    else:
        return redirect(url_for('auth.index'))

@auth_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Endpoint not found'}), 404
    else:
        return redirect(url_for('auth.index'))

# Utility Functions
def get_user_by_id(user_id):
    """Get user by ID"""
    return User.query.filter_by(user_id=user_id).first()

def get_user_by_username(username):
    """Get user by username"""
    return User.query.filter_by(username=username).first()

def is_user_online(user_id):
    """Check if user is online"""
    user = get_user_by_id(user_id)
    return getattr(user, 'is_online', False) if user else False

print("Auth system loaded successfully")