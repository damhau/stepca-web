from functools import wraps

from flask import jsonify, redirect, request, session, url_for

# Endpoints reachable without a session, everything else requires login
PUBLIC_ENDPOINTS = {"auth.login", "auth.logout", "static"}


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


def require_login():
    """before_request hook: deny by default instead of relying on per-route decorators."""
    if request.endpoint in PUBLIC_ENDPOINTS or 'user_id' in session:
        return None
    if request.path.startswith('/api/'):
        return jsonify({"error": "Authentication required"}), 401
    return redirect(url_for('auth.login'))
