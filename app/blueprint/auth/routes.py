from flask import Blueprint, current_app, redirect, render_template, request, session, url_for

from app.auth.factory import get_auth_backend
from app.auth.roles import resolve_role
from app.extensions import limiter
from app.libs.audit import audit

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
# Only failed sign-ins count: a successful one redirects
@limiter.limit(lambda: current_app.config["LOGIN_RATE_LIMIT"], methods=["POST"], deduct_when=lambda response: response.status_code != 302)
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        backend = get_auth_backend(current_app.config)
        user = backend.authenticate(username, password)
        role = resolve_role(user, current_app.config) if user else None
        if user and role:
            # Start from an empty session: nothing set before login survives it
            session.clear()
            session.permanent = True
            session['user_id'] = user.get('id', username)
            session['role'] = role
            audit("login", username)
            return redirect(url_for('home.index'))
        audit("login", username, success=False, detail="no role" if user else "invalid credentials", user=username)
        return render_template('auth/login.html', error='Invalid credentials')
    return render_template('auth/login.html')

@auth_bp.route('/logout')
def logout():
    if 'user_id' in session:
        audit("logout", session['user_id'])
    session.clear()
    return redirect(url_for('auth.login'))
