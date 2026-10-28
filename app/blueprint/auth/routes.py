from flask import Blueprint, current_app, redirect, render_template, request, session, url_for

from app.auth.factory import get_auth_backend

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        backend = get_auth_backend(current_app.config)
        user = backend.authenticate(username, password)
        if user:
            # Start from an empty session: nothing set before login survives it
            session.clear()
            session.permanent = True
            session['user_id'] = user.get('id', username)
            return redirect(url_for('home.index'))
        return render_template('auth/login.html', error='Invalid credentials')
    return render_template('auth/login.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))
