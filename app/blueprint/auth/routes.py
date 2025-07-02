from flask import Blueprint, request, session, redirect, url_for, render_template, current_app
from app.auth.factory import get_auth_backend

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        backend = get_auth_backend(current_app.config)
        user = backend.authenticate(username, password)
        print(user)
        if user:
            session['user_id'] = user.get('id', username)
            return redirect(url_for('home.index'))
        return render_template('auth/login.html', error='Invalid credentials')
    return render_template('auth/login.html')

@auth_bp.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('auth.login'))
