from .base import AuthBackend
from werkzeug.security import check_password_hash

USERS = {
    'admin': {
        'id': 'admin',
        'username': 'admin',
        'password_hash': 'scrypt:32768:8:1$HbGmOjnK1OtH9goI$985067b6809763fd91db9d0aeca8d6b63683c7f01d6b33d3ef1094e8ed4d0face469f74c4aff4042c2e9d8ff40b1a0e5ae6c3800e4c29f0df250e88bd88ef2ef',
        'attributes': {'role': 'admin'}
    },
}

class LocalAuthBackend(AuthBackend):
    def __init__(self, config):
        print("Using LocalAuthBackend")
        self.config = config

    def authenticate(self, username, password):
        user = USERS.get(username)
        if user and check_password_hash(user['password_hash'], password):
            return {'id': user['id'], 'attributes': user.get('attributes', {})}
        return None

    def get_user(self, user_id):
        user = USERS.get(user_id)
        if user:
            return {'id': user['id'], 'attributes': user.get('attributes', {})}
        return None
