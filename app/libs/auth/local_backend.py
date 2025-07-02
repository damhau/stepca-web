from .base import AuthBackend
from werkzeug.security import check_password_hash

USERS = {
    'admin': {
        'id': 'admin',
        'username': 'admin',
        'password_hash': 'REDACTED-rotated-password-hash',
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
