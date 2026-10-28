import json
import os

from werkzeug.security import check_password_hash

from .base import AuthBackend


def load_users(path):
    """Load users from a JSON file: {"<username>": {"password_hash": "...", "role": "admin|operator|viewer"}}."""
    if not os.path.exists(path):
        print(f"❌ Local users file {path} not found, no local user can log in.")
        return {}
    with open(path) as f:
        return json.load(f)


class LocalAuthBackend(AuthBackend):
    def __init__(self, config):
        print("Using LocalAuthBackend")
        self.config = config
        self.users = load_users(config.get('LOCAL_USERS_FILE', 'local_users.json'))

    def authenticate(self, username, password):
        user = self.users.get(username)
        if user and check_password_hash(user['password_hash'], password):
            attributes = user.get('attributes', {})
            return {'id': username, 'attributes': attributes, 'role': user.get('role') or attributes.get('role')}
        return None

    def get_user(self, user_id):
        user = self.users.get(user_id)
        if user:
            return {'id': user_id, 'attributes': user.get('attributes', {})}
        return None
