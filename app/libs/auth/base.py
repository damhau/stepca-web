class AuthBackend:
    def authenticate(self, username, password):
        raise NotImplementedError

    def get_user(self, user_id):
        raise NotImplementedError
