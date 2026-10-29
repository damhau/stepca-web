class AuthBackend:
    def authenticate(self, username, password):
        """The user as a dict ({'id': ..., plus 'role' or 'groups'}) if the credentials are valid, else None."""
        raise NotImplementedError
