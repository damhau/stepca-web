from app.libs.auth.ldap_backend import LDAPAuthBackend
from app.libs.auth.local_backend import LocalAuthBackend

BACKENDS = {"ldap": LDAPAuthBackend, "local": LocalAuthBackend}


# "oidc" has no password backend: single sign-on goes through app.libs.auth.oidc and /session/oidc/*
SSO_ONLY = "oidc"


def get_auth_backend(config):
    """The backend that checks a username and a password; None when only single sign-on is allowed."""
    backend_type = config.get('AUTH_BACKEND', 'ldap')
    if backend_type == SSO_ONLY:
        return None
    if backend_type not in BACKENDS:
        raise ValueError(f"Unknown auth backend: {backend_type} (use 'ldap', 'local' or 'oidc')")
    return BACKENDS[backend_type](config)
