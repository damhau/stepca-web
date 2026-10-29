from app.libs.auth.ldap_backend import LDAPAuthBackend
from app.libs.auth.local_backend import LocalAuthBackend

BACKENDS = {"ldap": LDAPAuthBackend, "local": LocalAuthBackend}


def get_auth_backend(config):
    backend_type = config.get('AUTH_BACKEND', 'ldap')
    if backend_type not in BACKENDS:
        raise ValueError(f"Unknown auth backend: {backend_type} (use 'ldap' or 'local')")
    return BACKENDS[backend_type](config)
