
from app.libs.auth.ldap_backend import LDAPAuthBackend
from app.libs.auth.radius_backend import RadiusAuthBackend
from app.libs.auth.saml_backend import SAMLAuthBackend
from app.libs.auth.oidc_backend import OIDCAuthBackend
from app.libs.auth.local_backend import LocalAuthBackend


def get_auth_backend(config):
    backend_type = config.get('AUTH_BACKEND', 'ldap')
    if backend_type == 'ldap':
        return LDAPAuthBackend(config)
    elif backend_type == 'radius':
        return RadiusAuthBackend(config)
    elif backend_type == 'saml':
        return SAMLAuthBackend(config)
    elif backend_type == 'oidc':
        return OIDCAuthBackend(config)
    elif backend_type == 'local':
        return LocalAuthBackend(config)
    else:
        raise ValueError(f"Unknown auth backend: {backend_type}")
