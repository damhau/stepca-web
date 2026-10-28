import os
import json
import random
import string

basedir = os.path.abspath(os.path.dirname(__file__))

# Load settings.json as fallback (optional when everything is set via env vars)
config = {}
if os.path.exists("settings.json"):
    with open("settings.json") as f:
        config = json.load(f)

def get_config(key_path: str, default=None):
    """Get configuration from env first, fallback to settings.json."""
    env_var = key_path.upper().replace(".", "_")  # e.g. database.host → DATABASE_HOST
    if env_var in os.environ:
        return os.environ[env_var]

    # Fallback to JSON
    parts = key_path.split(".")
    value = config
    try:
        for part in parts:
            value = value[part]
        return value
    except (KeyError, TypeError):
        return default

# Assign configuration values
DB_HOST = get_config("database.host")
DB_USER = get_config("database.user")
DB_PASSWORD = get_config("database.password")
DB_NAME = get_config("database.name")
DB_PORT = get_config("database.port")
CA_URL = get_config("ca.url")
CA_FINGERPRINT = get_config("ca.fingerprint")
# Optional path to the CA root PEM; otherwise it is downloaded once and pinned with CA_FINGERPRINT
CA_ROOT = get_config("ca.root")
CA_ADMIN_PROVISIONER_NAME = get_config("ca.admin_provisioner_name")

print(DB_HOST, DB_USER, CA_URL)

class Config:
    # Authentication backend: 'ldap', 'radius', 'saml', 'oidc'
    AUTH_BACKEND = os.environ.get('AUTH_BACKEND', 'ldap')
    # LDAP-specific configuration
    LDAP_URL = os.environ.get('LDAP_URL') or get_config('ldap.url', 'ldap://localhost')
    LDAP_BASE_DN = os.environ.get('LDAP_BASE_DN') or get_config('ldap.base_dn', '')
    LDAP_DOMAIN = os.environ.get('LDAP_DOMAIN') or get_config('ldap.domain', '')
    LDAP_USER_SEARCH_FILTER = os.environ.get('LDAP_USER_SEARCH_FILTER') or get_config('ldap.user_search_filter', '(uid={username})')
    LDAP_USER_SEARCH_BASE = os.environ.get('LDAP_USER_SEARCH_BASE') or get_config('ldap.user_search_base', LDAP_BASE_DN)
    LDAP_REQUIRED_GROUP_DN = os.environ.get('LDAP_REQUIRED_GROUP_DN') or get_config('ldap.ldap_required_group_dn', LDAP_BASE_DN)
    # Local backend: users and password hashes live outside the source tree
    LOCAL_USERS_FILE = os.environ.get('LOCAL_USERS_FILE', 'local_users.json')
    # OIDC, SAML, RADIUS config can be added similarly
    SECRET_KEY = os.environ.get("SECRET_KEY") or "".join(
        random.choice(string.ascii_letters) for _ in range(32)
    )

    SQLALCHEMY_DATABASE_URI = (
        os.environ.get("SQLALCHEMY_DATABASE_URI") or
        # Explicit driver: SQLAlchemy 2.1+ defaults postgresql:// to psycopg 3
        f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )

    # The app's own data lives in SQLite (in the working directory), so step-ca's
    # database is only ever read and a read-only role is enough
    SQLALCHEMY_BINDS = {
        "app": os.environ.get("APP_DATABASE_URI") or f"sqlite:///{os.path.abspath('stepca-web.db')}"
    }

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session cookie is not sent on cross-site POSTs or subresource requests
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_HTTPONLY = True
    # Set to true when the UI is served over HTTPS
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
    # CSRF tokens stay valid for the whole session instead of 1 hour
    WTF_CSRF_TIME_LIMIT = None
