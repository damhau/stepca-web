"""The app's settings, loaded once by create_app: environment variables first, then settings.json, then the defaults.

Environment variable names are the field names in upper case (DATABASE_HOST, CA_URL, ...). settings.json nests
them by their first word: {"database": {"host": ...}, "ca": {"url": ...}, "ldap": {...}, "roles": {...}}.
"""

import json
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal

from flask import current_app
from pydantic import SecretStr, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict
from sqlalchemy.engine import URL

# settings.json keys that predate this module and don't flatten to the setting's name
JSON_ALIASES = {
    "ldap_ldap_required_group_dn": "ldap_required_group_dn",
    "roles_admin_group": "role_admin_group",
    "roles_operator_group": "role_operator_group",
    "roles_viewer_group": "role_viewer_group",
    "roles_default": "default_role",
}

ROLE_NAMES = ("viewer", "operator", "admin", "none")


class JsonFileSource(PydanticBaseSettingsSource):
    """settings.json in the data directory, if there is one."""

    def __init__(self, settings_cls, path: Path):
        super().__init__(settings_cls)
        self.path = path

    def get_field_value(self, field, field_name):  # noqa: ARG002  required by the base class; __call__ does the work
        return None, field_name, False

    def __call__(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {}
        with self.path.open() as f:
            data = json.load(f)
        flat: dict[str, Any] = {}
        for section, values in data.items():
            if isinstance(values, dict):
                for key, value in values.items():
                    name = f"{section}_{key}".lower()
                    flat[JSON_ALIASES.get(name, name)] = value
            else:
                flat[section.lower()] = values
        return flat


class Settings(BaseSettings):
    # An empty variable (CA_ADMIN_PASSWORD_FILE= in .env) is unset, as before this module
    model_config = SettingsConfigDict(case_sensitive=False, extra="ignore", env_file=None, env_ignore_empty=True)

    # Where the app keeps its files: settings.json, admin.crt, admin.key, ca_root.crt, stepca-web.db,
    # jwk_key.json and local_users.json. Relative file settings are relative to it
    data_dir: Path = Path(".")
    testing: bool = False
    log_level: str = "INFO"

    # Signs the session cookie: the same for every worker and restart
    secret_key: SecretStr
    session_lifetime_hours: int = 8
    # The UI is served over HTTPS: secure cookie and HSTS
    session_cookie_secure: bool = False
    # Reverse proxies in front of the app, whose X-Forwarded-For/-Proto are trusted
    trusted_proxies: int = 0
    # Failed sign-ins allowed per client address (https://limits.readthedocs.io)
    login_rate_limit: str = "10 per minute;50 per hour"
    ratelimit_storage_uri: str = "memory://"

    # step-ca's database, read-only
    database_host: str
    database_port: int = 5432
    database_user: str | None = None
    database_password: SecretStr | None = None
    database_name: str | None = None
    # Overrides the URI built from database_*
    sqlalchemy_database_uri: str | None = None
    # The app's own database; sqlite:///<data_dir>/stepca-web.db by default
    app_database_uri: str | None = None

    # step-ca
    ca_url: str
    ca_fingerprint: str | None = None
    # The CA root as a file, instead of downloading it and checking ca_fingerprint
    ca_root: Path | None = None
    # The app's admin identity on the CA: this subject on this provisioner
    ca_admin_provisioner_name: str = "Admin JWK"
    ca_admin_subject: str = "step"
    # How the top bar names the CA (its URL's host by default), and an environment badge such as "Production"
    ca_display_name: str | None = None
    ca_environment: str | None = None
    # The provisioner's password, to decrypt its key in memory (otherwise jwk_key.json is read)
    ca_admin_password_file: Path | None = None
    ca_admin_password: SecretStr | None = None

    # Authentication
    # "oidc": single sign-on only, no password form. With "ldap" or "local", oidc_enabled adds it beside the form
    auth_backend: Literal["ldap", "local", "oidc"] = "ldap"
    ldap_url: str = "ldap://localhost"
    ldap_start_tls: bool = False
    ldap_ca_file: Path | None = None
    ldap_base_dn: str = ""
    ldap_domain: str = ""
    ldap_bind_dn: str | None = None
    ldap_user_search_filter: str = "(uid={username})"
    ldap_user_search_base: str | None = None
    ldap_required_group_dn: str | None = None
    local_users_file: Path = Path("local_users.json")

    # Single sign-on with OpenID Connect (authorization code flow with PKCE)
    oidc_enabled: bool = False
    # The provider's issuer URL: its /.well-known/openid-configuration is read from it
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: SecretStr | None = None
    # The secret as a file (a Docker secret), instead of oidc_client_secret
    oidc_client_secret_file: Path | None = None
    # Where the provider sends the browser back to: <this app's URL>/api/v1/session/oidc/callback
    # (built from the request when unset; set it when the app is behind a proxy that doesn't forward the scheme)
    oidc_redirect_uri: str | None = None
    oidc_scopes: str = "openid profile email"
    # The claim that names the user (the audit log's and the top bar's name), and the one that lists their groups
    oidc_username_claim: str = "preferred_username"
    oidc_groups_claim: str = "groups"
    # Only members of this group may sign in; the groups are matched against role_*_group as they are in the claim
    oidc_required_group: str | None = None
    # CA that issued the provider's certificate (the system CAs when unset)
    oidc_ca_file: Path | None = None
    # The sign-in button's text
    oidc_display_name: str = "Single sign-on"

    # Roles: LDAP group DNs per role; users in none of them get default_role ("none" refuses them)
    role_admin_group: str | None = None
    role_operator_group: str | None = None
    role_viewer_group: str | None = None
    default_role: Literal["viewer", "operator", "admin", "none"] = "viewer"

    # Start/stop of the step-ca systemd unit through sudo: off by default, never works in Docker
    service_control_enabled: bool = False

    # How often a page checks step-ca's tables for new certificates and revocations, at most
    inventory_refresh_seconds: float = 5

    # The built frontend (npm run build in frontend/); frontend/dist next to the app by default
    frontend_dir: Path = Path(__file__).resolve().parent.parent / "frontend" / "dist"

    @classmethod
    def settings_customise_sources(cls, settings_cls, init_settings, env_settings, dotenv_settings, file_secret_settings):
        data_dir = Path(env_settings().get("data_dir") or init_settings().get("data_dir") or ".")
        return init_settings, env_settings, JsonFileSource(settings_cls, data_dir / "settings.json")

    @field_validator("*", mode="before")
    @classmethod
    def empty_is_unset(cls, value, info):
        # Also for settings.json: "" would otherwise become Path("."), the data directory itself
        field = cls.model_fields[info.field_name]
        if value == "" and not field.is_required():
            return field.get_default(call_default_factory=True)
        return value

    @field_validator("secret_key")
    @classmethod
    def secret_key_is_set(cls, value):
        if not value.get_secret_value():
            raise ValueError('empty: generate one with python -c "import secrets; print(secrets.token_hex(32))"')
        return value

    @model_validator(mode="after")
    def defaults_from_other_settings(self):
        if self.ldap_user_search_base is None:
            self.ldap_user_search_base = self.ldap_base_dn
        return self

    @model_validator(mode="after")
    def oidc_is_complete(self):
        if not self.oidc_active:
            return self
        missing = [
            name.upper()
            for name, value in (("oidc_issuer", self.oidc_issuer), ("oidc_client_id", self.oidc_client_id))
            if not value
        ]
        if missing:
            raise ValueError(f"{', '.join(missing)}: required for single sign-on")
        if not (self.oidc_client_secret or self.oidc_client_secret_file):
            raise ValueError("OIDC_CLIENT_SECRET (or OIDC_CLIENT_SECRET_FILE): required for single sign-on")
        if self.oidc_client_secret_file and not self.path(self.oidc_client_secret_file).is_file():
            raise ValueError(f"OIDC_CLIENT_SECRET_FILE {self.path(self.oidc_client_secret_file)} does not exist")
        return self

    @property
    def oidc_active(self) -> bool:
        """Whether single sign-on is offered: auth_backend=oidc, or oidc_enabled beside ldap or local."""
        return self.oidc_enabled or self.auth_backend == "oidc"

    @property
    def password_login(self) -> bool:
        return self.auth_backend != "oidc"

    def oidc_secret(self) -> str | None:
        """The client secret: the file's content (without its trailing newline) when there is a file."""
        if self.oidc_client_secret_file:
            return self.path(self.oidc_client_secret_file).read_text().strip()
        return self.oidc_client_secret.get_secret_value() if self.oidc_client_secret else None

    def path(self, value: Path | str) -> Path:
        """A file setting, resolved against the data directory when it is relative."""
        value = Path(value)
        return value if value.is_absolute() else self.data_dir / value

    @property
    def step_database_uri(self) -> str:
        if self.sqlalchemy_database_uri:
            return self.sqlalchemy_database_uri
        password = self.database_password.get_secret_value() if self.database_password else None
        url = URL.create(
            "postgresql+psycopg", self.database_user, password, self.database_host, self.database_port, self.database_name
        )
        return url.render_as_string(hide_password=False)

    @property
    def app_database(self) -> str:
        return self.app_database_uri or f"sqlite:///{self.path('stepca-web.db').resolve()}"

    def flask_config(self) -> dict[str, Any]:
        """app.config, as Flask, its extensions and the app's own code read it."""
        return {
            "TESTING": self.testing,
            "SECRET_KEY": self.secret_key.get_secret_value(),
            "PERMANENT_SESSION_LIFETIME": timedelta(hours=self.session_lifetime_hours),
            # Session cookie is not sent on cross-site POSTs or subresource requests
            "SESSION_COOKIE_SAMESITE": "Lax",
            "SESSION_COOKIE_HTTPONLY": True,
            "SESSION_COOKIE_SECURE": self.session_cookie_secure,
            # CSRF tokens stay valid for the whole session instead of 1 hour
            "WTF_CSRF_TIME_LIMIT": None,
            "SQLALCHEMY_DATABASE_URI": self.step_database_uri,
            # The app's own data lives in its own database, so step-ca's is only ever read
            "SQLALCHEMY_BINDS": {"app": self.app_database},
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "RATELIMIT_STORAGE_URI": self.ratelimit_storage_uri,
            "TRUSTED_PROXIES": self.trusted_proxies,
            "LOGIN_RATE_LIMIT": self.login_rate_limit,
            "AUTH_BACKEND": self.auth_backend,
            "LDAP_URL": self.ldap_url,
            "LDAP_START_TLS": self.ldap_start_tls,
            "LDAP_CA_FILE": str(self.path(self.ldap_ca_file)) if self.ldap_ca_file else None,
            "LDAP_BASE_DN": self.ldap_base_dn,
            "LDAP_DOMAIN": self.ldap_domain,
            "LDAP_BIND_DN": self.ldap_bind_dn,
            "LDAP_USER_SEARCH_FILTER": self.ldap_user_search_filter,
            "LDAP_USER_SEARCH_BASE": self.ldap_user_search_base,
            "LDAP_REQUIRED_GROUP_DN": self.ldap_required_group_dn,
            "LOCAL_USERS_FILE": str(self.path(self.local_users_file)),
            "PASSWORD_LOGIN": self.password_login,
            "OIDC_ENABLED": self.oidc_active,
            "OIDC_ISSUER": self.oidc_issuer,
            "OIDC_CLIENT_ID": self.oidc_client_id,
            "OIDC_CLIENT_SECRET": self.oidc_secret() if self.oidc_active else None,
            "OIDC_REDIRECT_URI": self.oidc_redirect_uri,
            "OIDC_SCOPES": self.oidc_scopes,
            "OIDC_USERNAME_CLAIM": self.oidc_username_claim,
            "OIDC_GROUPS_CLAIM": self.oidc_groups_claim,
            "OIDC_REQUIRED_GROUP": self.oidc_required_group,
            "OIDC_CA_FILE": str(self.path(self.oidc_ca_file)) if self.oidc_ca_file else None,
            "OIDC_DISPLAY_NAME": self.oidc_display_name,
            "ROLE_ADMIN_GROUP": self.role_admin_group,
            "ROLE_OPERATOR_GROUP": self.role_operator_group,
            "ROLE_VIEWER_GROUP": self.role_viewer_group,
            "DEFAULT_ROLE": self.default_role,
            "SERVICE_CONTROL_ENABLED": self.service_control_enabled,
            "FRONTEND_DIR": str(self.path(self.frontend_dir)),
        }


def load_settings() -> Settings:
    """The settings from the environment and settings.json; RuntimeError with what is missing or wrong."""
    try:
        return Settings()  # type: ignore[call-arg]  # required fields come from the environment
    except ValidationError as e:
        problems = [f"{'_'.join(str(part) for part in error['loc']).upper()}: {error['msg']}" for error in e.errors()]
        raise RuntimeError("Invalid configuration (see .env.example): " + "; ".join(problems)) from None


def current_settings() -> Settings:
    return current_app.extensions["settings"]
