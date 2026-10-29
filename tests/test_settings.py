"""Settings: environment first, then settings.json, then the defaults; files in the data directory."""

import json

import pytest

from app.settings import Settings, load_settings

REQUIRED = {"SECRET_KEY": "s", "CA_URL": "https://ca.test", "DATABASE_HOST": "db.test"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    """A clean environment whose data directory is tmp_path."""
    for name in list(__import__("os").environ):
        if name.split("_")[0] in {"SECRET", "CA", "DATABASE", "LDAP", "ROLE", "DEFAULT", "AUTH", "DATA", "APP", "SQLALCHEMY", "SESSION", "LOCAL", "SERVICE", "TRUSTED", "LOGIN", "RATELIMIT", "LOG", "TESTING"}:
            monkeypatch.delenv(name)
    monkeypatch.setenv("DATA_DIR", str(tmp_path))

    def set_env(**values):
        for name, value in values.items():
            monkeypatch.setenv(name, value)

    return set_env


def test_missing_settings_are_named(env):
    with pytest.raises(RuntimeError, match="SECRET_KEY.*CA_URL|CA_URL.*SECRET_KEY") as error:
        load_settings()
    assert "DATABASE_HOST" in str(error.value)


def test_environment_comes_before_settings_json(env, tmp_path):
    (tmp_path / "settings.json").write_text(json.dumps({
        "database": {"host": "from-json", "port": 6543, "user": "web"},
        "ca": {"url": "https://ca.json", "admin_subject": "stepca-web"},
        "ldap": {"ldap_required_group_dn": "cn=pki,dc=corp", "url": "ldaps://dc.corp"},
        "roles": {"admin_group": "cn=admins,dc=corp", "default": "none"},
    }))
    env(SECRET_KEY="s", DATABASE_HOST="from-env")
    settings = load_settings()
    assert settings.database_host == "from-env"
    assert settings.database_port == 6543 and settings.ca_url == "https://ca.json" and settings.ca_admin_subject == "stepca-web"
    # Keys older than this module
    assert settings.ldap_required_group_dn == "cn=pki,dc=corp"
    assert settings.role_admin_group == "cn=admins,dc=corp" and settings.default_role == "none"


def test_files_live_in_the_data_directory(env, tmp_path):
    env(**REQUIRED, LOCAL_USERS_FILE="users.json", CA_ADMIN_PASSWORD_FILE="/run/secrets/pw")
    settings = load_settings()
    assert settings.path(settings.local_users_file) == tmp_path / "users.json"
    assert settings.path(settings.ca_admin_password_file).as_posix() == "/run/secrets/pw"
    assert settings.app_database == f"sqlite:///{(tmp_path / 'stepca-web.db').resolve()}"
    config = settings.flask_config()
    assert config["LOCAL_USERS_FILE"] == str(tmp_path / "users.json")


def test_database_password_is_escaped(env):
    env(**REQUIRED, DATABASE_USER="web", DATABASE_PASSWORD="p@ss:w/rd", DATABASE_NAME="step_ca_db")
    uri = load_settings().step_database_uri
    assert uri == "postgresql+psycopg://web:p%40ss%3Aw%2Frd@db.test:5432/step_ca_db"


@pytest.mark.parametrize("value, expected", [("true", True), ("True", True), ("1", True), ("false", False), ("no", False)])
def test_booleans(env, value, expected):
    env(**REQUIRED, LDAP_START_TLS=value, SERVICE_CONTROL_ENABLED=value)
    settings = load_settings()
    assert settings.ldap_start_tls is expected and settings.service_control_enabled is expected


@pytest.mark.parametrize("name, value", [("DEFAULT_ROLE", "superuser"), ("DATABASE_PORT", "not-a-port"), ("AUTH_BACKEND", "oidc")])
def test_invalid_values_are_explained(env, name, value):
    env(**REQUIRED, **{name: value})
    with pytest.raises(RuntimeError, match=name):
        load_settings()


def test_secrets_are_not_printed(env):
    env(**REQUIRED, DATABASE_PASSWORD="hunter2")
    settings = load_settings()
    assert "hunter2" not in repr(settings)
    assert isinstance(settings, Settings)


def test_empty_values_are_unset(env, tmp_path):
    """CA_ADMIN_PASSWORD_FILE= in .env must not become the data directory itself."""
    env(**REQUIRED, CA_ADMIN_PASSWORD_FILE="", CA_ROOT="", LDAP_CA_FILE="")
    (tmp_path / "settings.json").write_text(json.dumps({"ldap": {"bind_dn": ""}}))
    settings = load_settings()
    assert settings.ca_admin_password_file is None and settings.ca_root is None and settings.ldap_ca_file is None
    assert settings.ldap_bind_dn is None


@pytest.mark.parametrize("source", ["env", "json"])
def test_empty_secret_key_is_missing(env, tmp_path, source):
    env(CA_URL="https://ca.test", DATABASE_HOST="db.test", **({"SECRET_KEY": ""} if source == "env" else {}))
    if source == "json":
        (tmp_path / "settings.json").write_text(json.dumps({"secret_key": ""}))
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        load_settings()
