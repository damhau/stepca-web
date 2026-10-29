import logging
import ssl
from unittest import mock

import pytest
from ldap3 import AUTO_BIND_TLS_BEFORE_BIND
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError

from app import create_app
from app.auth.factory import get_auth_backend
from app.libs.auth.ldap_backend import LDAPAuthBackend, ldap_transport
from config import Config
from tests.conftest import PASSWORD, csrf_token


def test_app_refuses_to_start_without_secret_key():
    class NoSecret(Config):
        SECRET_KEY = None

    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app(NoSecret)


def test_login_starts_a_fresh_session(app):
    client = app.test_client()
    token = csrf_token(client)
    with client.session_transaction() as session:
        session["planted"] = "by an attacker"
    client.post("/auth/login", data={"username": "admin", "password": PASSWORD, "csrf_token": token})
    with client.session_transaction() as session:
        assert session["user_id"] == "admin"
        assert "planted" not in session
        assert session.permanent


def test_logout_clears_the_session(client):
    client.get("/auth/logout")
    with client.session_transaction() as session:
        assert dict(session) == {}
    assert client.get("/").status_code == 302


@pytest.mark.parametrize("backend", ["oidc", "saml", "radius"])
def test_unimplemented_backends_are_refused(backend):
    with pytest.raises(ValueError, match="ldap"):
        get_auth_backend({"AUTH_BACKEND": backend})


def test_no_required_ldap_group_by_default(monkeypatch):
    """It used to default to LDAP_BASE_DN, which no user is a member of: every LDAP login was refused."""
    monkeypatch.setenv("LDAP_BASE_DN", "dc=corp,dc=test")
    monkeypatch.delenv("LDAP_REQUIRED_GROUP_DN", raising=False)
    import importlib

    import config

    try:
        assert importlib.reload(config).Config.LDAP_REQUIRED_GROUP_DN is None
    finally:
        monkeypatch.undo()
        importlib.reload(config)


LDAP_CONFIG = {"LDAP_URL": "ldap://ldap.test", "LDAP_DOMAIN": "corp.test", "LDAP_USER_SEARCH_FILTER": "(uid={username})"}


def ldap_entry(groups):
    entry = mock.MagicMock(entry_dn="uid=bob,ou=people,dc=corp,dc=test")
    entry.entry_attributes_as_dict = {"memberOf": groups}
    return entry


class TestLDAP:
    @pytest.fixture
    def ldap(self):
        backend = LDAPAuthBackend(LDAP_CONFIG)
        connection = mock.MagicMock(bound=True, entries=[])
        with mock.patch("app.libs.auth.ldap_backend.Connection", return_value=connection) as connect:
            yield backend, connection, connect

    def test_server_certificate_is_always_verified(self, tmp_path):
        ca_file = tmp_path / "ca.crt"
        ca_file.write_text("unused")
        assert LDAPAuthBackend(LDAP_CONFIG).tls.validate == ssl.CERT_REQUIRED
        backend = LDAPAuthBackend({**LDAP_CONFIG, "LDAP_URL": "ldaps://ldap.test", "LDAP_CA_FILE": str(ca_file)})
        assert backend.tls.validate == ssl.CERT_REQUIRED
        assert backend.tls.ca_certs_file == str(ca_file)

    def test_start_tls_happens_before_the_bind(self, ldap):
        _, _, connect = ldap
        LDAPAuthBackend({**LDAP_CONFIG, "LDAP_START_TLS": True}).authenticate("bob", "secret")
        assert connect.call_args.kwargs["auto_bind"] == AUTO_BIND_TLS_BEFORE_BIND

    def test_binds_with_the_user_principal_name_by_default(self, ldap):
        backend, _, connect = ldap
        backend.authenticate("bob", "secret")
        assert connect.call_args.kwargs["user"] == "bob@corp.test"
        assert connect.call_args.kwargs["auto_bind"] is True

    def test_bind_dn_template_escapes_the_username(self, ldap):
        _, _, connect = ldap
        backend = LDAPAuthBackend({**LDAP_CONFIG, "LDAP_BIND_DN": "uid={username},ou=people,dc=corp,dc=test"})
        backend.authenticate("bob,ou=admins", "secret")
        assert connect.call_args.kwargs["user"] == r"uid=bob\,ou\=admins,ou=people,dc=corp,dc=test"

    def test_wrong_password_is_not_an_error(self, ldap, caplog):
        backend, _, connect = ldap
        connect.side_effect = LDAPBindError("invalidCredentials")
        assert backend.authenticate("bob", "wrong") is None
        assert not [r for r in caplog.records if r.levelno >= logging.ERROR]

    def test_tls_failure_is_logged(self, ldap, caplog):
        backend, _, connect = ldap
        connect.side_effect = LDAPSocketOpenError("certificate verify failed")
        assert backend.authenticate("bob", "secret") is None
        assert "certificate verify failed" in caplog.text

    def test_returns_the_groups(self, ldap):
        backend, connection, _ = ldap
        connection.entries = [ldap_entry(["CN=PKI-Admins,DC=corp,DC=test"])]
        user = backend.authenticate("bob", "secret")
        assert user == {"id": "bob", "dn": "uid=bob,ou=people,dc=corp,dc=test", "groups": ["CN=PKI-Admins,DC=corp,DC=test"]}

    def test_required_group_ignores_case(self, ldap):
        _, connection, _ = ldap
        connection.entries = [ldap_entry(["CN=PKI-Users,DC=corp,DC=test"])]
        backend = LDAPAuthBackend({**LDAP_CONFIG, "LDAP_REQUIRED_GROUP_DN": "cn=pki-users,dc=corp,dc=test"})
        assert backend.authenticate("bob", "secret") is not None
        backend = LDAPAuthBackend({**LDAP_CONFIG, "LDAP_REQUIRED_GROUP_DN": "cn=other,dc=corp,dc=test"})
        assert backend.authenticate("bob", "secret") is None

    def test_username_is_escaped_in_the_search_filter(self, ldap):
        backend, connection, _ = ldap
        backend.authenticate("bob*)(uid=*", "secret")
        search_filter = connection.search.call_args.kwargs["search_filter"]
        assert search_filter == r"(uid=bob\2a\29\28uid=\2a)"

    @pytest.mark.parametrize("password", ["", None])
    def test_empty_password_never_binds(self, ldap, password):
        backend, _, connect = ldap
        assert backend.authenticate("bob", password) is None
        connect.assert_not_called()


def test_app_refuses_to_start_without_ca_url(monkeypatch):
    import app as app_package

    monkeypatch.setattr(app_package, "CA_URL", None)
    with pytest.raises(RuntimeError, match="CA_URL"):
        create_app(Config)


@pytest.mark.parametrize(
    "url, start_tls, transport",
    [("ldaps://dc.corp", False, "ldaps"), ("LDAPS://dc.corp:636", True, "ldaps"), ("ldap://dc.corp", True, "starttls"), ("ldap://dc.corp", False, "cleartext")],
)
def test_ldap_transport(url, start_tls, transport):
    assert ldap_transport({"LDAP_URL": url, "LDAP_START_TLS": start_tls}) == transport


class LDAPConfig(Config):
    TESTING = True  # no version check against the CA in the background
    AUTH_BACKEND = "ldap"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_BINDS = {"app": "sqlite://"}


def test_cleartext_ldap_is_allowed_with_a_warning(caplog):
    class Cleartext(LDAPConfig):
        LDAP_URL = "ldap://dc.corp"
        LDAP_START_TLS = False

    create_app(Cleartext)
    assert "cleartext" in caplog.text


def test_missing_ldap_ca_file_stops_the_app():
    class MissingCA(LDAPConfig):
        LDAP_URL = "ldaps://dc.corp"
        LDAP_CA_FILE = "/nonexistent/ca.crt"

    with pytest.raises(RuntimeError, match="LDAP_CA_FILE"):
        create_app(MissingCA)


def test_config_page_warns_about_cleartext_ldap(app, client):
    app.config.update(AUTH_BACKEND="ldap", LDAP_URL="ldap://dc.corp", LDAP_START_TLS=False)
    html = client.get("/system/config").get_data(as_text=True)
    assert "alert-warning" in html and "cleartext" in html
    app.config.update(LDAP_URL="ldaps://dc.corp")
    html = client.get("/system/config").get_data(as_text=True)
    assert "alert-warning" not in html and "LDAPS, server certificate verified" in html
