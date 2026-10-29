from unittest import mock

import pytest

from app import create_app
from app.auth.factory import get_auth_backend
from app.libs.auth.ldap_backend import LDAPAuthBackend
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


class TestLDAP:
    @pytest.fixture
    def ldap(self):
        backend = LDAPAuthBackend(
            {"LDAP_URL": "ldap://ldap.test", "LDAP_DOMAIN": "corp.test", "LDAP_USER_SEARCH_FILTER": "(uid={username})"}
        )
        connection = mock.MagicMock(bound=True, entries=[])
        with mock.patch("app.libs.auth.ldap_backend.Connection", return_value=connection) as connect:
            yield backend, connection, connect

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
