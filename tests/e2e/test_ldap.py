"""LDAP login against a real OpenLDAP, over LDAPS, StartTLS and cleartext. Run with tests/e2e/run.sh."""

import os

import pytest

from app.auth.roles import resolve_role
from app.libs.auth.ldap_backend import LDAPAuthBackend

LDAP_URL = os.environ.get("E2E_LDAP_URL")
LDAPS_URL = os.environ.get("E2E_LDAPS_URL")
CA = os.environ.get("E2E_LDAP_CA")
ADMINS = "cn=pki-admins,ou=groups,dc=example,dc=org"
# OpenLDAP binds with a DN, not a user principal name like Active Directory
DIRECTORY = {
    "LDAP_BASE_DN": "dc=example,dc=org",
    "LDAP_USER_SEARCH_BASE": "dc=example,dc=org",
    "LDAP_BIND_DN": "uid={username},ou=people,dc=example,dc=org",
    "LDAP_USER_SEARCH_FILTER": "(uid={username})",
}
ROLES = {"ROLE_ADMIN_GROUP": ADMINS.upper(), "DEFAULT_ROLE": "viewer"}

pytestmark = pytest.mark.skipif(not LDAP_URL, reason="needs the stack started by tests/e2e/run.sh")


def backend(**config):
    return LDAPAuthBackend({**DIRECTORY, **config})


@pytest.mark.parametrize(
    "config",
    [
        pytest.param({"LDAP_URL": LDAPS_URL, "LDAP_CA_FILE": CA}, id="ldaps"),
        pytest.param({"LDAP_URL": LDAP_URL, "LDAP_START_TLS": True, "LDAP_CA_FILE": CA}, id="starttls"),
        pytest.param({"LDAP_URL": LDAP_URL}, id="cleartext"),
    ],
)
def test_login_gets_the_role_of_the_user_groups(config):
    alice = backend(**config).authenticate("alice", "alicepw")
    assert alice["groups"] == [ADMINS], "memberOf is returned although OpenLDAP treats it as operational"
    assert resolve_role(alice, ROLES) == "admin"
    assert resolve_role(backend(**config).authenticate("bob", "bobpw"), ROLES) == "viewer"
    assert backend(**config).authenticate("alice", "wrong") is None


@pytest.mark.parametrize(
    "config",
    [
        pytest.param({"LDAP_URL": LDAPS_URL}, id="ldaps-unknown-ca"),
        pytest.param({"LDAP_URL": LDAP_URL, "LDAP_START_TLS": True}, id="starttls-unknown-ca"),
        pytest.param({"LDAP_URL": (LDAPS_URL or "").replace("localhost", "127.0.0.1"), "LDAP_CA_FILE": CA}, id="ldaps-wrong-name"),
    ],
)
def test_unverified_server_is_refused(config, caplog):
    """The test CA is not a system CA, and 127.0.0.1 is not a name in the server certificate."""
    assert backend(**config).authenticate("alice", "alicepw") is None
    assert "Cannot connect to the LDAP server" in caplog.text
