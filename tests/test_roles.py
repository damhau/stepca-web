"""Roles (viewer / operator / admin), the audit log, expiry, service control and the config page."""

import datetime
from unittest import mock

import pytest

from app.auth.roles import resolve_role
from app.libs.auth.ldap_backend import LDAPAuthBackend
from app.models.audit import AuditEvent
from tests.conftest import csrf_token

ADMIN_POSTS = [
    "/step/provisioners",
    "/step/provisioner/Admin%20JWK/delete",
    "/step/admins",
    "/step/admin/adm-1/update",
    "/step/admin/adm-1/delete",
]
OPERATOR_POSTS = ["/x509/sign", "/x509/revoke"]


def test_viewer_cannot_change_anything(login_as, ca_client):
    viewer = login_as("viewer")
    token = csrf_token(viewer)
    for path in ADMIN_POSTS + OPERATOR_POSTS:
        assert viewer.post(path, data={"csrf_token": token, "type": "1", "cert_id": "1"}).status_code == 403, path
    assert not ca_client.method_calls


def test_operator_can_sign_and_revoke_only(login_as, ca_client, step_db):
    step_db.add_cert(42)
    operator = login_as("operator")
    token = csrf_token(operator)
    for path in ADMIN_POSTS:
        assert operator.post(path, data={"csrf_token": token, "type": "1"}).status_code == 403, path
    assert operator.post("/x509/revoke", data={"csrf_token": token, "cert_id": "42", "passphrase": "pw"}).status_code == 302
    ca_client.revoke.assert_called_once()


@pytest.mark.parametrize("path", ["/system/config", "/system/audit"])
def test_system_pages_are_for_admins(login_as, path):
    assert login_as("viewer").get(path).status_code == 403
    assert login_as("operator").get(path).status_code == 403
    assert login_as("admin").get(path).status_code == 200


def test_controls_follow_the_role(login_as, step_db):
    step_db.add_cert(42)
    pages = {
        role: (login_as(role).get("/x509/active").get_data(as_text=True), login_as(role).get("/step/provisioners").get_data(as_text=True))
        for role in ("viewer", "operator", "admin")
    }
    assert "Submit CSR" not in pages["viewer"][0] and 'data-target="#revokeModal"' not in pages["viewer"][0]
    assert "Submit CSR" in pages["operator"][0] and 'data-target="#revokeModal"' in pages["operator"][0]
    assert "Add Provisioner" not in pages["operator"][1]
    assert "Add Provisioner" in pages["admin"][1]
    assert "Audit Log" in pages["admin"][1] and "Audit Log" not in pages["operator"][1]


class TestResolveRole:
    config = {
        "ROLE_ADMIN_GROUP": "CN=PKI-Admins,DC=corp",
        "ROLE_OPERATOR_GROUP": "CN=PKI-Ops,DC=corp",
        "ROLE_VIEWER_GROUP": None,
        "DEFAULT_ROLE": "viewer",
    }

    def test_explicit_role_wins(self):
        assert resolve_role({"role": "operator", "groups": ["CN=PKI-Admins,DC=corp"]}, self.config) == "operator"

    def test_highest_group_wins_case_insensitively(self):
        assert resolve_role({"groups": ["cn=pki-ops,dc=corp", "cn=pki-admins,dc=corp"]}, self.config) == "admin"
        assert resolve_role({"groups": ["CN=PKI-Ops,DC=corp"]}, self.config) == "operator"

    def test_default_role(self):
        assert resolve_role({"groups": ["CN=Other,DC=corp"]}, self.config) == "viewer"
        assert resolve_role({"groups": []}, {**self.config, "DEFAULT_ROLE": "none"}) is None

    def test_ldap_backend_returns_the_groups(self):
        entry = mock.MagicMock(entry_dn="uid=bob,dc=corp", entry_attributes_as_dict={"memberOf": ["CN=PKI-Ops,DC=corp"]})
        connection = mock.MagicMock(bound=True, entries=[entry])
        with mock.patch("app.libs.auth.ldap_backend.Connection", return_value=connection):
            user = LDAPAuthBackend({"LDAP_DOMAIN": "corp"}).authenticate("bob", "secret")
        assert resolve_role(user, self.config) == "operator"


def test_user_without_role_cannot_log_in(app):
    app.config["DEFAULT_ROLE"] = "none"
    client = app.test_client()
    import json

    users = json.load(open(app.config["LOCAL_USERS_FILE"]))
    users["norole"] = {"password_hash": users["admin"]["password_hash"]}
    json.dump(users, open(app.config["LOCAL_USERS_FILE"], "w"))
    response = client.post("/auth/login", data={"username": "norole", "password": "testpw", "csrf_token": csrf_token(client)})
    assert response.status_code == 200
    assert client.get("/").status_code == 302


def test_actions_are_audited(client, ca_client, step_db):
    step_db.add_cert(42)
    token = csrf_token(client)
    client.post("/x509/revoke", data={"csrf_token": token, "cert_id": "42", "passphrase": "pw", "reason": "4"})
    ca_client.delete_provisioner.return_value = False
    client.post("/step/provisioner/old/delete", data={"csrf_token": token})
    events = [(e.user, e.role, e.action, e.target, e.success) for e in AuditEvent.query.order_by(AuditEvent.id)]
    assert events == [
        ("admin", "admin", "login", "admin", True),
        ("admin", "admin", "revoke", "42", True),
        ("admin", "admin", "delete_provisioner", "old", False),
    ]
    assert "delete_provisioner" in client.get("/system/audit").get_data(as_text=True)


def test_failed_logins_are_audited(app):
    client = app.test_client()
    client.post("/auth/login", data={"username": "admin", "password": "wrong", "csrf_token": csrf_token(client)})
    event = AuditEvent.query.one()
    assert (event.user, event.action, event.success, event.detail) == ("admin", "login", False, "invalid credentials")


def test_expiring_certificates(client, step_db):
    now = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)
    step_db.add_cert(1, "in-5-days.test", days_valid=6, not_before=now)
    step_db.add_cert(2, "in-20-days.test", days_valid=21, not_before=now)
    step_db.add_cert(3, "in-60-days.test", days_valid=61, not_before=now)
    step_db.add_cert(4, "revoked.test", days_valid=3, not_before=now)
    step_db.add_revocation(4)
    html = client.get("/x509/expiring?days=30").get_data(as_text=True)
    assert "in-5-days.test" in html and "in-20-days.test" in html
    assert "in-60-days.test" not in html and "revoked.test" not in html
    assert html.index("in-5-days.test") < html.index("in-20-days.test")
    assert "in-20-days.test" not in client.get("/x509/expiring?days=7").get_data(as_text=True)
    assert "<h3>2</h3>\n\n              <p>Expiring within 30 days</p>" in client.get("/").get_data(as_text=True)


class TestServiceControl:
    def test_disabled_by_default(self, client):
        assert client.get("/step/service").status_code == 404
        assert client.post("/step/service/stop", data={"csrf_token": csrf_token(client)}).status_code == 404
        assert "/step/service" not in client.get("/").get_data(as_text=True)

    def test_enabled_without_sudo_returns_an_error(self, app, client):
        app.config["SERVICE_CONTROL_ENABLED"] = True
        assert client.get("/step/service").status_code == 200
        with mock.patch("subprocess.check_output", side_effect=FileNotFoundError("sudo")):
            response = client.post("/step/service/restart", headers={"X-CSRFToken": csrf_token(client)})
        assert response.status_code == 500
        assert response.get_json()["success"] is False
        assert AuditEvent.query.filter_by(action="service_restart").one().success is False


def test_config_page_never_shows_the_db_password(client):
    html = client.get("/system/config").get_data(as_text=True)
    assert "unused" in html  # DATABASE_HOST from the test environment
    assert "Password" in html and "set" in html
    assert "test-secret" not in html
    assert "<form" not in html.split("Configuration")[-1] or 'name="db_password"' not in html
