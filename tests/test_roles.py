"""Roles (viewer / operator / admin), the audit log, service control and the settings page."""

import json
from unittest import mock

import pytest

from app.auth.roles import resolve_role
from app.libs.auth.ldap_backend import LDAPAuthBackend
from app.models.audit import AuditEvent
from tests.conftest import PASSWORD, ApiClient


@pytest.mark.parametrize("path", ["/api/v1/settings", "/api/v1/audit"])
def test_system_pages_are_for_admins(api_as, path):
    assert api_as("viewer").get(path).status_code == 403
    assert api_as("operator").get(path).status_code == 403
    assert api_as("admin").get(path).status_code == 200


@pytest.mark.parametrize("role", ["viewer", "operator", "admin"])
def test_the_session_says_the_role(api_as, role):
    assert api_as(role).get("/api/v1/session").get_json()["role"] == role


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


def test_user_without_role_cannot_sign_in(app):
    app.config["DEFAULT_ROLE"] = "none"
    with open(app.config["LOCAL_USERS_FILE"]) as f:
        users = json.load(f)
    users["norole"] = {"password_hash": users["admin"]["password_hash"]}
    with open(app.config["LOCAL_USERS_FILE"], "w") as f:
        json.dump(users, f)
    api = ApiClient(app)
    assert api.post("/api/v1/session", json={"username": "norole", "password": PASSWORD}).status_code == 401
    assert api.get("/api/v1/session").get_json()["authenticated"] is False
    assert AuditEvent.query.one().detail == "no role"


def test_actions_are_audited(api, ca_client, step_db):
    from app.stepca.client import CAError

    step_db.add_cert(42)
    api.post("/api/v1/certificates/42/revoke", json={"reason_code": 4})
    ca_client.delete_provisioner.side_effect = CAError("in use")
    api.delete("/api/v1/provisioners/old")
    events = [(e.user, e.role, e.action, e.target, e.success) for e in AuditEvent.query.order_by(AuditEvent.id)]
    assert events == [
        ("admin", "admin", "login", "admin", True),
        ("admin", "admin", "revoke", "42", True),
        ("admin", "admin", "delete_provisioner", "old", False),
    ]
    assert "delete_provisioner" in api.get("/api/v1/audit").get_json()["actions"]


class TestServiceControl:
    def test_disabled_by_default(self, api):
        assert api.post("/api/v1/service", json={"action": "status"}).status_code == 404
        assert api.get("/api/v1/session").get_json()["service_control"] is False

    def test_enabled_without_sudo_returns_an_error(self, app, api):
        app.config["SERVICE_CONTROL_ENABLED"] = True
        with mock.patch("subprocess.check_output", side_effect=FileNotFoundError("sudo")):
            response = api.post("/api/v1/service", json={"action": "restart"})
        assert response.status_code == 500
        assert response.get_json()["success"] is False and "Cannot run the service control script" in response.get_json()["error"]
        assert AuditEvent.query.filter_by(action="service_restart").one().success is False

    def test_unknown_actions_are_refused(self, app, api):
        app.config["SERVICE_CONTROL_ENABLED"] = True
        with mock.patch("subprocess.check_output") as run:
            assert api.post("/api/v1/service", json={"action": "rm -rf"}).status_code == 422
        run.assert_not_called()


def settings_values(api):
    return {item["label"]: item["value"] for section in api.get("/api/v1/settings").get_json()["sections"] for item in section["items"]}


def test_settings_never_show_the_database_password(api):
    values = settings_values(api)
    assert values["Host"] == "unused" and values["Password"] == "set"


def test_settings_mask_the_app_database_password(app, api):
    app.config["SQLALCHEMY_BINDS"] = {"app": "postgresql+psycopg://stepca_web:s3cret@db.test/stepca_web"}
    assert settings_values(api)["App database"] == "postgresql+psycopg://stepca_web:***@db.test/stepca_web"


def test_app_identity_type_from_the_admin_list_and_the_db(app, step_db):
    """The Admin API gives admins a provisioner id; provisioner names come from step-ca's database."""
    from app.services import provisioners

    step_db.add_provisioner("prov-web", "stepca-web")
    fake = mock.MagicMock(subject="stepca-web", provisioner_name="stepca-web")
    fake.list_admins.return_value = {
        "admins": [
            {"subject": "step", "provisioner_id": "prov-admin-jwk", "type": 2},
            {"subject": "stepca-web", "provisioner_id": "prov-web", "type": 1},
        ]
    }
    fake.identity_cache = (float("-inf"), None)
    app.extensions["stepca"] = fake
    assert provisioners.identity_type() == "ADMIN"
    fake.subject, fake.provisioner_name = "step", "Admin JWK"
    assert provisioners.identity_type() == "ADMIN", "cached"
    fake.identity_cache = (float("-inf"), None)
    assert provisioners.identity_type() == "SUPER_ADMIN"


def test_admin_creation_date_falls_back_to_the_database(api, ca_client, step_db):
    """Admins added since the CA started have no created_at in the Admin API's answer."""
    step_db.add_admin("adm-1", "step", "prov-admin-jwk")
    (admin,) = api.get("/api/v1/admins").get_json()["admins"]
    assert admin["created_at"].startswith("2026-10-29T12:30:08")
