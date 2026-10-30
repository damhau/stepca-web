"""The JSON API: sessions, roles, CSRF, and each resource against rows in step-ca's format."""

import csv
import datetime
import io
import json
import pathlib

import pytest
import requests
from cryptography import x509

from app.models.audit import AuditEvent
from app.stepca.client import CAError, SignError
from tests.conftest import ADMIN_JWK, PASSWORD, ApiClient, make_cert
from tests.test_ca_status import ca_up  # noqa: F401  fixture
from tests.test_signing import make_csr

SERIAL = 119960802063269571811733802872440608485


class TestSession:
    def test_signed_out(self, app):
        session = app.test_client().get("/api/v1/session").get_json()
        assert session["authenticated"] is False and session["role"] is None
        assert session["csrf_token"]

    def test_sign_in_and_out(self, app, ca_client):
        api = ApiClient(app)
        response = api.post("/api/v1/session", json={"username": "operator", "password": PASSWORD})
        assert response.status_code == 200
        assert response.get_json() | {"csrf_token": "x"} == {
            "authenticated": True, "user": "operator", "role": "operator", "csrf_token": "x", "service_control": False,
            "authority": {"name": "ca.test", "environment": None, "url": "https://ca.test:9000"},
        }
        api.token = response.get_json()["csrf_token"]
        assert api.get("/api/v1/dashboard").status_code == 200
        assert api.delete("/api/v1/session").get_json()["authenticated"] is False
        assert api.get("/api/v1/dashboard").status_code == 401

    def test_wrong_password(self, app):
        api = ApiClient(app)
        response = api.post("/api/v1/session", json={"username": "admin", "password": "wrong"})
        assert response.status_code == 401
        assert response.get_json() == {"error": "Invalid username or password."}
        event = AuditEvent.query.one()
        assert (event.user, event.action, event.success) == ("admin", "login", False)

    def test_failed_sign_ins_are_rate_limited(self, app):
        app.config["RATELIMIT_ENABLED"] = True
        api = ApiClient(app)
        statuses = [api.post("/api/v1/session", json={"username": "admin", "password": "wrong"}).status_code for _ in range(11)]
        assert statuses[-1] == 429
        assert api.post("/api/v1/session", json={"username": "admin", "password": "wrong"}).get_json()["error"].startswith("Too many")

    def test_session_cookie_is_http_only(self, app):
        api = ApiClient(app)
        response = api.post("/api/v1/session", json={"username": "admin", "password": PASSWORD})
        cookie = response.headers["Set-Cookie"]
        assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_invalid_requests_do_not_echo_what_was_sent(app):
    api = ApiClient(app)
    response = api.post("/api/v1/session", json={"username": "admin"})
    assert response.status_code == 422
    (problem,) = response.get_json()
    assert problem["loc"] == ["password"] and "input" not in problem
    response = api.post("/api/v1/session", json={"username": "admin", "password": 12345678})
    assert "12345678" not in response.get_data(as_text=True)


@pytest.mark.parametrize(
    "method, path, body",
    [
        ("POST", "/api/v1/certificates", {}),
        ("POST", "/api/v1/certificates/1/revoke", {"reason_code": 0}),
        ("PUT", "/api/v1/provisioners/x", {}),
        ("PATCH", "/api/v1/admins/x", {"type": "ADMIN"}),
        ("DELETE", "/api/v1/admins/x", None),
        ("DELETE", "/api/v1/session", None),
    ],
)
def test_writes_need_the_csrf_token(api, method, path, body):
    response = api.client.open(path, method=method, json=body)
    assert response.status_code == 400
    assert "CSRF token is missing" in response.get_json()["error"]


class TestRoles:
    VIEWER_REFUSED = [
        ("POST", "/api/v1/certificates", {"csr_pem": "x", "provisioner": "p", "password": "p"}),
        ("POST", "/api/v1/certificates/1/revoke", {"reason_code": 0}),
        ("POST", "/api/v1/csr/preview", {"csr_pem": "x"}),
    ]
    OPERATOR_REFUSED = [
        ("POST", "/api/v1/provisioners", {"name": "x", "type": "ACME"}),
        ("PUT", "/api/v1/provisioners/x", {}),
        ("DELETE", "/api/v1/provisioners/x", None),
        ("POST", "/api/v1/admins", {"subject": "x", "provisioner": "p", "type": "ADMIN"}),
        ("PATCH", "/api/v1/admins/x", {"type": "ADMIN"}),
        ("DELETE", "/api/v1/admins/x", None),
        ("GET", "/api/v1/settings", None),
        ("GET", "/api/v1/audit", None),
        ("POST", "/api/v1/service", {"action": "status"}),
    ]

    def test_viewers_only_read(self, api_as, ca_client):
        viewer = api_as("viewer")
        for method, path, body in self.VIEWER_REFUSED + self.OPERATOR_REFUSED:
            response = viewer._send(method, path, json=body)
            assert response.status_code == 403, (method, path)
            assert response.get_json() == {"error": "Your role does not allow this."}
        assert viewer.get("/api/v1/certificates").status_code == 200
        ca_client.revoke.assert_not_called()

    def test_operators_sign_and_revoke_only(self, api_as, ca_client):
        operator = api_as("operator")
        for method, path, body in self.OPERATOR_REFUSED:
            assert operator._send(method, path, json=body).status_code == 403, (method, path)
        assert operator.post("/api/v1/csr/preview", json={"csr_pem": make_csr()}).status_code == 200
        ca_client.create_provisioner_acme.assert_not_called()


class TestCertificates:
    def test_list_pages_and_filters(self, api, step_db):
        for serial in range(1, 8):
            step_db.add_cert(serial, f"host{serial}.test")
        step_db.add_revocation(7)
        body = api.get("/api/v1/certificates?status=valid&per_page=4&page=2&sort=serial&order=asc").get_json()
        assert (body["total"], body["page"], body["per_page"], body["pending"]) == (6, 2, 4, 0)
        assert [item["serial"] for item in body["items"]] == ["5", "6"]
        item = body["items"][0]
        assert item["subject"] == "CN=host5.test" and item["provisioner_name"] == "Admin JWK" and item["status"] == "valid"
        assert item["not_after"].endswith("Z") or "+00:00" in item["not_after"]
        revoked = api.get("/api/v1/certificates?status=revoked").get_json()["items"]
        assert [(item["serial"], item["revocation_reason_code"]) for item in revoked] == [("7", 1)]
        assert api.get("/api/v1/certificates?q=host3").get_json()["total"] == 1

    def test_bad_filters_are_refused(self, api):
        assert api.get("/api/v1/certificates?status=lost").status_code == 422
        assert api.get("/api/v1/certificates?per_page=100000").status_code == 422

    def test_csv_export_has_every_row_and_no_formulas(self, api, step_db):
        step_db.add_cert(1, "=cmd|' /C calc'!A0.test")
        step_db.add_cert(2, "plain.test")
        response = api.get("/api/v1/certificates?format=csv&per_page=1")
        assert response.headers["Content-Type"].startswith("text/csv")
        rows = list(csv.DictReader(io.StringIO(response.get_data(as_text=True))))
        assert len(rows) == 2
        subjects = {row["subject"] for row in rows}
        assert "CN=plain.test" in subjects
        assert all(not row["dns_names"].startswith("=") for row in rows)
        assert "'=cmd|' /C calc'!A0.test" in {row["dns_names"] for row in rows}

    def test_detail(self, api, step_db):
        step_db.add_cert(SERIAL, "detail.test")
        body = api.get(f"/api/v1/certificates/{SERIAL}").get_json()
        assert body["certificate"]["serial_hex"] == format(SERIAL, "x")
        assert body["revocation"] is None and body["acme_order_id"] is None
        assert {"name": "Subject alternative names", "value": "DNS:detail.test", "critical": False} in body["extensions"]
        assert x509.load_pem_x509_certificate(body["pem"].encode()).serial_number == SERIAL
        assert api.get("/api/v1/certificates/999").status_code == 404
        assert api.get("/api/v1/certificates/not-a-serial").status_code == 422

    def test_detail_of_a_certificate_issued_since_the_last_check(self, app, api, step_db):
        app.extensions["inventory"].refresh_seconds = 3600
        api.get("/api/v1/certificates")
        step_db.add_cert(SERIAL, "new.test")
        assert api.get(f"/api/v1/certificates/{SERIAL}").status_code == 200

    def test_download(self, api, ca_client, step_db):
        step_db.add_cert(SERIAL, "dl.test")
        pem = api.get(f"/api/v1/certificates/{SERIAL}/download")
        assert pem.headers["Content-Disposition"] == 'attachment; filename="dl.test.pem"'
        assert x509.load_pem_x509_certificate(pem.data).serial_number == SERIAL
        assert x509.load_der_x509_certificate(api.get(f"/api/v1/certificates/{SERIAL}/download?format=der").data).serial_number == SERIAL
        ca_client.intermediates.side_effect = requests.ConnectionError("down")
        response = api.get(f"/api/v1/certificates/{SERIAL}/download?format=chain")
        assert response.status_code == 502 and "could not be reached" in response.get_json()["error"]

    def test_revoke(self, api, ca_client, step_db):
        step_db.add_cert(SERIAL)
        response = api.post(f"/api/v1/certificates/{SERIAL}/revoke", json={"reason_code": 4})
        assert response.status_code == 200
        ca_client.revoke.assert_called_once_with(str(SERIAL), reason_code=4, reason="Superseded")
        assert AuditEvent.query.filter_by(action="revoke").one().target == str(SERIAL)

    def test_revoke_refusals(self, api, ca_client, step_db):
        step_db.add_cert(SERIAL)
        assert api.post(f"/api/v1/certificates/{SERIAL}/revoke", json={"reason_code": 6}).status_code == 422
        assert api.post("/api/v1/certificates/42/revoke", json={"reason_code": 0}).status_code == 404
        ca_client.revoke.side_effect = CAError("certificate already revoked")
        response = api.post(f"/api/v1/certificates/{SERIAL}/revoke", json={"reason_code": 0})
        assert response.status_code == 502
        assert response.get_json()["error"] == "step-ca did not revoke the certificate: certificate already revoked"

    def test_revoked_status_is_seen_at_once(self, app, api, ca_client, step_db):
        """step-ca writes the revocation; the next read must show it, whatever the refresh interval."""
        app.extensions["inventory"].refresh_seconds = 3600
        step_db.add_cert(SERIAL)
        api.get("/api/v1/certificates")
        ca_client.revoke.side_effect = lambda *args, **kwargs: step_db.add_revocation(SERIAL)
        body = api.post(f"/api/v1/certificates/{SERIAL}/revoke", json={"reason_code": 0}).get_json()
        assert body["certificate"]["status"] == "revoked" and body["revocation"]["provisioner_name"] == "Admin JWK"

    def test_sign(self, api, ca_client, step_db):
        def sign(csr, provisioner, password, not_after=None):
            step_db.add_cert(88, "signed.test")
            return x509.load_der_x509_certificate(make_cert(88, "signed.test"))

        ca_client.sign.side_effect = sign
        csr = make_csr("signed.test", sans=("signed.test",))
        response = api.post("/api/v1/certificates", json={"csr_pem": csr, "provisioner": "Admin JWK", "password": "pw", "valid_for": "48h"})
        body = response.get_json()
        assert response.status_code == 201 and body["serial"] == "88"
        assert x509.load_pem_x509_certificate(body["pem"].encode()).serial_number == 88
        # The certificate, then the intermediate the CA reports (the test CA's fake client has none)
        assert body["chain_pem"].startswith(body["pem"])
        ca_client.sign.assert_called_once_with(csr, "Admin JWK", "pw", not_after="48h")
        assert api.get("/api/v1/certificates/88").status_code == 200
        assert AuditEvent.query.filter_by(action="sign").one().target == "88"

    def test_sign_errors(self, api, ca_client):
        ca_client.sign.side_effect = SignError("Wrong password for provisioner 'Admin JWK'")
        response = api.post("/api/v1/certificates", json={"csr_pem": make_csr(), "provisioner": "Admin JWK", "password": "x"})
        assert response.status_code == 422
        assert response.get_json() == {"error": "The certificate was not signed: Wrong password for provisioner 'Admin JWK'."}
        bad = api.post("/api/v1/certificates", json={"csr_pem": make_csr(), "provisioner": "Admin JWK", "password": "x", "valid_for": "two days"})
        assert bad.status_code == 422 and "is not a duration" in bad.get_json()[0]["msg"]

    def test_csr_preview(self, api):
        assert api.post("/api/v1/csr/preview", json={"csr_pem": make_csr()}).get_json()["common_name"] == "web.test"
        assert api.post("/api/v1/csr/preview", json={"csr_pem": "nope"}).status_code == 422

    def test_unmatched_revocations(self, api, step_db):
        step_db.add_cert(12)
        # What the old UI sent for serial 12: the hex of its ASCII
        step_db.add_revocation("3132")
        (row,) = api.get("/api/v1/revocations/unmatched").get_json()["items"]
        assert row["revocation"]["serial"] == "3132" and row["misdirected_serial"] == "12"


def test_dashboard(api, step_db):
    # 20 days left of 100: expiring; a 10-day certificate would be short-lived, and never expiring
    step_db.add_cert(1, "a.test", days_valid=100, not_before=datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=80))
    step_db.add_cert(2, "b.test", days_valid=100)
    step_db.add_acme_issuance(3, "acme.test")
    body = api.get("/api/v1/dashboard").get_json()
    assert (body["total"], body["valid"], body["expiring"], body["revoked"], body["acme_certificates"]) == (2, 2, 1, 0, 1)
    assert body["issued_by_provisioner"] == [{"name": "Admin JWK", "count": 2}]
    assert body["acme_orders_by_status"] == [{"name": "valid", "count": 1}]
    assert [item["serial"] for item in body["expiring_soon"]] == ["1"]


def test_reference(api, step_db):
    body = api.get("/api/v1/reference").get_json()
    assert {"code": 4, "name": "Superseded"} in body["revocation_reasons"]
    assert body["signing_provisioners"] == ["Admin JWK"]
    assert body["acme_challenges"][0] == {"value": "HTTP_01", "label": "http-01"}


def test_search(api, step_db):
    step_db.add_cert(SERIAL, "findme.test")
    ids = step_db.add_acme_issuance(5, "findme-acme.test")
    body = api.get("/api/v1/search?q=findme").get_json()
    assert {item["serial"] for item in body["certificates"]} == {str(SERIAL)}
    assert [order["id"] for order in body["acme_orders"]] == [ids["order"]]
    assert body["truncated"] == []
    assert api.get("/api/v1/search?q=" + format(SERIAL, "x")[:8]).get_json()["certificates"][0]["serial"] == str(SERIAL)


class TestAcme:
    def test_lists(self, api, step_db):
        ids = step_db.add_acme_issuance(5, "acme.test")
        step_db.add_acme_issuance(6, "other.test", prefix="b")
        accounts = api.get("/api/v1/acme/accounts").get_json()
        assert accounts["total"] == 2 and accounts["items"][0]["contact"] == ["ops@example.org"]
        orders = api.get("/api/v1/acme/orders?q=other.test").get_json()
        assert orders["total"] == 1 and orders["items"][0]["certificate_serial"] == "6"
        authorizations = api.get(f"/api/v1/acme/authorizations?q={ids['authz']}").get_json()["items"]
        assert authorizations[0]["order_id"] == ids["order"]
        challenges = api.get("/api/v1/acme/challenges?status=valid").get_json()
        assert challenges["total"] == 2 and {c["type"] for c in challenges["items"]} == {"http-01"}
        certificates = api.get("/api/v1/acme/certificates?per_page=1").get_json()
        assert certificates["total"] == 2 and len(certificates["items"]) == 1 and certificates["items"][0]["serial"] in {"5", "6"}

    def test_drill_down(self, api, step_db):
        ids = step_db.add_acme_issuance(5, "acme.test")
        account = api.get(f"/api/v1/acme/accounts/{ids['account']}").get_json()
        assert [order["id"] for order in account["orders"]] == [ids["order"]]
        order = api.get(f"/api/v1/acme/orders/{ids['order']}").get_json()
        assert order["order"]["certificate_serial"] == "5" and order["account"]["id"] == ids["account"]
        (authorization,) = order["authorizations"]
        assert [c["type"] for c in authorization["challenges"]] == ["dns-01", "http-01", "tls-alpn-01"]
        assert order["certificate"]["subject"] == "CN=acme.test"
        assert api.get("/api/v1/acme/orders/missing").status_code == 404
        assert api.get("/api/v1/acme/accounts/missing").status_code == 404

    def test_csv(self, api, step_db):
        step_db.add_acme_issuance(5, "acme.test")
        rows = list(csv.reader(io.StringIO(api.get("/api/v1/acme/orders?format=csv").get_data(as_text=True))))
        assert rows[0][:3] == ["id", "account_id", "identifiers"] and rows[1][2] == "acme.test"


JWK_FROM_API = {
    "id": "prov-admin-jwk",
    "type": "JWK",
    "name": "Admin JWK",
    "claims": {"x509": {"enabled": True, "durations": {"default": "24h"}}, "disableRenewal": False},
    "createdAt": "2026-10-01T10:00:00Z",
}
ACME_FROM_API = {"type": "ACME", "name": "acme", "details": {"ACME": {"challenges": ["HTTP_01", "DEVICE_ATTEST_01"], "forceCn": True}}, "claims": {}}


class TestProvisioners:
    def test_list(self, api, ca_client, step_db):
        step_db.add_provisioner("prov-acme", "acme", prov_type=6)
        ca_client.list_provisioners.return_value = {"provisioners": [JWK_FROM_API, ACME_FROM_API]}
        jwk, acme = api.get("/api/v1/provisioners").get_json()["provisioners"]
        assert jwk["is_app_provisioner"] and jwk["durations"] == {"default": "24h", "min": None, "max": None}
        assert jwk["acme"] is None and jwk["created_at"].startswith("2026-10-01")
        # The Admin API's list has no ids: they come from the database
        assert acme["id"] == "prov-acme"
        assert acme["acme"] == {"challenges": ["HTTP_01"], "require_eab": False, "force_cn": True}
        ca_client.list_provisioners.return_value = None
        assert api.get("/api/v1/provisioners").status_code == 502

    def test_list_in_the_admin_apis_list_format(self, api, ca_client, step_db):
        # What step-ca 0.30 answers to GET /admin/provisioners: its older JSON, not linkedca's
        step_db.add_provisioner("prov-demo", "demo", created_at="2026-10-02T08:00:00Z")
        step_db.add_provisioner("prov-web", "web", prov_type=6)
        jwk = {"type": "JWK", "name": "demo", "claims": {"defaultTLSCertDuration": "2160h0m0s", "maxTLSCertDuration": "8760h0m0s", "disableRenewal": True}}
        acme = {"type": "ACME", "name": "web", "claims": {}, "challenges": ["dns-01", "device-attest-01"], "requireEAB": True, "forceCN": True}
        ca_client.list_provisioners.return_value = {"provisioners": [jwk, acme]}
        demo, web = api.get("/api/v1/provisioners").get_json()["provisioners"]
        assert demo["durations"] == {"min": None, "default": "2160h0m0s", "max": "8760h0m0s"} and demo["disable_renewal"]
        assert demo["created_at"].startswith("2026-10-02") and web["created_at"] is None
        assert web["acme"] == {"challenges": ["DNS_01"], "require_eab": True, "force_cn": True}

    def test_create(self, api, ca_client):
        body = {"name": "web", "type": "ACME", "durations": {"default": "24h", "max": ""}, "acme": {"challenges": ["DNS_01"], "require_eab": True}}
        assert api.post("/api/v1/provisioners", json=body).status_code == 201
        kwargs = ca_client.create_provisioner_acme.call_args.kwargs
        assert kwargs["details"] == {"ACME": {"requireEab": True, "forceCn": False, "challenges": ["DNS_01"]}}
        assert kwargs["claims"] == {"x509": {"enabled": True, "durations": {"default": "24h"}}}
        assert api.post("/api/v1/provisioners", json={"name": "j", "type": "JWK"}).status_code == 422
        assert api.post("/api/v1/provisioners", json={"name": "j", "type": "JWK", "password": "secret"}).status_code == 201
        ca_client.create_provisioner_jwk.assert_called_once_with("j", "secret", claims={"x509": {"enabled": True}})
        assert api.post("/api/v1/provisioners", json={**body, "durations": {"default": "a day"}}).status_code == 422

    def test_step_ca_refusal_is_shown(self, api, ca_client):
        ca_client.create_provisioner_acme.side_effect = CAError("provisioner with name web already exists")
        response = api.post("/api/v1/provisioners", json={"name": "web", "type": "ACME"})
        assert response.get_json() == {"error": "step-ca did not create the provisioner: provisioner with name web already exists"}
        assert AuditEvent.query.filter_by(action="create_provisioner").one().success is False

    def test_update(self, api, ca_client):
        ca_client.get_provisioner.return_value = json.loads(json.dumps(ACME_FROM_API))
        ca_client.update_provisioner.side_effect = lambda name, record: record
        body = {"durations": {"max": "720h"}, "disable_renewal": True, "acme": {"challenges": ["TLS_ALPN_01"], "require_eab": False, "force_cn": False}}
        response = api.put("/api/v1/provisioners/acme", json=body)
        assert response.status_code == 200
        sent = ca_client.update_provisioner.call_args.args[1]
        assert sent["claims"]["x509"] == {"durations": {"max": "720h"}} and sent["claims"]["disableRenewal"] is True
        # Challenges the form doesn't offer are kept
        assert sent["details"]["ACME"]["challenges"] == ["TLS_ALPN_01", "DEVICE_ATTEST_01"]

    def test_the_app_provisioner_is_protected(self, api, ca_client):
        ca_client.get_provisioner.return_value = json.loads(json.dumps(JWK_FROM_API))
        response = api.put("/api/v1/provisioners/Admin%20JWK", json={"durations": {"max": "1h"}})
        assert response.status_code == 422 and "the app's own provisioner" in response.get_json()["error"]
        assert api.delete("/api/v1/provisioners/Admin%20JWK").status_code == 422
        ca_client.update_provisioner.assert_not_called()
        ca_client.delete_provisioner.assert_not_called()

    def test_delete(self, api, ca_client):
        assert api.delete("/api/v1/provisioners/old").get_json() == {"message": "Provisioner 'old' deleted."}
        ca_client.delete_provisioner.assert_called_once_with("old")
        ca_client.get_provisioner.return_value = None
        assert api.put("/api/v1/provisioners/gone", json={}).status_code == 404


class TestAdmins:
    def test_list(self, api, step_db):
        body = api.get("/api/v1/admins").get_json()
        assert body["manageable"] is True and body["identity_type"] == "SUPER_ADMIN"
        (admin,) = body["admins"]
        assert (admin["subject"], admin["provisioner_name"], admin["type"]) == ("step", "Admin JWK", "SUPER_ADMIN")
        assert body["provisioners"] == [{"id": ADMIN_JWK["id"], "name": "Admin JWK"}]

    def test_changes(self, api, ca_client):
        assert api.post("/api/v1/admins", json={"subject": "alice", "provisioner": "Admin JWK", "type": "ADMIN"}).status_code == 201
        ca_client.create_admin.assert_called_once_with(subject="alice", provisioner="Admin JWK", admin_type=1)
        assert api.patch("/api/v1/admins/adm-1", json={"type": "SUPER_ADMIN"}).status_code == 200
        ca_client.update_admin.assert_called_once_with("adm-1", 2)
        ca_client.delete_admin.side_effect = CAError("admin cannot delete itself")
        assert api.delete("/api/v1/admins/adm-1").get_json()["error"] == "step-ca did not delete the admin: admin cannot delete itself"

    def test_read_only_with_an_admin_identity(self, api, ca_client):
        ca_client.identity = "ADMIN"
        assert api.get("/api/v1/admins").get_json()["manageable"] is False
        response = api.post("/api/v1/admins", json={"subject": "alice", "provisioner": "Admin JWK", "type": "ADMIN"})
        assert response.status_code == 403 and "step ca admin" in response.get_json()["error"]
        assert api.delete("/api/v1/admins/adm-1").status_code == 403
        ca_client.create_admin.assert_not_called()
        ca_client.delete_admin.assert_not_called()


class TestCa:
    def test_status(self, api, ca_up):  # noqa: F811  fixture
        body = api.get("/api/v1/ca").get_json()
        assert (body["health"], body["version"], body["version_tested"], body["errors"]) == ("ok", "0.30.2", True, [])
        assert body["roots"][0]["pinned"] is True and body["roots"][0]["key"] == "secp256r1"
        assert body["intermediates"][0]["days_left"] in (19, 20)
        assert body["crl"]["entries"] == 2

    def test_status_with_the_ca_down(self, api, ca_up):  # noqa: F811  fixture
        for call in (ca_up.health, ca_up.version, ca_up.roots, ca_up.intermediates, ca_up.crl):
            call.side_effect = requests.ConnectionError("connection refused")
        body = api.get("/api/v1/ca").get_json()
        assert body["health"] is None and "version: connection refused" in body["errors"]

    def test_downloads(self, api, ca_up):  # noqa: F811  fixture
        assert x509.load_pem_x509_certificates(api.get("/api/v1/ca/roots.pem").data) == ca_up.roots.return_value
        assert api.get("/api/v1/ca/other.pem").status_code == 422
        assert len(x509.load_der_x509_crl(api.get("/api/v1/ca/crl").data)) == 2
        assert len(x509.load_pem_x509_crl(api.get("/api/v1/ca/crl?format=pem").data)) == 2
        ca_up.crl.return_value = None
        assert api.get("/api/v1/ca/crl").status_code == 404


class TestSystem:
    def test_settings_hide_secrets(self, api):
        body = api.get("/api/v1/settings").get_json()
        values = {item["label"]: item["value"] for section in body["sections"] for item in section["items"]}
        assert values["Password"] == "set" and values["Backend"] == "local"
        assert "test-secret" not in json.dumps(body)

    def test_audit_log(self, api, ca_client, step_db):
        step_db.add_cert(1)
        api.post("/api/v1/certificates/1/revoke", json={"reason_code": 0})
        body = api.get("/api/v1/audit").get_json()
        assert [event["action"] for event in body["items"]] == ["revoke", "login"]
        assert body["actions"] == ["login", "revoke"]
        assert api.get("/api/v1/audit?action=revoke").get_json()["total"] == 1
        assert api.get("/api/v1/audit?success=false").get_json()["total"] == 0
        rows = list(csv.DictReader(io.StringIO(api.get("/api/v1/audit?format=csv").get_data(as_text=True))))
        assert rows[0]["action"] == "revoke"

    def test_service_control_is_off_by_default(self, api):
        assert api.post("/api/v1/service", json={"action": "status"}).status_code == 404

    def test_health_check(self, app):
        assert app.test_client().get("/healthz").get_json() == {"status": "ok"}


def test_openapi_document_is_current(app):
    """frontend/openapi.json is what the frontend's types are generated from: regenerate it with
    `uv run python -m app.api.openapi`."""
    from app.api.openapi import document

    committed = pathlib.Path(__file__).parent.parent / "frontend" / "openapi.json"
    assert json.loads(committed.read_text()) == document(app)


def test_dates_are_utc(api, step_db):
    step_db.add_cert(1, not_before=datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.UTC))
    item = api.get("/api/v1/certificates").get_json()["items"][0]
    assert datetime.datetime.fromisoformat(item["not_before"]) == datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.UTC)


class TestRedesign:
    """The endpoints of the certificate list's tabs and filters, the detail sheet, and the overview."""

    @pytest.fixture
    def inventory(self, step_db):
        now = datetime.datetime.now(datetime.UTC)
        step_db.add_cert(1, "web.test", days_valid=100, not_before=now - datetime.timedelta(days=95))  # expiring
        step_db.add_cert(2, "db.test", days_valid=100, not_before=now - datetime.timedelta(days=2))
        step_db.add_cert(3, "old.test", days_valid=10, not_before=now - datetime.timedelta(days=40))  # expired
        step_db.add_cert(4, "acme.test", provisioner={"id": "prov-acme", "name": "acme", "type": "ACME"})
        step_db.add_cert(5, "gone.test", days_valid=100, not_before=now - datetime.timedelta(days=3))
        step_db.add_revocation(5)
        return step_db

    def test_counts_and_facets(self, api, inventory):
        assert api.get("/api/v1/certificates/counts").get_json() == {"all": 5, "valid": 3, "expiring": 1, "expired": 1, "revoked": 1}
        assert api.get("/api/v1/certificates/facets").get_json() == {"provisioners": ["Admin JWK", "acme"], "keys": ["secp256r1"]}

    def test_several_provisioners_and_keys(self, api, inventory):
        assert api.get("/api/v1/certificates?provisioner=acme").get_json()["total"] == 1
        assert api.get("/api/v1/certificates?provisioner=acme&provisioner=Admin%20JWK").get_json()["total"] == 5
        assert api.get("/api/v1/certificates?key=RSA%202048").get_json()["total"] == 0
        assert api.get("/api/v1/certificates?key=secp256r1&provisioner=acme").get_json()["total"] == 1

    def test_bundle(self, api, inventory):
        response = api.get("/api/v1/certificates/bundle?serial=1&serial=2&serial=1")
        assert [c.serial_number for c in x509.load_pem_x509_certificates(response.data)] == [1, 2]
        assert api.get("/api/v1/certificates/bundle?serial=1&serial=99").status_code == 404
        assert api.get("/api/v1/certificates/bundle").status_code == 422

    def test_events(self, api, inventory):
        kinds = [event["kind"] for event in api.get("/api/v1/certificates/5/events").get_json()["items"]]
        assert kinds[0] == "expires" and "revoked" in kinds and kinds[-1] == "issued"
        assert api.get("/api/v1/certificates/99/events").status_code == 404

    def test_events_of_an_acme_certificate(self, api, step_db):
        step_db.add_cert(7, "acme.test", provisioner={"id": "prov-acme", "name": "acme", "type": "ACME"})
        step_db.add_acme_issuance(7, "acme.test")
        labels = [event["label"] for event in api.get("/api/v1/certificates/7/events").get_json()["items"]]
        assert "http-01 challenge validated for acme.test" in labels and "ACME order placed" in labels

    def test_overview(self, api, inventory):
        body = api.get("/api/v1/overview?range=7d").get_json()
        kpis = {kpi["key"]: kpi for kpi in body["kpis"]}
        assert kpis["active"]["value"] == 3 and len(kpis["active"]["series"]) == 8
        # Issued in the last 7 days: db, acme and gone (revoked since)
        assert kpis["issued"]["value"] == 3 and sum(kpis["issued"]["series"]) == 3
        assert kpis["expiring"]["value"] == 1
        assert body["issuance"]["series"] == ["Admin JWK", "acme"] and len(body["issuance"]["buckets"]) == 7
        assert sum(sum(bucket["counts"]) for bucket in body["issuance"]["buckets"]) == 3
        assert body["callout"]["kind"] == "expiring" and body["callout"]["serial"] == "1"
        assert [event["action"] for event in body["activity"]][:1] == ["issued"]
        assert api.get("/api/v1/overview?range=1y").status_code == 422

    def test_callout_names_failed_acme_renewals(self, api, step_db):
        from app.extensions import db
        from app.models import acme as acme_tables

        now = datetime.datetime.now(datetime.UTC)
        step_db.add_cert(1, "web.test", days_valid=100, not_before=now - datetime.timedelta(days=95))
        order = {"id": "failed", "accountID": "a", "identifiers": [{"type": "dns", "value": "web.test"}], "status": "invalid",
                 "createdAt": now.isoformat(), "error": {"detail": "DNS-01 record not found"}}
        db.session.add(acme_tables.AcmeOrder(nkey=b"failed", nvalue=json.dumps(order).encode()))
        db.session.commit()
        callout = api.get("/api/v1/overview").get_json()["callout"]
        assert (callout["failed_renewals"], callout["error"]) == (1, "DNS-01 record not found")

    def test_activity_names_who_revoked(self, api, ca_client, inventory):
        ca_client.revoke.side_effect = lambda *args, **kwargs: inventory.add_revocation(2)
        api.post("/api/v1/certificates/2/revoke", json={"reason_code": 0})
        activity = api.get("/api/v1/overview").get_json()["activity"]
        assert {"actor": "admin", "action": "revoked", "subject": "db.test"}.items() <= next(a for a in activity if a["action"] == "revoked").items()

    def test_provisioner_extras(self, api, ca_client, step_db):
        step_db.add_cert(4, "acme.test", provisioner={"id": "prov-acme", "name": "acme", "type": "ACME"})
        ca_client.list_provisioners.return_value = {"provisioners": [ACME_FROM_API]}
        (acme,) = api.get("/api/v1/provisioners").get_json()["provisioners"]
        assert acme["directory_url"] == "https://ca.test:9000/acme/acme/directory" and acme["issued_30d"] == 1

    def test_authority_name_and_environment(self, app):
        from app import create_app

        named = create_app(app.extensions["settings"].model_copy(update={"ca_display_name": "Corp CA", "ca_environment": "Production"}))
        body = named.test_client().get("/api/v1/session").get_json()
        assert body["authority"] == {"name": "Corp CA", "environment": "Production", "url": "https://ca.test:9000"}
