"""End-to-end tests of the API against a real step-ca. Run with tests/e2e/run.sh, which starts the stack."""

import json
import os
import subprocess
import time
from urllib.parse import quote

import pytest
import requests
from cryptography import x509

BASE_URL = os.environ.get("E2E_BASE_URL")
COMPOSE = os.environ.get("E2E_COMPOSE", "tests/e2e/compose.yml")
IDENTITY = os.environ.get("E2E_IDENTITY", "admin")
CA = ["--ca-url", "https://localhost:9000", "--root", "/home/step/certs/root_ca.crt"]

pytestmark = pytest.mark.skipif(not BASE_URL, reason="needs the stack started by tests/e2e/run.sh")


def compose_exec(service, *args, stdin=None):
    return subprocess.run(["docker", "compose", "-f", COMPOSE, "exec", "-T", service, *args], input=stdin, capture_output=True, text=True)


def step(*args, stdin=None):
    return compose_exec("step-ca", "step", *args, stdin=stdin)


class Api:
    """The API as the frontend uses it: a session cookie, and its CSRF token on every write."""

    def __init__(self):
        self.http = requests.Session()
        self.token = self.http.get(f"{BASE_URL}/api/v1/session").json()["csrf_token"]

    def sign_in(self, username="admin", password="testpw"):
        response = self.send("POST", "/api/v1/session", {"username": username, "password": password})
        assert response.status_code == 200, response.text
        self.token = response.json()["csrf_token"]
        return self

    def get(self, path):
        return self.http.get(f"{BASE_URL}{path}")

    def send(self, method, path, body=None):
        return self.http.request(method, f"{BASE_URL}{path}", json=body, headers={"X-CSRFToken": self.token})


@pytest.fixture(scope="module")
def api():
    return Api().sign_in()


def test_signed_out_requests_are_refused():
    assert requests.get(f"{BASE_URL}/api/v1/admins").status_code == 401
    assert requests.get(f"{BASE_URL}/api/v1/certificates").status_code == 401
    # The frontend's page is public: it asks the API who is signed in
    assert '<div id="root">' in requests.get(f"{BASE_URL}/certificates").text


def test_the_frontend_is_served(api):
    page = requests.get(f"{BASE_URL}/")
    assert page.headers["Content-Security-Policy"].count("'nonce-") == 1
    script = next(part.split('"')[1] for part in page.text.split("src=")[1:] if part.startswith('"/assets/'))
    assert requests.get(f"{BASE_URL}{script}").headers["Content-Type"].startswith("text/javascript")


def test_forged_requests_are_refused(api):
    response = api.http.delete(f"{BASE_URL}/api/v1/provisioners/{quote('Admin JWK')}")
    assert response.status_code == 400
    assert '"Admin JWK"' in step("ca", "provisioner", "list", *CA).stdout


def test_ca_root_was_pinned():
    assert compose_exec("stepca-web", "test", "-s", "/data/ca_root.crt").returncode == 0


def make_csr(name, path):
    assert step("certificate", "create", name, f"/tmp/{path}.csr", f"/tmp/{path}.key", "--csr", "--no-password", "--insecure").returncode == 0
    return compose_exec("step-ca", "cat", f"/tmp/{path}.csr").stdout


def test_sign_download_and_revoke(api):
    """Sign through the API, download the certificate, revoke it, and check that step-ca refuses to renew it."""
    csr = make_csr("e2e-ui.test", "ui")
    response = api.send("POST", "/api/v1/certificates", {"csr_pem": csr, "password": "testpass", "provisioner": "Admin JWK"})
    assert response.status_code == 201, response.text
    serial = response.json()["serial"]

    pem = api.get(f"/api/v1/certificates/{serial}/download").content
    assert str(x509.load_pem_x509_certificate(pem).serial_number) == serial
    chain = x509.load_pem_x509_certificates(api.get(f"/api/v1/certificates/{serial}/download?format=chain").content)
    assert len(chain) == 2 and chain[1].subject == chain[0].issuer, "the chain is the certificate and its intermediate"
    compose_exec("step-ca", "sh", "-c", "cat > /tmp/ui.crt", stdin=pem.decode())
    renew = ["ca", "renew", "--force", *CA, "--out", "/tmp/renewed.crt", "/tmp/ui.crt", "/tmp/ui.key"]
    assert step(*renew).returncode == 0, "renewal must work before the revocation"

    detail = api.send("POST", f"/api/v1/certificates/{serial}/revoke", {"reason_code": 4}).json()
    assert detail["certificate"]["status"] == "revoked"
    assert (detail["revocation"]["reason_code"], detail["revocation"]["reason"]) == (4, "Superseded"), "as step-ca recorded it"
    assert step(*renew).returncode != 0, "step-ca must refuse to renew a revoked certificate"
    crl = x509.load_der_x509_crl(api.get("/api/v1/ca/crl").content)
    assert crl.get_revoked_certificate_by_serial_number(int(serial)) is not None, "the CRL lists the revoked serial"
    valid = api.get("/api/v1/certificates?status=valid&per_page=500").json()["items"]
    assert serial not in [item["serial"] for item in valid]


def test_lists_are_not_truncated_at_20(api):
    for i in range(25):
        api.send("POST", "/api/v1/provisioners", {"type": "ACME", "name": f"acme-{i:02d}", "durations": {"default": "24h", "min": "5m", "max": "48h"}})
    names = [p["name"] for p in api.get("/api/v1/provisioners").json()["provisioners"]]
    assert len([name for name in names if name.startswith("acme-") and name[5:].isdigit()]) == 25


@pytest.mark.skipif(IDENTITY != "super", reason="only a SUPER_ADMIN identity can change admins")
def test_admin_type_can_be_changed(api):
    def admins(subject):
        return [admin for admin in api.get("/api/v1/admins").json()["admins"] if admin["subject"] == subject]

    assert api.send("POST", "/api/v1/admins", {"subject": "e2e-ops", "provisioner": "Admin JWK", "type": "ADMIN"}).status_code == 201
    (admin,) = admins("e2e-ops")
    assert admin["type"] == "ADMIN"
    assert api.send("PATCH", f"/api/v1/admins/{admin['id']}", {"type": "SUPER_ADMIN"}).status_code == 200
    assert [admin["type"] for admin in admins("e2e-ops")] == ["SUPER_ADMIN"], "editing must not duplicate the admin"


@pytest.mark.skipif(IDENTITY != "admin", reason="dedicated ADMIN identity only")
def test_dedicated_admin_identity(api):
    """The app acts as the ADMIN 'stepca-web', with a key decrypted in memory only."""
    listed = api.get("/api/v1/admins").json()
    assert (listed["manageable"], listed["identity_type"]) == (False, "ADMIN")
    response = api.send("POST", "/api/v1/admins", {"subject": "x", "provisioner": "Admin JWK", "type": "SUPER_ADMIN"})
    assert response.status_code == 403 and "step ca admin" in response.json()["error"]
    assert "x" not in [admin["subject"] for admin in api.get("/api/v1/admins").json()["admins"]]

    values = {item["label"]: item["value"] for section in api.get("/api/v1/settings").json()["sections"] for item in section["items"]}
    assert values["App identity"] == "stepca-web on provisioner stepca-web"
    assert values["App identity type"] == "ADMIN"
    assert "decrypted in memory" in values["Admin provisioner key"]

    check = compose_exec(
        "stepca-web",
        "python",
        "-c",
        "import os; from cryptography import x509; from app.libs.cert_utils import issuing_provisioner; "
        "c = x509.load_pem_x509_certificate(open('/data/admin.crt', 'rb').read()); "
        "print(c.subject.rfc4514_string(), issuing_provisioner(c), os.path.exists('/data/jwk_key.json'))",
    )
    assert check.stdout.splitlines()[-1].split() == ["CN=stepca-web", "stepca-web", "False"], check.stderr


def test_provisioner_can_be_edited_and_deleted(api):
    """A name with a space: the Admin API paths and the token audience must escape it the same way."""
    name = "e2e edit"
    path = f"/api/v1/provisioners/{quote(name)}"
    created = api.send("POST", "/api/v1/provisioners", {"name": name, "type": "ACME", "durations": {"default": "24h"}, "acme": {"challenges": ["DNS_01"]}})
    assert created.json() == {"message": f"Provisioner '{name}' created."}
    assert api.get(path).json()["durations"]["default"] == "24h"

    changes = {
        "durations": {"default": "12h", "max": "36h"},
        "acme": {"force_cn": True, "require_eab": False, "challenges": ["HTTP_01", "TLS_ALPN_01"]},
    }
    saved = api.send("PUT", path, changes)
    assert saved.status_code == 200, saved.text
    listed = next(p for p in json.loads(step("ca", "provisioner", "list", *CA).stdout) if p["name"] == name)
    assert listed["forceCN"] is True
    assert sorted(listed["challenges"]) == ["http-01", "tls-alpn-01"]
    assert api.get(path).json()["durations"] == {"default": "12h", "min": None, "max": "36h"}

    # step-ca's own validation: a default longer than the maximum is refused, with its message
    refused = api.send("PUT", path, {**changes, "durations": {"default": "48h", "max": "36h"}})
    assert refused.status_code == 422 and refused.json()["error"].startswith(f"Provisioner '{name}' was not updated:"), refused.text

    assert api.send("DELETE", path).json() == {"message": f"Provisioner '{name}' deleted."}
    assert name not in [p["name"] for p in json.loads(step("ca", "provisioner", "list", *CA).stdout)]


def test_ca_status(api):
    status = api.get("/api/v1/ca").json()
    assert status["health"] == "ok" and status["errors"] == []
    assert status["version"] == "0.30.2" and status["version_tested"]
    assert status["roots"][0]["pinned"], "the root matches CA_FINGERPRINT"
    roots = x509.load_pem_x509_certificates(api.get("/api/v1/ca/roots.pem").content)
    root = compose_exec("step-ca", "cat", "/home/step/certs/root_ca.crt").stdout.encode()
    assert roots == [x509.load_pem_x509_certificate(root)]


def test_acme_drill_down(api):
    """run.sh issued a certificate for acme-client over ACME, with an http-01 challenge."""
    (order,) = [item for item in api.get("/api/v1/acme/orders").json()["items"] if item["identifiers"][0]["value"] == "acme-client"]
    detail = api.get(f"/api/v1/acme/orders/{order['id']}").json()
    (authorization,) = detail["authorizations"]
    assert authorization["authorization"]["identifier"]["value"] == "acme-client"
    assert {c["type"]: c["status"] for c in authorization["challenges"]}["http-01"] == "valid"
    serial = detail["order"]["certificate_serial"]
    assert api.get(f"/api/v1/certificates/{serial}").json()["acme_order_id"] == order["id"]
    contact = api.get(f"/api/v1/acme/accounts/{order['account_id']}").json()["account"]["contact"]
    assert contact in (["e2e@example.org"], ["mailto:e2e@example.org"])


def test_sign_with_a_validity_and_readable_errors(api):
    csr = make_csr("e2e-valid.test", "v")
    body = {"csr_pem": csr, "provisioner": "Admin JWK"}

    wrong = api.send("POST", "/api/v1/certificates", {**body, "password": "wrong"}).json()
    assert wrong == {"error": "The certificate was not signed: Wrong password for provisioner 'Admin JWK'."}

    too_long = api.send("POST", "/api/v1/certificates", {**body, "password": "testpass", "valid_for": "900h"}).json()
    assert too_long["error"].startswith("The certificate was not signed: step-ca refused:"), too_long

    signed = api.send("POST", "/api/v1/certificates", {**body, "password": "testpass", "valid_for": "10m"})
    assert signed.status_code == 201, signed.text
    cert = x509.load_pem_x509_certificate(api.get(f"/api/v1/certificates/{signed.json()['serial']}/download").content)
    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    # step-ca backdates notBefore by a minute
    assert 10 * 60 <= lifetime.total_seconds() <= 11 * 60, lifetime


def test_the_inventory_follows_step_ca(api):
    """A certificate issued outside the app (here by the step CLI) shows up in the lists."""
    token = step("ca", "token", "e2e-cli.test", "--provisioner", "Admin JWK", "--password-file", "/home/step/secrets/password", *CA).stdout.strip()
    assert step("ca", "certificate", "e2e-cli.test", "/tmp/cli.crt", "/tmp/cli.key", "--token", token, "--force", *CA).returncode == 0
    # The inventory looks for new certificates at most every INVENTORY_REFRESH_SECONDS (5)
    for _ in range(20):
        found = api.get("/api/v1/certificates?q=e2e-cli.test").json()
        assert "total" in found, found
        if found["total"]:
            break
        time.sleep(0.5)
    assert found["total"] == 1 and found["items"][0]["provisioner_name"] == "Admin JWK"
    assert api.get("/api/v1/dashboard").json()["total"] >= 3
