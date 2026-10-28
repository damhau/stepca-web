"""End-to-end tests against a real step-ca. Run with tests/e2e/run.sh, which starts the stack."""

import os
import re
import subprocess

import pytest
import requests
from cryptography import x509

BASE_URL = os.environ.get("E2E_BASE_URL")
COMPOSE = os.environ.get("E2E_COMPOSE", "tests/e2e/compose.yml")
CA = ["--ca-url", "https://localhost:9000", "--root", "/home/step/certs/root_ca.crt"]

pytestmark = pytest.mark.skipif(not BASE_URL, reason="needs the stack started by tests/e2e/run.sh")


def compose_exec(service, *args, stdin=None):
    return subprocess.run(["docker", "compose", "-f", COMPOSE, "exec", "-T", service, *args], input=stdin, capture_output=True, text=True)


def step(*args, stdin=None):
    return compose_exec("step-ca", "step", *args, stdin=stdin)


def token_from(html):
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def flashes(html):
    return [
        (kind, re.sub(r"\s+", " ", text).strip())
        for kind, text in re.findall(r"alert alert-(success|danger)[^>]*>(.*?)<button", html, re.S)
    ]


@pytest.fixture(scope="module")
def session():
    s = requests.Session()
    token = token_from(s.get(f"{BASE_URL}/auth/login").text)
    response = s.post(
        f"{BASE_URL}/auth/login", data={"username": "admin", "password": "testpw", "csrf_token": token}, allow_redirects=False
    )
    assert response.status_code == 302
    s.csrf = token_from(s.get(f"{BASE_URL}/auth/login").text)
    return s


def test_logged_out_requests_are_refused():
    s = requests.Session()
    assert s.get(f"{BASE_URL}/step/admins", allow_redirects=False).status_code == 302
    assert s.get(f"{BASE_URL}/api/x509/certs").status_code == 401


@pytest.mark.parametrize(
    "path", ["/", "/x509/all", "/x509/active", "/x509/revoked", "/acme/accounts", "/step/provisioners", "/step/admins", "/system/config"]
)
def test_pages_render(session, path):
    assert session.get(f"{BASE_URL}{path}").status_code == 200


def test_forged_requests_are_refused(session):
    response = session.post(f"{BASE_URL}/step/provisioner/Admin%20JWK/delete")
    assert response.status_code == 400
    provisioners = step("ca", "provisioner", "list", *CA).stdout
    assert '"Admin JWK"' in provisioners


def test_ca_root_was_pinned():
    assert compose_exec("stepca-web", "test", "-s", "/data/ca_root.crt").returncode == 0


def test_sign_download_and_revoke(session):
    """Sign from the UI, download the certificate, revoke it, and check that step-ca refuses to renew it."""
    assert (
        step("certificate", "create", "e2e-ui.test", "/tmp/ui.csr", "/tmp/ui.key", "--csr", "--no-password", "--insecure").returncode == 0
    )
    csr = compose_exec("step-ca", "cat", "/tmp/ui.csr").stdout
    html = session.post(
        f"{BASE_URL}/x509/sign", data={"csr_pem": csr, "passphrase": "testpass", "provisioner": "Admin JWK", "csrf_token": session.csrf}
    ).text
    (kind, message), *_ = flashes(html)
    assert kind == "success", message
    serial = re.search(r"Certificate (\d+) created", message).group(1)

    pem = session.get(f"{BASE_URL}/x509/download/{serial}").content
    assert str(x509.load_pem_x509_certificate(pem).serial_number) == serial
    compose_exec("step-ca", "sh", "-c", "cat > /tmp/ui.crt", stdin=pem.decode())
    renew = ["ca", "renew", "--force", *CA, "--out", "/tmp/renewed.crt", "/tmp/ui.crt", "/tmp/ui.key"]
    assert step(*renew).returncode == 0, "renewal must work before the revocation"

    html = session.post(f"{BASE_URL}/x509/revoke", data={"cert_id": serial, "passphrase": "testpass", "csrf_token": session.csrf}).text
    assert ("success", f"Certificate {serial} has been revoked successfully.") in flashes(html)
    assert step(*renew).returncode != 0, "step-ca must refuse to renew a revoked certificate"
    assert serial not in session.get(f"{BASE_URL}/x509/active").text


def test_lists_are_not_truncated_at_20(session):
    for i in range(25):
        session.post(
            f"{BASE_URL}/step/provisioners",
            data={
                "type": "ACME",
                "name": f"acme-{i:02d}",
                "duration_default": "24h",
                "duration_min": "5m",
                "duration_max": "48h",
                "csrf_token": session.csrf,
            },
        )
    html = session.get(f"{BASE_URL}/step/provisioners").text
    assert len(re.findall(r'action="/step/provisioner/[^"]+/delete"', html)) == 26
