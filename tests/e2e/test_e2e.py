"""End-to-end tests against a real step-ca. Run with tests/e2e/run.sh, which starts the stack."""

import json
import os
import re
import subprocess
from html import unescape
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


def token_from(html):
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def flashes(html):
    return [
        (kind, unescape(re.sub(r"\s+", " ", text).strip()))
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
    chain = x509.load_pem_x509_certificates(session.get(f"{BASE_URL}/x509/download/{serial}?format=chain").content)
    assert len(chain) == 2 and chain[1].subject == chain[0].issuer, "the chain is the certificate and its intermediate"
    compose_exec("step-ca", "sh", "-c", "cat > /tmp/ui.crt", stdin=pem.decode())
    renew = ["ca", "renew", "--force", *CA, "--out", "/tmp/renewed.crt", "/tmp/ui.crt", "/tmp/ui.key"]
    assert step(*renew).returncode == 0, "renewal must work before the revocation"

    html = session.post(f"{BASE_URL}/x509/revoke", data={"cert_id": serial, "reason": "4", "csrf_token": session.csrf}).text
    assert ("success", f"Certificate {serial} has been revoked successfully.") in flashes(html)
    assert "Superseded (4)" in html, "the revocation reason recorded by step-ca is shown on the certificate page"
    assert step(*renew).returncode != 0, "step-ca must refuse to renew a revoked certificate"
    crl = x509.load_der_x509_crl(session.get(f"{BASE_URL}/step/ca/crl").content)
    assert crl.get_revoked_certificate_by_serial_number(int(serial)) is not None, "the CRL lists the revoked serial"
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
    assert len(re.findall(r'action="/step/provisioner/acme-\d\d/delete"', html)) == 25


@pytest.mark.skipif(IDENTITY != "super", reason="only a SUPER_ADMIN identity can change admins")
def test_admin_type_can_be_changed(session):
    def admin_row(subject):
        rows = re.findall(r"<tr>(.*?)</tr>", session.get(f"{BASE_URL}/step/admins").text, re.S)
        return next(row for row in rows if f"<td>{subject}</td>" in row)

    session.post(
        f"{BASE_URL}/step/admins", data={"subject": "e2e-ops", "provisioner": "Admin JWK", "type": "1", "csrf_token": session.csrf}
    )
    row = admin_row("e2e-ops")
    assert "SUPER_ADMIN" not in row
    admin_id = re.search(r"/step/admin/([^/\"]+)/delete", row).group(1)
    html = session.post(f"{BASE_URL}/step/admin/{admin_id}/update", data={"type": "2", "csrf_token": session.csrf}).text
    assert ("success", f"Admin '{admin_id}' updated.") in flashes(html)
    assert "SUPER_ADMIN" in admin_row("e2e-ops")
    assert len(re.findall(r"<td>e2e-ops</td>", session.get(f"{BASE_URL}/step/admins").text)) == 1, "editing must not duplicate the admin"


@pytest.mark.skipif(IDENTITY != "admin", reason="dedicated ADMIN identity only")
def test_dedicated_admin_identity(session):
    """The app acts as the ADMIN 'stepca-web', with a key decrypted in memory only."""
    html = session.get(f"{BASE_URL}/step/admins").text
    assert "admins are read-only here" in html
    assert "Add Admin" not in html
    html = session.post(
        f"{BASE_URL}/step/admins", data={"subject": "x", "provisioner": "Admin JWK", "type": "2", "csrf_token": session.csrf}
    ).text
    assert "manage admins with `step ca admin`" in unescape(html)
    assert "<td>x</td>" not in session.get(f"{BASE_URL}/step/admins").text

    config = unescape(session.get(f"{BASE_URL}/system/config").text)
    assert "stepca-web on provisioner stepca-web" in config
    assert "<code>ADMIN</code>" in config
    assert "decrypted in memory" in config

    check = compose_exec(
        "stepca-web",
        "python",
        "-c",
        "import os; from cryptography import x509; from app.libs.cert_utils import issuing_provisioner; "
        "c = x509.load_pem_x509_certificate(open('/data/admin.crt', 'rb').read()); "
        "print(c.subject.rfc4514_string(), issuing_provisioner(c), os.path.exists('/data/jwk_key.json'))",
    )
    assert check.stdout.splitlines()[-1].split() == ["CN=stepca-web", "stepca-web", "False"], check.stderr


def test_provisioner_can_be_edited_and_deleted(session):
    """A name with a space: the Admin API paths and the token audience must escape it the same way."""
    name = "e2e edit"
    edit_url = f"{BASE_URL}/step/provisioner/{quote(name)}/edit"
    html = session.post(
        f"{BASE_URL}/step/provisioners",
        data={"name": name, "type": "ACME", "duration_default": "24h", "challenges": "DNS_01", "csrf_token": session.csrf},
    ).text
    assert ("success", f"Provisioner '{name}' created successfully.") in flashes(html)
    assert 'value="24h"' in session.get(edit_url).text

    changes = {"x509_enabled": "on", "duration_default": "12h", "duration_max": "36h", "force_cn": "on", "challenges": ["HTTP_01", "TLS_ALPN_01"]}
    html = session.post(edit_url, data={**changes, "csrf_token": session.csrf}).text
    assert ("success", f"Provisioner '{name}' updated.") in flashes(html)
    listed = next(p for p in json.loads(step("ca", "provisioner", "list", *CA).stdout) if p["name"] == name)
    assert listed["forceCN"] is True
    assert sorted(listed["challenges"]) == ["http-01", "tls-alpn-01"]
    assert 'value="12h"' in session.get(edit_url).text and 'value="36h"' in session.get(edit_url).text

    # step-ca's own validation: a default longer than the maximum is refused, with its message
    html = session.post(edit_url, data={**changes, "duration_default": "48h", "csrf_token": session.csrf}).text
    (kind, message), *_ = flashes(html)
    assert kind == "danger" and message.startswith(f"Provisioner '{name}' was not updated:"), message

    html = session.post(f"{BASE_URL}/step/provisioner/{quote(name)}/delete", data={"csrf_token": session.csrf}).text
    assert ("success", f"Provisioner '{name}' deleted successfully.") in flashes(html)
    assert name not in [p["name"] for p in json.loads(step("ca", "provisioner", "list", *CA).stdout)]


def test_ca_status(session):
    html = session.get(f"{BASE_URL}/step/ca").text
    assert 'badge-success">ok' in html
    assert "0.30.2" in html and "not tested" not in html
    assert ">pinned<" in html, "the root matches CA_FINGERPRINT"
    roots = x509.load_pem_x509_certificates(session.get(f"{BASE_URL}/step/ca/roots.pem").content)
    root = compose_exec("step-ca", "cat", "/home/step/certs/root_ca.crt").stdout.encode()
    assert roots == [x509.load_pem_x509_certificate(root)]


def test_acme_drill_down(session):
    """run.sh issued a certificate for acme-client over ACME, with an http-01 challenge."""
    order_id = re.search(r'href="/acme/order/([^"]+)"', session.get(f"{BASE_URL}/acme/orders").text).group(1)
    html = session.get(f"{BASE_URL}/acme/order/{order_id}").text
    assert "Authorization for acme-client" in html
    assert re.search(r'http-01</td>\s*<td><span class="badge badge-success">valid', html), "the http-01 challenge is valid"
    serial = re.search(r'href="/x509/cert/(\d+)"', html).group(1)
    assert f'href="/acme/order/{order_id}"' in session.get(f"{BASE_URL}/x509/cert/{serial}").text
    account_id = re.search(r'href="/acme/account/([^"]+)"', html).group(1)
    assert "e2e@example.org" in session.get(f"{BASE_URL}/acme/account/{account_id}").text


def test_sign_with_a_validity_and_readable_errors(session):
    assert step("certificate", "create", "e2e-valid.test", "/tmp/v.csr", "/tmp/v.key", "--csr", "--no-password", "--insecure").returncode == 0
    csr = compose_exec("step-ca", "cat", "/tmp/v.csr").stdout
    form = {"csr_pem": csr, "provisioner": "Admin JWK", "csrf_token": session.csrf}

    (kind, message), *_ = flashes(session.post(f"{BASE_URL}/x509/sign", data={**form, "passphrase": "wrong"}).text)
    assert (kind, message) == ("danger", "The certificate was not signed: Wrong password for provisioner 'Admin JWK'.")

    (kind, message), *_ = flashes(session.post(f"{BASE_URL}/x509/sign", data={**form, "passphrase": "testpass", "valid_for": "900h"}).text)
    assert kind == "danger" and message.startswith("The certificate was not signed: step-ca refused:"), message

    html = session.post(f"{BASE_URL}/x509/sign", data={**form, "passphrase": "testpass", "valid_for": "10m"}).text
    (kind, message), *_ = flashes(html)
    assert kind == "success", message
    serial = re.search(r"Certificate (\d+) created", message).group(1)
    cert = x509.load_pem_x509_certificate(session.get(f"{BASE_URL}/x509/download/{serial}").content)
    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    # step-ca backdates notBefore by a minute
    assert 10 * 60 <= lifetime.total_seconds() <= 11 * 60, lifetime
