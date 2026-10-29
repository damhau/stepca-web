"""What every page shares (flash messages, dates, no inline scripts) and the list and form details."""

import json
import re
from datetime import UTC, datetime

import pytest
from cryptography import x509

from app import format_datetime
from tests.conftest import make_cert
from tests.test_pages import PAGES

HTML_PAGES = [path for path in PAGES if not path.startswith("/api/")]


@pytest.fixture
def populated(step_db):
    step_db.add_cert(1001, "a.test")
    step_db.add_cert(1002, "b.test")
    step_db.add_cert(1003, "no-metadata.test", provisioner=None)
    step_db.add_revocation(1002)
    step_db.add_provisioner("prov-acme", "acme", prov_type=6)
    step_db.add_admin("adm-1", "step", "prov-admin-jwk")


@pytest.mark.parametrize("path", HTML_PAGES)
def test_every_page_shows_flash_messages(client, populated, path):
    with client.session_transaction() as session:
        session["_flashes"] = [("danger", "A message from the previous request")]
    assert "A message from the previous request" in client.get(path).get_data(as_text=True)


@pytest.mark.parametrize("path", HTML_PAGES + ["/auth/login"])
def test_no_inline_scripts_or_event_handlers(client, populated, path):
    """The Content-Security-Policy only allows the app's own script files."""
    html = client.get(path).get_data(as_text=True)
    inline = [tag for tag in re.findall(r"<script\b[^>]*>", html) if "src=" not in tag and 'type="application/json"' not in tag]
    assert inline == []
    assert re.findall(r"\son[a-z]+=", html) == []
    assert "javascript:" not in html


@pytest.mark.parametrize(
    "value, shown",
    [
        ("2025-07-01T12:34:56.123456789Z", "2025-07-01 12:34 UTC"),  # Go's RFC 3339 with nanoseconds
        ("2025-07-01T14:34:56+02:00", "2025-07-01 12:34 UTC"),
        ("0001-01-01T00:00:00Z", "—"),  # Go's zero time
        (1751373296, "2025-07-01 12:34 UTC"),  # epoch seconds
        (datetime(2025, 7, 1, 12, 34), "2025-07-01 12:34 UTC"),  # naive: UTC
        (datetime(2025, 7, 1, 12, 34, tzinfo=UTC), "2025-07-01 12:34 UTC"),
        (None, "—"),
        ("not a date", "not a date"),
    ],
)
def test_one_date_format(value, shown):
    assert format_datetime(value) == shown


def test_sign_form_only_offers_jwk_provisioners(client, populated):
    html = client.get("/x509/active").get_data(as_text=True)
    select = html[html.index('id="provisionerSelect"') : html.index("</select>", html.index('id="provisionerSelect"'))]
    assert re.findall(r'<option value="([^"]+)"', select) == ["Admin JWK"]


def test_sign_opens_the_new_certificate(client, ca_client, populated):
    ca_client.sign.return_value = x509.load_der_x509_certificate(make_cert(4242, "new.test"))
    response = client.post("/x509/sign", data={"csr_pem": "unused", "passphrase": "pw", "provisioner": "Admin JWK", "csrf_token": token(client)})
    assert response.headers["Location"] == "/x509/cert/4242"


def test_revoked_list_names_the_reason(client, populated):
    html = client.get("/x509/revoked").get_data(as_text=True)
    assert "Key compromise (1)" in html
    assert "2026-10-28 12:00 UTC" in html


def test_admins_table_names_the_provisioner(client, populated):
    html = client.get("/step/admins").get_data(as_text=True)
    assert "<td>Admin JWK</td>" in html
    assert "<td>SUPER_ADMIN</td>" in html


def test_lists_show_an_empty_state(client, step_db):
    assert "No certificates yet." in client.get("/x509/all").get_data(as_text=True)


def test_dashboard_charts_use_the_server_counts(client, populated):
    html = client.get("/").get_data(as_text=True)
    charts = json.loads(re.search(r'<script type="application/json" id="dashboard-data">(.*?)</script>', html, re.S).group(1))
    assert charts["issued_by_provisioner"] == {"Admin JWK": 2, "Unknown": 1}
    assert charts["acme_orders_by_status"] == {}
    assert "/api/x509/certs" not in html


def test_current_page_is_highlighted_in_the_menu(client, populated):
    html = client.get("/x509/revoked").get_data(as_text=True)
    assert re.findall(r'class="nav-link active"[^>]*>\s*<i[^>]*></i>\s*<p>([^<]+)</p>', html) == ["Revoked"]


def token(client):
    html = client.get("/x509/active").get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def test_admin_creation_date_falls_back_to_the_database(client, ca_client, populated):
    """The Admin API leaves created_at out for admins added since step-ca started."""
    ca_client.list_admins.return_value = {"admins": [{"id": "adm-1", "subject": "step", "provisioner_id": "prov-admin-jwk", "type": 2}]}
    assert "2026-10-29 12:30 UTC" in client.get("/step/admins").get_data(as_text=True)
