"""Render every page with data in the tables, to catch template and route errors."""

import re

import pytest

PAGES = [
    "/",
    "/x509/all",
    "/x509/active",
    "/x509/revoked",
    "/acme/accounts",
    "/acme/orders",
    "/acme/certs",
    "/acme/authzs",
    "/acme/challenges",
    "/step/provisioners",
    "/step/admins",
    "/system/config",
    "/system/audit",
    "/x509/expiring",
    "/x509/expiring?days=7",
    "/x509/cert/1001",
    "/api/x509/certs",
]


@pytest.fixture
def populated(step_db):
    step_db.add_cert(1001, "a.test")
    step_db.add_cert(1002, "b.test")
    step_db.add_cert(1003, "no-metadata.test", provisioner=None)
    step_db.add_revocation(1002)
    step_db.add_admin("adm-1", "step", "prov-admin-jwk")


@pytest.mark.parametrize("path", PAGES)
def test_page_renders(client, populated, path):
    response = client.get(path)
    assert response.status_code == 200, response.get_data(as_text=True)[:500]


def test_dashboard_counts(client, populated):
    html = client.get("/").get_data(as_text=True)
    tiles = dict((label, int(n)) for n, label in re.findall(r"<h3>(\d+)</h3>\s*<p>([^<]+)</p>", html))
    # 3 certificates, of which 1 is revoked
    assert tiles["Active Certificates"] == 2
    assert tiles["Revoked Certificates"] == 1
    assert tiles["Provisioners"] == 1


@pytest.mark.parametrize(
    "path",
    [
        "/x509/all",
        "/x509/active",
        "/x509/revoked",
        "/x509/expiring",
        "/acme/accounts",
        "/acme/orders",
        "/step/provisioners",
        "/step/admins",
        "/system/audit",
    ],
)
def test_lists_have_search_sort_and_paging(client, populated, path):
    html = client.get(path).get_data(as_text=True)
    assert "data-table-tools" in html
    assert '<script src="/static/assets/js/tables.js"></script>' in html


def test_pages_load_scripts_from_the_app_only(client, populated):
    for path in PAGES:
        html = client.get(path).get_data(as_text=True)
        assert "code.jquery.com" not in html and "cdn.jsdelivr.net" not in html, path
