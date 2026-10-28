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
    "/step/service",
    "/system/config",
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
