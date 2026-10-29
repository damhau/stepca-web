"""ACME lists and the drill-down, on rows in step-ca's format."""

import json

import pytest

from app.services import acme


@pytest.fixture
def issued(step_db):
    step_db.add_provisioner("prov-acme", "acme", prov_type=6)
    step_db.add_cert(5001, "web.test", provisioner={"id": "prov-acme", "name": "acme", "type": "ACME"})
    return step_db.add_acme_issuance(5001, "web.test")


def test_order_view_links_everything(issued):
    view = acme.order(issued["order"])
    assert view.account.contact == ["ops@example.org"]
    assert [i.value for i in view.order.identifiers] == ["web.test"]
    (authorization,) = view.authorizations
    assert [(c.type, c.status) for c in authorization.challenges] == [("dns-01", "pending"), ("http-01", "valid"), ("tls-alpn-01", "pending")]
    assert view.certificate.serial == "5001"
    # Go's zero time is "never", an empty validatedAt is no date
    assert view.account.deactivated_at is None
    assert authorization.challenges[0].validated_at is None


def test_account_page_lists_its_orders(client, issued):
    html = client.get(f"/acme/account/{issued['account']}").get_data(as_text=True)
    assert "ops@example.org" in html
    assert f'href="/acme/order/{issued["order"]}"' in html
    assert 'href="/x509/cert/5001"' in html


def test_order_page(client, issued):
    html = client.get(f"/acme/order/{issued['order']}").get_data(as_text=True)
    assert "Authorization for web.test" in html
    assert "http-01" in html and "2026-10-29 14:28 UTC" in html
    assert f'href="/acme/account/{issued["account"]}"' in html
    assert 'href="/x509/cert/5001"' in html


@pytest.mark.parametrize("path, target", [("/acme/authzs", "order"), ("/acme/challenges", "order"), ("/acme/certs", "order"), ("/acme/orders", "order")])
def test_lists_link_to_the_order(client, issued, path, target):
    assert f'href="/acme/order/{issued[target]}"' in client.get(path).get_data(as_text=True)


def test_accounts_list_links_to_the_account(client, issued):
    assert f'href="/acme/account/{issued["account"]}"' in client.get("/acme/accounts").get_data(as_text=True)


def test_certificate_page_links_to_its_acme_order(client, issued):
    assert f'href="/acme/order/{issued["order"]}"' in client.get("/x509/cert/5001").get_data(as_text=True)


@pytest.mark.parametrize("path", ["/acme/account/missing", "/acme/order/missing"])
def test_unknown_ids_redirect(client, step_db, path):
    response = client.get(path, follow_redirects=True)
    assert "not found" in response.get_data(as_text=True)


def test_api_returns_records(client, issued):
    (order,) = json.loads(client.get("/api/acme/orders").data)
    assert order["id"] == issued["order"] and order["status"] == "valid"
    assert order["created_at"] == "2026-10-29T14:28:37+00:00"


def test_a_row_that_does_not_parse_is_skipped(step_db, issued, caplog):
    from app.extensions import db
    from app.models import acme as tables

    db.session.add(tables.AcmeOrder(nkey=b"broken", nvalue=b"{not json"))
    db.session.commit()
    assert [row.order.id for row in acme.orders()] == [issued["order"]]
    assert "Cannot parse a row of acme_orders" in caplog.text
