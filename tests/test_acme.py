"""ACME lists and the drill-down, on rows in step-ca's format."""

import pytest

from app.services import acme
from app.services.acme_inventory import ListQuery


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


def test_certificate_page_links_to_its_acme_order(api, issued):
    assert api.get("/api/v1/certificates/5001").get_json()["acme_order_id"] == issued["order"]


def test_lists_link_back_to_the_order(api, issued):
    for kind in ("authorizations", "challenges", "certificates"):
        (first, *_) = api.get(f"/api/v1/acme/{kind}").get_json()["items"]
        assert first["order_id"] == issued["order"], kind


def test_dates_are_iso_8601_in_utc(api, issued):
    (order,) = api.get("/api/v1/acme/orders").get_json()["items"]
    assert order["created_at"] in ("2026-10-29T14:28:37Z", "2026-10-29T14:28:37+00:00")


def test_a_row_that_does_not_parse_is_skipped(step_db, issued, caplog):
    from app.extensions import db
    from app.models import acme as tables

    db.session.add(tables.AcmeOrder(nkey=b"broken", nvalue=b"{not json"))
    db.session.commit()
    rows, total = acme.orders(ListQuery())
    assert [row.order.id for row in rows] == [issued["order"]] and total == 1
    assert "Cannot parse a row of acme_orders" in caplog.text
