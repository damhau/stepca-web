"""The app's copy of step-ca's ACME tables: what is copied, what is read again, what is left alone."""

import json

import pytest

from app.extensions import db
from app.models import acme as tables
from app.services import acme, acme_inventory


def edit(model, key, **changes):
    """Change a row of a step-ca table, as step-ca would."""
    row = db.session.get(model, key.encode())
    row.nvalue = json.dumps({**json.loads(bytes(row.nvalue)), **changes}).encode()
    db.session.commit()


def items(api, kind, query=""):
    return api.get(f"/api/v1/acme/{kind}{query}").get_json()["items"]


@pytest.fixture
def issued(step_db):
    step_db.add_provisioner("prov-acme", "acme", prov_type=6)
    return step_db.add_acme_issuance(5001, "web.test")


def test_objects_are_copied_with_the_order_they_belong_to(api, issued):
    (order,) = items(api, "orders")
    assert order["id"] == issued["order"] and order["certificate_serial"] == "5001"
    (authorization,) = items(api, "authorizations")
    assert authorization["order_id"] == issued["order"]
    assert {c["order_id"] for c in items(api, "challenges")} == {issued["order"]}
    (certificate,) = items(api, "certificates")
    assert (certificate["serial"], certificate["subject"], certificate["dns_names"]) == ("5001", "CN=web.test", ["web.test"])
    # An order's id finds its authorization and challenges
    assert len(items(api, "challenges", f"?q={issued['order']}")) == 3


def test_an_open_order_is_read_again_until_it_is_final(api, issued):
    edit(tables.AcmeOrder, issued["order"], status="pending")
    assert items(api, "orders")[0]["status"] == "pending"
    edit(tables.AcmeOrder, issued["order"], status="invalid", error={"detail": "dns-01 failed"})
    (order,) = items(api, "orders")
    assert (order["status"], order["error"]) == ("invalid", "dns-01 failed")
    # Final: step-ca never changes it again, so the copy doesn't read it again
    edit(tables.AcmeOrder, issued["order"], status="valid")
    assert items(api, "orders")[0]["status"] == "invalid"


def test_challenges_are_read_again_only_while_their_authorization_is_open(api, issued):
    edit(tables.AcmeAuthz, issued["authz"], status="pending")
    items(api, "challenges")
    # The authorization is open: a pending challenge that step-ca validates is updated
    edit(tables.AcmeChallenge, "a-challenge-dns", status="valid")
    assert {c["id"]: c["status"] for c in items(api, "challenges")}["a-challenge-dns"] == "valid"
    # Once it is valid, its unused challenges stay pending in step-ca forever, and are not read again
    edit(tables.AcmeAuthz, issued["authz"], status="valid")
    items(api, "authorizations")
    edit(tables.AcmeChallenge, "a-challenge-tls", status="valid")
    assert {c["id"]: c["status"] for c in items(api, "challenges")}["a-challenge-tls"] == "pending"


def test_new_and_deleted_objects(api, step_db, issued):
    assert len(items(api, "orders")) == 1
    other = step_db.add_acme_issuance(5002, "api.test", prefix="b")
    assert {o["id"] for o in items(api, "orders")} == {issued["order"], other["order"]}
    # Someone pruned step-ca's database: the order goes, and its authorization no longer points at it
    db.session.delete(db.session.get(tables.AcmeOrder, issued["order"].encode()))
    db.session.commit()
    assert [o["id"] for o in items(api, "orders")] == [other["order"]]
    assert {a["id"]: a["order_id"] for a in items(api, "authorizations")}[issued["authz"]] is None


def test_lists_are_filtered_sorted_and_paged_in_sql(api, step_db, issued):
    newer = step_db.add_acme_issuance(5002, "api.test", prefix="b")
    edit(tables.AcmeOrder, newer["order"], createdAt="2026-10-30T09:00:00Z", status="invalid")
    body = api.get("/api/v1/acme/orders?per_page=1").get_json()
    assert (body["total"], [o["id"] for o in body["items"]], body["pending"]) == (2, [newer["order"]], 0)
    assert [o["id"] for o in items(api, "orders", "?per_page=1&page=2")] == [issued["order"]]
    assert [o["id"] for o in items(api, "orders", "?status=invalid")] == [newer["order"]]
    # Ids are mixed case; the filter isn't
    assert [o["id"] for o in items(api, "orders", "?q=WEB.TEST")] == [issued["order"]]
    assert [o["id"] for o in items(api, "orders", f"?q={issued['account'].upper()}")] == [issued["order"]]
    csv = api.get("/api/v1/acme/orders?format=csv&per_page=1").get_data(as_text=True)
    assert len(csv.strip().splitlines()) == 3


def test_an_accounts_page_has_its_latest_orders(api, step_db, issued, monkeypatch):
    monkeypatch.setattr(acme, "ACCOUNT_ORDERS", 1)
    second = step_db.add_acme_issuance(5002, "api.test", prefix="b")
    edit(tables.AcmeOrder, second["order"], accountID=issued["account"], createdAt="2026-10-30T09:00:00Z")
    body = api.get(f"/api/v1/acme/accounts/{issued['account']}").get_json()
    assert ([o["id"] for o in body["orders"]], body["order_total"]) == ([second["order"]], 2)


def test_pending_counts_what_is_not_copied_yet(app, step_db, issued):
    assert acme_inventory.pending("orders") == 1
    acme_inventory.sync()
    assert acme_inventory.pending("orders") == 0


def test_failed_renewals_match_the_names_exactly(app, step_db, issued):
    from datetime import UTC, datetime

    edit(tables.AcmeOrder, issued["order"], status="invalid")
    acme_inventory.sync()
    since = datetime(2026, 10, 1, tzinfo=UTC)
    assert [o.id for o in acme_inventory.failed_orders(since, {"web.test"})] == [issued["order"]]
    # "web.test" contains "eb.test", which isn't one of the order's names
    assert acme_inventory.failed_orders(since, {"eb.test"}) == []
    assert acme_inventory.failed_orders(datetime(2026, 10, 30, tzinfo=UTC)) == []
