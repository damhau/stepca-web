"""The global search."""

import pytest

from app.services import search
from app.services.inventory import hex_serial


@pytest.fixture
def populated(step_db):
    step_db.add_cert(0xABCDEF0123, "db1.prod.example.org")
    step_db.add_cert(1002, "web.test")
    step_db.add_provisioner("prov-acme", "acme-prod", prov_type=6)
    step_db.add_admin("adm-1", "alice@example.org", "prov-admin-jwk")
    step_db.add_acme_issuance(1002, "web.test")


@pytest.mark.parametrize("text, normalised", [("AB:CD:EF:01:23", "abcdef0123"), ("0xabcdef0123", "abcdef0123"), ("00ab cd", "abcd"), ("zz", None)])
def test_hex_serials_as_people_paste_them(text, normalised):
    assert hex_serial(text) == normalised


@pytest.mark.parametrize(
    "query, kind, expected",
    [
        (str(0xABCDEF0123), "certificates", [str(0xABCDEF0123)]),  # decimal serial
        ("ab:cd:ef:01:23", "certificates", [str(0xABCDEF0123)]),  # hex, as openssl prints it
        ("prod.example", "certificates", [str(0xABCDEF0123)]),  # DNS name
        ("ops@example", "acme_accounts", ["a-account"]),  # ACME contact
        ("web.test", "acme_orders", ["a-order"]),  # ACME identifier
        ("acme-pr", "provisioners", ["acme-prod"]),
        ("alice", "admins", ["alice@example.org"]),
    ],
)
def test_finds(populated, query, kind, expected):
    found = getattr(search.search(query), kind)
    keys = {
        "certificates": lambda c: c.serial,
        "acme_accounts": lambda a: a.id,
        "acme_orders": lambda o: o.id,
        "provisioners": lambda p: p.name,
        "admins": lambda row: row[0].subject,
    }
    assert [keys[kind](item) for item in found] == expected


def test_needs_two_characters(populated):
    assert search.search(" w ").count == 0


def test_results_are_limited(populated, step_db, monkeypatch):
    monkeypatch.setattr(search, "LIMIT", 1)
    results = search.search("cn=")  # both certificates' subjects
    assert len(results.certificates) == 1 and "certificates" in results.truncated


def test_search_api(api, populated):
    body = api.get("/api/v1/search?q=web.test").get_json()
    assert [cert["serial"] for cert in body["certificates"]] == ["1002"]
    assert [order["id"] for order in body["acme_orders"]] == ["a-order"]


def test_nothing_found(api, populated):
    body = api.get("/api/v1/search?q=no-such-host").get_json()
    assert all(body[kind] == [] for kind in ("certificates", "acme_accounts", "acme_orders", "provisioners", "admins"))
