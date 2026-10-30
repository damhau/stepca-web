"""The certificate inventory: kept in step with step-ca's tables, filtered, sorted and paged in SQL."""

import datetime
from unittest import mock

import pytest

from app.extensions import db
from app.models.inventory import InventoryCertificate
from app.models.x509 import X509Cert
from app.services import inventory
from app.services.inventory import CertificateQuery
from app.stepca import store

NOW = datetime.datetime.now(datetime.UTC)


def serials(query=None, **kwargs):
    items, _ = inventory.certificates(query or CertificateQuery(**kwargs), per_page=None)
    return [item.serial for item in items]


@pytest.fixture
def certificates(step_db):
    """Valid, expiring, expired, not yet valid and revoked certificates."""
    yesterday = NOW - datetime.timedelta(days=1)
    step_db.add_cert(1, "valid.test", days_valid=200, not_before=yesterday)
    step_db.add_cert(2, "expiring.test", days_valid=106, not_before=NOW - datetime.timedelta(days=100))
    step_db.add_cert(3, "expired.test", days_valid=1, not_before=NOW - datetime.timedelta(days=10))
    step_db.add_cert(4, "future.test", days_valid=30, not_before=NOW + datetime.timedelta(days=2))
    step_db.add_cert(5, "revoked.test", days_valid=200, not_before=yesterday)
    step_db.add_revocation(5)
    return step_db


def test_new_certificates_are_parsed_once(app, certificates):
    assert inventory.refresh() == 6  # 5 certificates and 1 revocation
    with mock.patch.object(store, "certificates", wraps=store.certificates) as read:
        assert inventory.refresh() == 0
        read.assert_not_called()
        certificates.add_cert(6, "new.test")
        assert inventory.refresh() == 1
        # Only the new certificate is read
        assert read.call_args.args[0] == ["6"]


def test_refresh_is_throttled(app, certificates):
    app.extensions["inventory"].refresh_seconds = 60
    assert inventory.refresh() == 6
    certificates.add_cert(6, "new.test")
    assert inventory.refresh() == 0
    assert inventory.refresh(force=True) == 1


def test_one_thread_refreshes_at_a_time(app, certificates):
    with app.extensions["inventory"].lock:
        assert inventory.refresh(force=True) == 0
    assert inventory.refresh(force=True) == 6


def test_rows_step_ca_no_longer_has_are_dropped(app, certificates):
    inventory.refresh()
    db.session.delete(db.session.get(X509Cert, b"3"))
    db.session.commit()
    inventory.refresh(force=True)
    assert "3" not in serials()


def test_status_filters(app, certificates):
    assert serials(status="valid", sort="serial", order="asc") == ["1", "2"]
    assert serials(status="expiring", days=30) == ["2"]
    assert serials(status="expired") == ["3"]
    assert serials(status="not_yet_valid") == ["4"]
    assert serials(status="revoked") == ["5"]
    assert sorted(serials()) == ["1", "2", "3", "4", "5"]
    statuses = {item.serial: item.status for item in inventory.certificates(CertificateQuery(), per_page=None)[0]}
    assert statuses == {"1": "valid", "2": "valid", "3": "expired", "4": "not_yet_valid", "5": "revoked"}


def test_revoked_items_carry_the_revocation(app, certificates):
    item = inventory.certificate("5")
    assert item.revoked_at == datetime.datetime(2026, 10, 28, 12, tzinfo=datetime.UTC)
    assert item.revocation_reason_code == 1
    assert inventory.certificate("1").revoked_at is None


def test_text_filter_matches_subject_names_and_serials(app, certificates):
    certificates.add_cert(0xABCDEF0123, "hex.test")
    assert serials(q="EXPIRING") == ["2"]
    assert serials(q="future.te") == ["4"]
    assert serials(q=str(0xABCDEF0123)) == [str(0xABCDEF0123)]
    # Hex, as people paste it
    assert serials(q="ab:cd:ef:01") == [str(0xABCDEF0123)]
    assert serials(q="0xABCDEF") == [str(0xABCDEF0123)]
    # LIKE wildcards are matched literally
    assert serials(q="%") == []
    assert serials(q="_") == []


def test_provisioner_filter_and_names(app, certificates):
    certificates.add_cert(9, "acme.test", provisioner={"id": "prov-acme", "name": "acme", "type": "ACME"})
    assert serials(provisioners=("acme",)) == ["9"]
    assert inventory.facets() == {"provisioners": ["Admin JWK", "acme"], "keys": ["secp256r1"]}


def test_sort_and_pages(app, certificates):
    query = CertificateQuery(sort="not_after", order="asc")
    first, total = inventory.certificates(query, page=1, per_page=2)
    second, _ = inventory.certificates(query, page=2, per_page=2)
    assert total == 5
    # 1 and 5 expire at the same time: the serial breaks the tie
    assert [item.serial for item in first] == ["3", "2"]
    assert [item.serial for item in second] == ["4", "1"]
    assert serials(sort="not_after", order="desc") == ["1", "5", "4", "2", "3"]


def test_counts(app, certificates):
    certificates.add_cert(9, "unknown.test", days_valid=100, provisioner=None)
    # Short-lived: never counted as expiring
    certificates.add_cert(10, "daily.test", days_valid=1, not_before=NOW - datetime.timedelta(hours=2))
    counts = inventory.counts(expiring_days=30)
    assert (counts.total, counts.valid, counts.expiring, counts.expired, counts.revoked) == (7, 4, 1, 1, 1)
    assert counts.by_provisioner == [("Admin JWK", 6), ("Unknown", 1)]
    expiring = {item.serial for item in inventory.certificates(CertificateQuery(), per_page=None)[0] if item.expiring}
    assert expiring == {"2"}


def test_unparseable_certificates_are_kept(app, step_db):
    db.session.add(X509Cert(nkey=b"77", nvalue=b"not DER"))
    db.session.commit()
    (item,) = inventory.certificates(CertificateQuery(), per_page=None)[0]
    assert item.status == "invalid" and item.error
    assert serials(status="valid") == []


def test_pending_while_it_is_built(app, certificates):
    assert inventory.pending() == 5
    inventory.refresh()
    assert inventory.pending() == 0


def test_keys_are_stored_readably(app, step_db):
    step_db.add_cert(1, "ec.test")
    inventory.refresh()
    assert db.session.get(InventoryCertificate, "1").key == "secp256r1"
