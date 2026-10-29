"""Reads step-ca's database. step-ca keeps each kind of object in a key/value table (nkey, nvalue), the
value being the JSON of a Go struct (see acme/db/nosql in step-ca). This module is the only place that
knows those tables and field names; it returns records.py dataclasses."""

import json
import logging
from datetime import datetime

from app.extensions import db
from app.libs.cert_utils import parse_cert
from app.models import acme as tables
from app.stepca.records import AcmeAccount, AcmeAuthorization, AcmeCertificate, AcmeChallenge, AcmeIdentifier, AcmeOrder

log = logging.getLogger(__name__)


def go_time(value):
    """A Go time.Time from JSON, or None for Go's zero time (step-ca's "never") and empty strings."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return None if parsed.year == 1 else parsed


def acme_error(value):
    """The detail of an acme.Error, or None."""
    if not value:
        return None
    return value.get("detail") or value.get("type") or "error"


def _rows(model, keys=None):
    """(key, decoded JSON) of the rows of a table, or of the rows with these keys. Rows that don't parse are logged and skipped."""
    query = db.session.query(model)
    if keys is not None:
        query = query.filter(model.nkey.in_([key.encode() for key in keys]))
    for row in query.all():
        try:
            yield bytes(row.nkey).decode(), json.loads(bytes(row.nvalue))
        except (ValueError, UnicodeDecodeError) as e:
            log.warning("Cannot parse a row of %s: %s", model.__tablename__, e)


def _row(model, key):
    row = db.session.get(model, key.encode())
    if row is None:
        return None
    try:
        return json.loads(bytes(row.nvalue))
    except ValueError as e:
        log.warning("Cannot parse %s %s: %s", model.__tablename__, key, e)
        return None


def _identifier(value):
    value = value or {}
    return AcmeIdentifier(type=value.get("type", ""), value=value.get("value", ""))


def _account(data):
    return AcmeAccount(
        id=data["id"],
        status=data.get("status", ""),
        contact=data.get("contact") or [],
        provisioner_id=data.get("provisionerID") or None,
        provisioner_name=data.get("provisionerName") or None,
        created_at=go_time(data.get("createdAt")),
        deactivated_at=go_time(data.get("deactivatedAt")),
    )


def _order(data):
    return AcmeOrder(
        id=data["id"],
        account_id=data.get("accountID", ""),
        provisioner_id=data.get("provisionerID") or None,
        identifiers=[_identifier(i) for i in data.get("identifiers") or []],
        authorization_ids=data.get("authorizationIDs") or [],
        status=data.get("status", ""),
        certificate_id=data.get("certificate") or None,
        not_before=go_time(data.get("notBefore")),
        not_after=go_time(data.get("notAfter")),
        created_at=go_time(data.get("createdAt")),
        expires_at=go_time(data.get("expiresAt")),
        error=acme_error(data.get("error")),
    )


def _authorization(data):
    return AcmeAuthorization(
        id=data["id"],
        account_id=data.get("accountID", ""),
        identifier=_identifier(data.get("identifier")),
        status=data.get("status", ""),
        wildcard=bool(data.get("wildcard")),
        challenge_ids=data.get("challengeIDs") or [],
        created_at=go_time(data.get("createdAt")),
        expires_at=go_time(data.get("expiresAt")),
        error=acme_error(data.get("error")),
    )


def _challenge(data):
    return AcmeChallenge(
        id=data["id"],
        account_id=data.get("accountID", ""),
        type=data.get("type", ""),
        status=data.get("status", ""),
        value=data.get("value", ""),
        validated_at=go_time(data.get("validatedAt")),
        created_at=go_time(data.get("createdAt")),
        error=acme_error(data.get("error")),
    )


def _certificate(data):
    return AcmeCertificate(
        id=data["id"],
        account_id=data.get("accountID", ""),
        order_id=data.get("orderID", ""),
        created_at=go_time(data.get("createdAt")),
        # leaf is the PEM chain, base64-encoded as Go encodes []byte
        leaf=parse_cert(data["leaf"]) if data.get("leaf") else {},
    )


def _records(model, build, keys=None):
    records = []
    for key, data in _rows(model, keys):
        try:
            records.append(build(data))
        except (KeyError, TypeError) as e:
            log.warning("Cannot read %s %s: %s", model.__tablename__, key, e)
    return records


def acme_accounts():
    return _records(tables.AcmeAccount, _account)


def acme_account(account_id):
    data = _row(tables.AcmeAccount, account_id)
    return _account(data) if data else None


def acme_orders():
    return _records(tables.AcmeOrder, _order)


def acme_order(order_id):
    data = _row(tables.AcmeOrder, order_id)
    return _order(data) if data else None


def acme_authorizations(ids=None):
    return _records(tables.AcmeAuthz, _authorization, ids)


def acme_challenges(ids=None):
    return _records(tables.AcmeChallenge, _challenge, ids)


def acme_certificates(ids=None):
    return _records(tables.AcmeCert, _certificate, ids)


def acme_certificate_id_by_serial(serial):
    """The ACME certificate that has this decimal serial, if it was issued over ACME."""
    data = _row(tables.AcmeSerialCert, serial)
    return data.get("certificateID") if data else None


def acme_certificate_count():
    return db.session.query(tables.AcmeCert).count()
