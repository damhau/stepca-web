"""The app's copy of step-ca's ACME orders, authorizations, challenges and certificates.

step-ca keeps every ACME object forever, and each renewal adds an order, its authorizations, three challenges
each and a certificate: cert-manager renewing 24-hour certificates leaves some 550 orders a year per
certificate. So the ACME pages read this copy, filtered, sorted and paged in SQL, instead of every row of
step-ca's tables. It is kept current with the certificate inventory (inventory.refresh):

- new and deleted objects are found from the table keys, when a table's size changed (and at start-up);
- objects that can still change are read again each time. step-ca's orders and authorizations change until
  they are valid or invalid; a challenge until it is, or its authorization is (each authorization keeps its
  unused challenges pending forever). ACME certificates never change.

ACME accounts are few and are still read from step-ca's table.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Select, delete, func, or_, select, update

from app.extensions import db
from app.models.inventory import (
    InventoryAcmeAuthorization,
    InventoryAcmeAuthorizationChallenge,
    InventoryAcmeCertificate,
    InventoryAcmeChallenge,
    InventoryAcmeOrder,
    InventoryAcmeOrderAuthorization,
)
from app.services.inventory import BATCH, aware, chunks, insert_new, like_pattern, naive_utc
from app.stepca import store
from app.stepca.records import AcmeAuthorization, AcmeCertificate, AcmeChallenge, AcmeIdentifier, AcmeOrder

log = logging.getLogger(__name__)

# The statuses step-ca still moves objects out of (acme/order.go, authorization.go, challenge.go)
ORDER_OPEN = ("pending", "ready", "processing")
AUTHORIZATION_OPEN = ("pending",)
CHALLENGE_OPEN = ("pending", "processing")


def _search(*values):
    return " ".join(value for value in values if value).lower()


def _order_row(order: AcmeOrder):
    return {
        "id": order.id,
        "account_id": order.account_id,
        "provisioner_id": order.provisioner_id,
        "identifiers": [{"type": i.type, "value": i.value} for i in order.identifiers],
        "authorization_ids": list(order.authorization_ids),
        "status": order.status,
        "certificate_id": order.certificate_id,
        "not_before": naive_utc(order.not_before),
        "not_after": naive_utc(order.not_after),
        "created_at": naive_utc(order.created_at),
        "expires_at": naive_utc(order.expires_at),
        "error": order.error,
        "search": _search(order.id, order.account_id, *(i.value for i in order.identifiers)),
    }


def _authorization_row(authorization: AcmeAuthorization):
    return {
        "id": authorization.id,
        "account_id": authorization.account_id,
        "identifier_type": authorization.identifier.type,
        "identifier_value": authorization.identifier.value,
        "status": authorization.status,
        "wildcard": authorization.wildcard,
        "challenge_ids": list(authorization.challenge_ids),
        "created_at": naive_utc(authorization.created_at),
        "expires_at": naive_utc(authorization.expires_at),
        "error": authorization.error,
        "search": _search(authorization.id, authorization.identifier.value),
    }


def _challenge_row(challenge: AcmeChallenge):
    return {
        "id": challenge.id,
        "account_id": challenge.account_id,
        "type": challenge.type,
        "status": challenge.status,
        "value": challenge.value,
        "validated_at": naive_utc(challenge.validated_at),
        "created_at": naive_utc(challenge.created_at),
        "error": challenge.error,
        "search": _search(challenge.id, challenge.type, challenge.value),
    }


def _leaf_time(value):
    return naive_utc(datetime.fromisoformat(value)) if value else None


def _certificate_row(certificate: AcmeCertificate):
    leaf = certificate.leaf
    dns_names = leaf.get("dns_names") or []
    return {
        "id": certificate.id,
        "account_id": certificate.account_id,
        "order_id": certificate.order_id,
        "created_at": naive_utc(certificate.created_at),
        "serial": leaf.get("serial_dec"),
        "subject": leaf.get("subject"),
        "dns_names": dns_names,
        "not_before": _leaf_time(leaf.get("not_before")),
        "not_after": _leaf_time(leaf.get("not_after")),
        "error": leaf.get("error"),
        "search": _search(certificate.id, leaf.get("serial_dec"), leaf.get("subject"), *dns_names, certificate.order_id),
    }


# --- Keeping the copy current ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Kind:
    name: str  # store.ACME_TABLES key
    model: Any
    read: Callable[[list[str]], list]
    to_row: Callable[[Any], dict]
    # (link model, its rows) for a batch of records, and how to drop a deleted batch's links
    links: Callable[[list], tuple[Any, list[dict]]] | None = None
    unlink: Callable[[list[str]], Any] | None = None
    # The ids of copied objects that can still change, read again on each sync
    open_ids: Callable[[], Select] | None = None


def _open_challenges():
    challenge, link, authorization = InventoryAcmeChallenge, InventoryAcmeAuthorizationChallenge, InventoryAcmeAuthorization
    return (
        select(challenge.id)
        .outerjoin(link, link.challenge_id == challenge.id)
        .outerjoin(authorization, authorization.id == link.authorization_id)
        .where(
            challenge.status.in_(CHALLENGE_OPEN),
            or_(authorization.id.is_(None), authorization.status.in_(AUTHORIZATION_OPEN)),
        )
    )


KINDS = [
    Kind(
        "orders",
        InventoryAcmeOrder,
        store.acme_orders,
        _order_row,
        links=lambda orders: (
            InventoryAcmeOrderAuthorization,
            [{"authorization_id": aid, "order_id": order.id} for order in orders for aid in order.authorization_ids],
        ),
        unlink=lambda ids: delete(InventoryAcmeOrderAuthorization).where(InventoryAcmeOrderAuthorization.order_id.in_(ids)),
        open_ids=lambda: select(InventoryAcmeOrder.id).where(InventoryAcmeOrder.status.in_(ORDER_OPEN)),
    ),
    # Before the challenges: whether a challenge can still change depends on its authorization
    Kind(
        "authorizations",
        InventoryAcmeAuthorization,
        store.acme_authorizations,
        _authorization_row,
        links=lambda authorizations: (
            InventoryAcmeAuthorizationChallenge,
            [{"challenge_id": cid, "authorization_id": a.id} for a in authorizations for cid in a.challenge_ids],
        ),
        unlink=lambda ids: delete(InventoryAcmeAuthorizationChallenge).where(InventoryAcmeAuthorizationChallenge.authorization_id.in_(ids)),
        open_ids=lambda: select(InventoryAcmeAuthorization.id).where(InventoryAcmeAuthorization.status.in_(AUTHORIZATION_OPEN)),
    ),
    Kind("challenges", InventoryAcmeChallenge, store.acme_challenges, _challenge_row, open_ids=_open_challenges),
    Kind("certificates", InventoryAcmeCertificate, store.acme_certificates, _certificate_row),
]


def _sync(kind: Kind, force):
    """Read again the objects that can still change, then add the new ones and drop the deleted ones. Returns the number added."""
    model = kind.model
    if kind.open_ids is not None:
        for batch in chunks(db.session.scalars(kind.open_ids()), BATCH):
            rows = [kind.to_row(record) for record in kind.read(batch)]
            if rows:
                db.session.execute(update(model), rows)
            db.session.commit()
    # A deletion and an addition between two syncs cancel out until the next addition: step-ca never deletes
    # ACME objects, only someone pruning its database does
    if not force and db.session.scalar(select(func.count()).select_from(model)) == store.acme_count(kind.name):
        return 0
    wanted = store.acme_ids(kind.name)
    cached = set(db.session.scalars(select(model.id)))
    gone = cached - wanted
    for batch in chunks(gone, BATCH):
        db.session.execute(delete(model).where(model.id.in_(batch)))
        if kind.unlink is not None:
            db.session.execute(kind.unlink(batch))
    new = wanted - cached
    for batch in chunks(new, BATCH):
        records = kind.read(batch)
        insert_new(model, [kind.to_row(record) for record in records])
        if kind.links is not None:
            link_model, link_rows = kind.links(records)
            insert_new(link_model, link_rows)
        db.session.commit()
    db.session.commit()
    if new or gone:
        log.info("Inventory %s: %d added, %d removed", model.__tablename__, len(new), len(gone))
    return len(new)


def sync(force=False):
    """Bring the copy up to date with step-ca's ACME tables (called by inventory.refresh). Returns the number of objects added."""
    return sum(_sync(kind, force) for kind in KINDS)


def pending(kind):
    """Objects of this kind step-ca has that the copy doesn't have yet (while it is being built)."""
    model = next(k.model for k in KINDS if k.name == kind)
    return max(store.acme_count(kind) - (db.session.scalar(select(func.count()).select_from(model)) or 0), 0)


# --- Reading --------------------------------------------------------------------------------------------


def _order(row: InventoryAcmeOrder):
    return AcmeOrder(
        id=row.id,
        account_id=row.account_id,
        provisioner_id=row.provisioner_id,
        identifiers=[AcmeIdentifier(type=i.get("type", ""), value=i.get("value", "")) for i in row.identifiers],
        authorization_ids=list(row.authorization_ids),
        status=row.status,
        certificate_id=row.certificate_id,
        not_before=aware(row.not_before),
        not_after=aware(row.not_after),
        created_at=aware(row.created_at),
        expires_at=aware(row.expires_at),
        error=row.error,
    )


def _authorization(row: InventoryAcmeAuthorization):
    return AcmeAuthorization(
        id=row.id,
        account_id=row.account_id,
        identifier=AcmeIdentifier(type=row.identifier_type, value=row.identifier_value),
        status=row.status,
        wildcard=row.wildcard,
        challenge_ids=list(row.challenge_ids),
        created_at=aware(row.created_at),
        expires_at=aware(row.expires_at),
        error=row.error,
    )


def _challenge(row: InventoryAcmeChallenge):
    return AcmeChallenge(
        id=row.id,
        account_id=row.account_id,
        type=row.type,
        status=row.status,
        value=row.value,
        validated_at=aware(row.validated_at),
        created_at=aware(row.created_at),
        error=row.error,
    )


def _certificate(row: InventoryAcmeCertificate):
    """As the API's AcmeCertificateItem."""
    return {
        "id": row.id,
        "account_id": row.account_id,
        "order_id": row.order_id,
        "created_at": aware(row.created_at),
        "serial": row.serial,
        "subject": row.subject,
        "dns_names": list(row.dns_names),
        "not_before": aware(row.not_before),
        "not_after": aware(row.not_after),
        "error": row.error,
    }


@dataclass(frozen=True)
class ListQuery:
    q: str = ""
    status: str | None = None
    page: int = 1
    # None: every matching row (CSV export)
    per_page: int | None = 50


def _matching(text: str, *columns):
    """Rows where any of the columns contains the text, ignoring case."""
    needle = text.strip().lower()
    if not needle:
        return None
    pattern = like_pattern(needle)
    return or_(*(func.lower(column).like(pattern, escape="\\") for column in columns))


def _page(statement, query: ListQuery, *order_by):
    """(rows of the page, total matching), newest first."""
    total = db.session.scalar(select(func.count()).select_from(statement.subquery())) or 0
    statement = statement.order_by(*order_by)
    if query.per_page is not None:
        statement = statement.limit(query.per_page).offset((query.page - 1) * query.per_page)
    return db.session.execute(statement).all(), total


def orders(query: ListQuery, account_id=None):
    """([(order, its certificate's decimal serial or None)], total), newest first."""
    order, certificate = InventoryAcmeOrder, InventoryAcmeCertificate
    statement = select(order, certificate.serial).outerjoin(certificate, certificate.id == order.certificate_id)
    if (text := _matching(query.q, order.search)) is not None:
        statement = statement.where(text)
    if query.status:
        statement = statement.where(order.status == query.status)
    if account_id is not None:
        statement = statement.where(order.account_id == account_id)
    rows, total = _page(statement, query, order.created_at.desc().nulls_last(), order.id)
    return [(_order(row), serial) for row, serial in rows], total


def authorizations(query: ListQuery):
    """([(authorization, id of its order or None)], total), newest first."""
    authorization, link = InventoryAcmeAuthorization, InventoryAcmeOrderAuthorization
    statement = select(authorization, link.order_id).outerjoin(link, link.authorization_id == authorization.id)
    if (text := _matching(query.q, authorization.search, link.order_id)) is not None:
        statement = statement.where(text)
    if query.status:
        statement = statement.where(authorization.status == query.status)
    rows, total = _page(statement, query, authorization.created_at.desc().nulls_last(), authorization.id)
    return [(_authorization(row), order_id) for row, order_id in rows], total


def challenges(query: ListQuery):
    """([(challenge, id of its order or None)], total), newest first."""
    challenge, link, order_link = InventoryAcmeChallenge, InventoryAcmeAuthorizationChallenge, InventoryAcmeOrderAuthorization
    statement = (
        select(challenge, order_link.order_id)
        .outerjoin(link, link.challenge_id == challenge.id)
        .outerjoin(order_link, order_link.authorization_id == link.authorization_id)
    )
    if (text := _matching(query.q, challenge.search, order_link.order_id)) is not None:
        statement = statement.where(text)
    if query.status:
        statement = statement.where(challenge.status == query.status)
    rows, total = _page(statement, query, challenge.created_at.desc().nulls_last(), challenge.id)
    return [(_challenge(row), order_id) for row, order_id in rows], total


def certificates(query: ListQuery):
    """([ACME certificate as the API's item], total), newest first."""
    certificate = InventoryAcmeCertificate
    statement = select(certificate)
    if (text := _matching(query.q, certificate.search)) is not None:
        statement = statement.where(text)
    rows, total = _page(statement, query, certificate.created_at.desc().nulls_last(), certificate.id)
    return [_certificate(row) for (row,) in rows], total


def failed_orders(since, names=None):
    """Invalid orders created after `since`, for any of these names if given, newest first."""
    order = InventoryAcmeOrder
    statement = select(order).where(order.status == "invalid", order.created_at > naive_utc(since))
    if names:
        # A first cut in SQL, then the exact match
        statement = statement.where(or_(*(order.search.like(like_pattern(name.lower()), escape="\\") for name in names)))
    found = [_order(row) for row in db.session.scalars(statement.order_by(order.created_at.desc()))]
    return [o for o in found if not names or names & {i.value for i in o.identifiers}]


def orders_by_status():
    """[(status, number of orders)], the most common first."""
    status = func.coalesce(func.nullif(InventoryAcmeOrder.status, ""), "unknown")
    rows = db.session.execute(select(status, func.count()).group_by(status).order_by(func.count().desc(), status)).all()
    return [(name, total) for name, total in rows]
