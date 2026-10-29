"""ACME objects, and the drill-down from an account to its orders, authorizations, challenges and certificate."""

from dataclasses import dataclass
from datetime import UTC, datetime

from app.stepca import store
from app.stepca.records import AcmeAccount, AcmeAuthorization, AcmeCertificate, AcmeChallenge, AcmeOrder

OLDEST = datetime.min.replace(tzinfo=UTC)


def newest_first(records):
    return sorted(records, key=lambda record: record.created_at or OLDEST, reverse=True)


@dataclass(frozen=True)
class AuthorizationView:
    authorization: AcmeAuthorization
    challenges: list[AcmeChallenge]


@dataclass(frozen=True)
class OrderView:
    order: AcmeOrder
    account: AcmeAccount | None
    authorizations: list[AuthorizationView]
    certificate: AcmeCertificate | None


@dataclass(frozen=True)
class OrderRow:
    order: AcmeOrder
    certificate_serial: str | None


def _certificate_serials():
    """ACME certificate id -> decimal serial, to link to the certificate page."""
    return {cert.id: cert.serial for cert in store.acme_certificates()}


def accounts():
    return newest_first(store.acme_accounts())


def account(account_id):
    """(the account, its orders with their certificate's serial), or None."""
    found = store.acme_account(account_id)
    if found is None:
        return None
    serials = _certificate_serials()
    orders = [OrderRow(o, serials.get(o.certificate_id)) for o in newest_first(store.acme_orders()) if o.account_id == account_id]
    return found, orders


def orders():
    serials = _certificate_serials()
    return [OrderRow(order, serials.get(order.certificate_id)) for order in newest_first(store.acme_orders())]


def order(order_id):
    found = store.acme_order(order_id)
    if found is None:
        return None
    authorizations = {a.id: a for a in store.acme_authorizations(found.authorization_ids)}
    challenge_ids = [cid for a in authorizations.values() for cid in a.challenge_ids]
    challenges = {c.id: c for c in store.acme_challenges(challenge_ids)}
    certificates = store.acme_certificates([found.certificate_id]) if found.certificate_id else []
    return OrderView(
        order=found,
        account=store.acme_account(found.account_id),
        # In the order's own order, like the challenges of each authorization
        authorizations=[
            AuthorizationView(authorizations[aid], [challenges[cid] for cid in authorizations[aid].challenge_ids if cid in challenges])
            for aid in found.authorization_ids
            if aid in authorizations
        ],
        certificate=certificates[0] if certificates else None,
    )


def authorizations():
    """[(authorization, id of its order or None)]"""
    order_of = {aid: o.id for o in store.acme_orders() for aid in o.authorization_ids}
    return [(a, order_of.get(a.id)) for a in newest_first(store.acme_authorizations())]


def challenges():
    """[(challenge, id of its order or None)]"""
    orders_by_authz = {aid: o.id for o in store.acme_orders() for aid in o.authorization_ids}
    order_of = {cid: orders_by_authz.get(a.id) for a in store.acme_authorizations() for cid in a.challenge_ids}
    return [(c, order_of.get(c.id)) for c in newest_first(store.acme_challenges())]


def certificates():
    return newest_first(store.acme_certificates())


def order_id_for_serial(serial):
    """The ACME order that issued the certificate with this decimal serial, if any."""
    certificate_id = store.acme_certificate_id_by_serial(serial)
    if not certificate_id:
        return None
    certificates = store.acme_certificates([certificate_id])
    return certificates[0].order_id if certificates else None
