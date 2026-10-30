"""ACME objects, and the drill-down from an account to its orders, authorizations, challenges and certificate.

The lists read the app's copy of step-ca's ACME tables (acme_inventory); one account, one order and its
authorizations, challenges and certificate are read from step-ca's tables, as they are now."""

from dataclasses import dataclass
from datetime import UTC, datetime

from app.services import acme_inventory, inventory
from app.services.acme_inventory import ListQuery
from app.stepca import store
from app.stepca.records import AcmeAccount, AcmeAuthorization, AcmeCertificate, AcmeChallenge, AcmeOrder

OLDEST = datetime.min.replace(tzinfo=UTC)
# The orders an account's page shows; the orders list has every one
ACCOUNT_ORDERS = 50


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


@dataclass(frozen=True)
class AccountView:
    account: AcmeAccount
    # The latest ACCOUNT_ORDERS, and how many it has
    orders: list[OrderRow]
    order_total: int


def accounts():
    return newest_first(store.acme_accounts())


def account(account_id):
    found = store.acme_account(account_id)
    if found is None:
        return None
    inventory.refresh()
    rows, total = acme_inventory.orders(ListQuery(per_page=ACCOUNT_ORDERS), account_id=account_id)
    return AccountView(found, [OrderRow(order, serial) for order, serial in rows], total)


def orders(query: ListQuery):
    """([order rows], total)"""
    inventory.refresh()
    rows, total = acme_inventory.orders(query)
    return [OrderRow(order, serial) for order, serial in rows], total


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


def authorizations(query: ListQuery):
    """([(authorization, id of its order or None)], total)"""
    inventory.refresh()
    return acme_inventory.authorizations(query)


def challenges(query: ListQuery):
    """([(challenge, id of its order or None)], total)"""
    inventory.refresh()
    return acme_inventory.challenges(query)


def certificates(query: ListQuery):
    """([certificate items], total)"""
    inventory.refresh()
    return acme_inventory.certificates(query)


def pending(kind):
    return acme_inventory.pending(kind)


def order_id_for_serial(serial):
    """The ACME order that issued the certificate with this decimal serial, if any."""
    certificate_id = store.acme_certificate_id_by_serial(serial)
    if not certificate_id:
        return None
    certificates = store.acme_certificates([certificate_id])
    return certificates[0].order_id if certificates else None
