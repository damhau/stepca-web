"""ACME accounts, orders, authorizations, challenges and certificates. The lists read the app's copy of step-ca's
tables (services.acme_inventory), filtered and paged in SQL; accounts are few and read in full."""

from dataclasses import asdict

from app.api import attribute, blueprint, contains, csv_response, dump, error, page, paginate
from app.api.schemas import (
    AcmeAccountDetail,
    AcmeAccountPage,
    AcmeAuthorizationPage,
    AcmeCertificatePage,
    AcmeChallengePage,
    AcmeListQuery,
    AcmeOrderDetail,
    AcmeOrderPage,
    Error,
    IdPath,
)
from app.services import acme
from app.services.acme_inventory import ListQuery

bp = blueprint("api_acme", "ACME")


def order_item(row):
    return {**asdict(row.order), "certificate_serial": row.certificate_serial}


def certificate_item(cert):
    leaf = cert.leaf
    return {
        "id": cert.id,
        "account_id": cert.account_id,
        "order_id": cert.order_id,
        "created_at": cert.created_at,
        "serial": cert.serial,
        "subject": leaf.get("subject"),
        "dns_names": leaf.get("dns_names") or [],
        "not_before": leaf.get("not_before"),
        "not_after": leaf.get("not_after"),
        "error": leaf.get("error"),
    }


def identifiers(order):
    return [identifier["value"] for identifier in order["identifiers"]]


def list_query(query: AcmeListQuery):
    """What to read from the copy: this page, or every matching row for a CSV export."""
    return ListQuery(q=query.q, status=query.status, page=query.page, per_page=None if query.format == "csv" else query.per_page)


def listing(query: AcmeListQuery, model, kind, rows, total, filename, columns):
    """One page of rows (dicts), or all of them as CSV."""
    if query.format == "csv":
        return csv_response(filename, columns, rows)
    return page(model, rows, total, query, pending=acme.pending(kind))


@bp.get("/acme/accounts", responses={200: AcmeAccountPage})
def accounts(query: AcmeListQuery):
    rows = [asdict(account) for account in acme.accounts()]
    rows = [
        row
        for row in rows
        if contains(query.q, row["id"], *row["contact"], row["provisioner_name"]) and (not query.status or row["status"] == query.status)
    ]
    columns = [(name, attribute(name)) for name in ("id", "status", "contact", "provisioner_name", "created_at", "deactivated_at")]
    if query.format == "csv":
        return csv_response("acme-accounts.csv", columns, rows)
    items, total = paginate(rows, query)
    return page(AcmeAccountPage, items, total, query)


@bp.get("/acme/accounts/<id>", responses={200: AcmeAccountDetail, 404: Error})
def account(path: IdPath):
    found = acme.account(path.id)
    if found is None:
        return error(f"ACME account {path.id} not found.", 404)
    return dump(AcmeAccountDetail, {"account": found.account, "orders": [order_item(row) for row in found.orders], "order_total": found.order_total})


@bp.get("/acme/orders", responses={200: AcmeOrderPage})
def orders(query: AcmeListQuery):
    found, total = acme.orders(list_query(query))
    rows = [order_item(row) for row in found]
    columns = [
        ("id", attribute("id")),
        ("account_id", attribute("account_id")),
        ("identifiers", identifiers),
        ("status", attribute("status")),
        ("created_at", attribute("created_at")),
        ("expires_at", attribute("expires_at")),
        ("certificate_serial", attribute("certificate_serial")),
        ("error", attribute("error")),
    ]
    return listing(query, AcmeOrderPage, "orders", rows, total, "acme-orders.csv", columns)


@bp.get("/acme/orders/<id>", responses={200: AcmeOrderDetail, 404: Error})
def order(path: IdPath):
    found = acme.order(path.id)
    if found is None:
        return error(f"ACME order {path.id} not found.", 404)
    serial = found.certificate.serial if found.certificate else None
    return dump(
        AcmeOrderDetail,
        {
            "order": {**asdict(found.order), "certificate_serial": serial},
            "account": found.account,
            "authorizations": [
                {"authorization": {**asdict(view.authorization), "order_id": found.order.id}, "challenges": [{**asdict(c), "order_id": found.order.id} for c in view.challenges]}
                for view in found.authorizations
            ],
            "certificate": certificate_item(found.certificate) if found.certificate else None,
        },
    )


@bp.get("/acme/authorizations", responses={200: AcmeAuthorizationPage})
def authorizations(query: AcmeListQuery):
    found, total = acme.authorizations(list_query(query))
    rows = [{**asdict(authorization), "order_id": order_id} for authorization, order_id in found]
    columns = [
        ("id", attribute("id")),
        ("identifier", lambda row: row["identifier"]["value"]),
        ("status", attribute("status")),
        ("wildcard", attribute("wildcard")),
        ("created_at", attribute("created_at")),
        ("expires_at", attribute("expires_at")),
        ("order_id", attribute("order_id")),
        ("error", attribute("error")),
    ]
    return listing(query, AcmeAuthorizationPage, "authorizations", rows, total, "acme-authorizations.csv", columns)


@bp.get("/acme/challenges", responses={200: AcmeChallengePage})
def challenges(query: AcmeListQuery):
    found, total = acme.challenges(list_query(query))
    rows = [{**asdict(challenge), "order_id": order_id} for challenge, order_id in found]
    columns = [(name, attribute(name)) for name in ("id", "type", "value", "status", "validated_at", "created_at", "order_id", "error")]
    return listing(query, AcmeChallengePage, "challenges", rows, total, "acme-challenges.csv", columns)


@bp.get("/acme/certificates", responses={200: AcmeCertificatePage})
def certificates(query: AcmeListQuery):
    rows, total = acme.certificates(list_query(query))
    columns = [(name, attribute(name)) for name in ("id", "serial", "subject", "dns_names", "not_before", "not_after", "order_id", "account_id", "created_at")]
    return listing(query, AcmeCertificatePage, "certificates", rows, total, "acme-certificates.csv", columns)
