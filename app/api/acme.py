"""ACME accounts, orders, authorizations, challenges and certificates, read from step-ca's tables."""

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


def listing(query: AcmeListQuery, model, rows, text, filename, columns):
    """One page of rows (dicts) that contain the query's text and have its status, or all of them as CSV."""
    rows = [row for row in rows if contains(query.q, *text(row)) and (not query.status or row.get("status") == query.status)]
    if query.format == "csv":
        return csv_response(filename, columns, rows)
    items, total = paginate(rows, query)
    return page(model, items, total, query)


@bp.get("/acme/accounts", responses={200: AcmeAccountPage})
def accounts(query: AcmeListQuery):
    rows = [asdict(account) for account in acme.accounts()]
    columns = [(name, attribute(name)) for name in ("id", "status", "contact", "provisioner_name", "created_at", "deactivated_at")]
    return listing(query, AcmeAccountPage, rows, lambda row: [row["id"], *row["contact"], row["provisioner_name"]], "acme-accounts.csv", columns)


@bp.get("/acme/accounts/<id>", responses={200: AcmeAccountDetail, 404: Error})
def account(path: IdPath):
    found = acme.account(path.id)
    if found is None:
        return error(f"ACME account {path.id} not found.", 404)
    account, orders = found
    return dump(AcmeAccountDetail, {"account": account, "orders": [order_item(row) for row in orders]})


@bp.get("/acme/orders", responses={200: AcmeOrderPage})
def orders(query: AcmeListQuery):
    rows = [order_item(row) for row in acme.orders()]
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
    return listing(query, AcmeOrderPage, rows, lambda row: [row["id"], row["account_id"], *identifiers(row)], "acme-orders.csv", columns)


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
    rows = [{**asdict(authorization), "order_id": order_id} for authorization, order_id in acme.authorizations()]
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
    return listing(query, AcmeAuthorizationPage, rows, lambda row: [row["id"], row["identifier"]["value"], row["order_id"]], "acme-authorizations.csv", columns)


@bp.get("/acme/challenges", responses={200: AcmeChallengePage})
def challenges(query: AcmeListQuery):
    rows = [{**asdict(challenge), "order_id": order_id} for challenge, order_id in acme.challenges()]
    columns = [(name, attribute(name)) for name in ("id", "type", "value", "status", "validated_at", "created_at", "order_id", "error")]
    return listing(query, AcmeChallengePage, rows, lambda row: [row["id"], row["type"], row["value"], row["order_id"]], "acme-challenges.csv", columns)


@bp.get("/acme/certificates", responses={200: AcmeCertificatePage})
def certificates(query: AcmeListQuery):
    rows = [certificate_item(cert) for cert in acme.certificates()]
    columns = [(name, attribute(name)) for name in ("id", "serial", "subject", "dns_names", "not_before", "not_after", "order_id", "account_id", "created_at")]
    return listing(query, AcmeCertificatePage, rows, lambda row: [row["id"], row["serial"], row["subject"], *row["dns_names"], row["order_id"]], "acme-certificates.csv", columns)
