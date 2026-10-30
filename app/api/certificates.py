"""X.509 certificates: the inventory's lists, a certificate's page and downloads, signing and revoking.
Also the dashboard, the search and the forms' fixed choices."""

from dataclasses import asdict

from app.api import attribute, blueprint, csv_response, dump, error, file_response, page
from app.api.schemas import (
    BundleQuery,
    CertificateDetail,
    CertificateEvents,
    CertificateListQuery,
    CertificatePage,
    CsrBody,
    CsrDescription,
    Dashboard,
    DownloadQuery,
    Error,
    Facets,
    Overview,
    OverviewQuery,
    Readiness,
    Reference,
    RevokeBody,
    SearchQuery,
    SearchResults,
    SerialPath,
    SignBody,
    SignResult,
    StatusCounts,
    UnmatchedRevocationList,
)
from app.auth.roles import role_required
from app.libs.cert_utils import describe_csr
from app.libs.provisioners import ACME_CHALLENGES
from app.services import ca, certificates, dashboard, inventory, overview, provisioners
from app.services import search as search_service
from app.services.certificates import REVOCATION_REASONS
from app.stepca.client import SignError

bp = blueprint("api_certificates", "Certificates")

CSV_COLUMNS = [
    ("serial", attribute("serial")),
    ("serial_hex", attribute("serial_hex")),
    ("status", attribute("status")),
    ("subject", attribute("subject")),
    ("not_before", attribute("not_before")),
    ("not_after", attribute("not_after")),
    ("dns_names", attribute("dns_names")),
    ("key", attribute("key")),
    ("provisioner", attribute("provisioner_name")),
    ("revoked_at", attribute("revoked_at")),
    ("revocation_reason", attribute("revocation_reason")),
]


def _inventory_query(query: CertificateListQuery):
    return inventory.CertificateQuery(
        status=query.status,
        days=query.days,
        q=query.q,
        provisioners=tuple(query.provisioner),
        keys=tuple(query.key),
        sort=query.sort,
        order=query.order,
    )


@bp.get("/certificates", responses={200: CertificatePage}, summary="Certificates, filtered, sorted and paged (format=csv: all of them, as a file)")
def list_certificates(query: CertificateListQuery):
    if query.format == "csv":
        items, _ = certificates_matching(query, all_pages=True)
        return csv_response(f"certificates-{query.status}.csv", CSV_COLUMNS, items)
    items, total = certificates_matching(query)
    return page(CertificatePage, items, total, query, pending=inventory.pending())


def certificates_matching(query: CertificateListQuery, all_pages=False):
    return inventory.certificates(_inventory_query(query), page=query.page, per_page=None if all_pages else query.per_page)


@bp.get("/certificates/counts", responses={200: StatusCounts}, summary="How many certificates each tab of the list holds")
def certificate_counts():
    return dump(StatusCounts, inventory.status_counts())


@bp.get("/certificates/facets", responses={200: Facets}, summary="The values the list can be filtered on")
def certificate_facets():
    return dump(Facets, inventory.facets())


@bp.get("/certificates/bundle", responses={200: None, 404: Error}, summary="Several certificates as one PEM file")
def certificate_bundle(query: BundleQuery):
    pems = []
    for serial in dict.fromkeys(query.serial):
        found = certificates.download(serial, "pem", ca.client().intermediates)
        if found is None:
            return error(f"Certificate {serial} not found.", 404)
        pems.append(found[0])
    return file_response(b"".join(pems), f"certificates-{len(pems)}.pem", "application/x-pem-file")


@bp.get("/certificates/<serial>/events", responses={200: CertificateEvents, 404: Error}, summary="What happened to a certificate")
def certificate_events(path: SerialPath):
    events = overview.certificate_events(path.serial)
    if events is None:
        return error(f"Certificate {path.serial} not found.", 404)
    return dump(CertificateEvents, {"items": events})


@bp.get("/certificates/<serial>", responses={200: CertificateDetail, 404: Error})
def get_certificate(path: SerialPath):
    found = certificates.detail(path.serial)
    if found is None:
        return error(f"Certificate {path.serial} not found.", 404)
    return dump(CertificateDetail, found)


@bp.get("/certificates/<serial>/download", responses={200: None, 404: Error, 502: Error}, summary="PEM, DER, or PEM with the issuing intermediate")
def download_certificate(path: SerialPath, query: DownloadQuery):
    found = certificates.download(path.serial, query.format, ca.client().intermediates)
    if found is None:
        return error(f"Certificate {path.serial} not found.", 404)
    return file_response(*found)


@bp.post("/certificates/<serial>/revoke", responses={200: CertificateDetail, 404: Error, 422: Error, 502: Error})
@role_required("operator")
def revoke_certificate(path: SerialPath, body: RevokeBody):
    try:
        certificates.revoke(path.serial, body.reason_code)
    except LookupError as e:
        return error(str(e), 404)
    except ValueError as e:
        return error(str(e), 422)
    except (RuntimeError, *ca.CA_ERRORS) as e:
        return error(f"step-ca did not revoke the certificate: {e}", 502)
    return dump(CertificateDetail, certificates.detail(path.serial))


@bp.post("/certificates", responses={201: SignResult, 422: Error}, summary="Sign a CSR with a JWK provisioner")
@role_required("operator")
def sign_certificate(body: SignBody):
    try:
        signed = certificates.sign(body.csr_pem, body.provisioner, body.password, body.valid_for)
    except SignError as e:
        return error(f"The certificate was not signed: {e}.", 422)
    return dump(SignResult, signed), 201


@bp.get("/overview", responses={200: Overview}, summary="Figures over a time range, what needs attention, recent activity")
def get_overview(query: OverviewQuery):
    return dump(Overview, overview.overview(query.range))


@bp.get("/readiness", responses={200: Readiness}, summary="The deployment checked against the recommended setup")
def get_readiness():
    return dump(Readiness, overview.readiness())


@bp.post("/csr/preview", responses={200: CsrDescription, 422: Error}, summary="What a CSR asks for")
@role_required("operator")
def preview_csr(body: CsrBody):
    try:
        return dump(CsrDescription, describe_csr(body.csr_pem))
    except ValueError:
        return error("This is not a PEM certificate signing request.", 422)


@bp.get("/revocations/unmatched", responses={200: UnmatchedRevocationList}, summary="Revocations of serials step-ca never issued")
def unmatched_revocations():
    return dump(UnmatchedRevocationList, {"items": certificates.unmatched_revocations()})


@bp.get("/dashboard", responses={200: Dashboard})
def get_dashboard():
    return dump(Dashboard, dashboard.overview())


@bp.get("/reference", responses={200: Reference}, summary="The fixed choices of the forms")
def reference():
    return dump(
        Reference,
        {
            "revocation_reasons": [{"code": code, "name": name} for code, name in REVOCATION_REASONS],
            "acme_challenges": [{"value": value, "label": label} for value, label in ACME_CHALLENGES],
            "signing_provisioners": provisioners.signing_provisioners(),
        },
    )


@bp.get("/search", responses={200: SearchResults})
def search(query: SearchQuery):
    results = search_service.search(query.q)
    return dump(
        SearchResults,
        {
            "query": results.query,
            "certificates": results.certificates,
            "acme_accounts": results.acme_accounts,
            "acme_orders": [{**asdict(order), "certificate_serial": None} for order in results.acme_orders],
            "provisioners": results.provisioners,
            "admins": [{"id": admin.id, "subject": admin.subject, "provisioner_name": name, "type": admin.type} for admin, name in results.admins],
            "truncated": sorted(results.truncated),
        },
    )
