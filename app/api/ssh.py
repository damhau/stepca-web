"""SSH certificates: the list (user and host certificates), a certificate's page and its *-cert.pub file. Read-only:
step-ca issues and revokes them itself (`step ssh certificate`, `step ssh revoke`)."""

from app.api import attribute, blueprint, csv_response, dump, error, file_response, page
from app.api.schemas import Error, SerialPath, SshCertificateDetail, SshCertificatePage, SshCounts, SshCountsQuery, SshListQuery
from app.services import ssh
from app.services.ssh import SshQuery

bp = blueprint("api_ssh", "SSH")

CSV_COLUMNS = [
    (name, attribute(name))
    for name in (
        "serial",
        "kind",
        "key_id",
        "principals",
        "status",
        "valid_after",
        "valid_before",
        "key_type",
        "fingerprint",
        "ca_fingerprint",
        "revoked_at",
        "revocation_reason",
    )
]


@bp.get("/ssh/certificates", responses={200: SshCertificatePage}, summary="SSH certificates, filtered, sorted and paged (format=csv: all of them, as a file)")
def list_certificates(query: SshListQuery):
    ssh_query = SshQuery(kind=query.kind, status=query.status, q=query.q, sort=query.sort, order=query.order)
    if query.format == "csv":
        rows, _ = ssh.certificates(ssh_query, per_page=None)
        return csv_response("ssh-certificates.csv", CSV_COLUMNS, rows)
    rows, total = ssh.certificates(ssh_query, page=query.page, per_page=query.per_page)
    return page(SshCertificatePage, rows, total, query)


@bp.get("/ssh/certificates/counts", responses={200: SshCounts}, summary="How many SSH certificates each tab of the list holds")
def certificate_counts(query: SshCountsQuery):
    return dump(SshCounts, ssh.counts(query.kind))


@bp.get("/ssh/certificates/<serial>", responses={200: SshCertificateDetail, 404: Error})
def get_certificate(path: SerialPath):
    found = ssh.detail(path.serial)
    if found is None:
        return error(f"SSH certificate {path.serial} not found.", 404)
    return dump(SshCertificateDetail, found)


@bp.get("/ssh/certificates/<serial>/download", responses={200: None, 404: Error}, summary="The certificate as an *-cert.pub file")
def download_certificate(path: SerialPath):
    found = ssh.download(path.serial)
    if found is None:
        return error(f"SSH certificate {path.serial} not found.", 404)
    return file_response(*found)
