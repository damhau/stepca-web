import re
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from flask import flash, jsonify, make_response, redirect, render_template, request, url_for

from app.auth.decorator import login_required
from app.auth.roles import role_required
from app.blueprint.x509 import bp
from app.libs import ca
from app.libs.audit import audit
from app.libs.ca import client
from app.libs.cert_utils import certificate_extensions, describe_csr
from app.libs.db_step import get_jwk_provisioner_names, get_step_provisioners
from app.libs.db_x509 import (
    get_expiring_certs,
    get_revocation,
    get_revoked_x509_with_cert_info,
    get_x509_active_certs,
    get_x509_cert,
    get_x509_certs,
    get_x509_certs_by_id,
    save_generated_cert,
)
from app.libs.provisioners import duration_seconds
from app.libs.stepapi import SignError
from app.services import acme

# Every RFC 5280 reason code, to name the ones step-ca recorded
REASON_NAMES = {
    0: "Unspecified",
    1: "Key compromise",
    2: "CA compromise",
    3: "Affiliation changed",
    4: "Superseded",
    5: "Cessation of operation",
    6: "Certificate hold",
    8: "Remove from CRL",
    9: "Privilege withdrawn",
    10: "AA compromise",
}

# RFC 5280 reasons that make sense for a passive revocation
REVOCATION_REASONS = [
    (0, "Unspecified"),
    (1, "Key compromise"),
    (3, "Affiliation changed"),
    (4, "Superseded"),
    (5, "Cessation of operation"),
    (9, "Privilege withdrawn"),
]


### X.509 Html routes
@bp.route("/all")
@login_required
def all_certs():
    certs = get_x509_certs()
    return render_template("x509/all_certs.html", title="X.509 All Certificates", certs=certs)


@bp.route("/active")
@login_required
def active_certs():
    certs = get_x509_active_certs()
    return render_template(
        "x509/active_certs.html",
        title="X.509 Active Certificates",
        certs=certs,
        signing_provisioners=get_jwk_provisioner_names(get_step_provisioners()),
        revocation_reasons=REVOCATION_REASONS,
    )


@bp.route("/expiring")
@login_required
def expiring_certs():
    days = request.args.get("days", 30, type=int)
    days = days if days in (7, 30, 90) else 30
    return render_template("x509/expiring.html", title=f"Expiring within {days} days", certs=get_expiring_certs(days), days=days)


@bp.route("/revoked")
@login_required
def revoked_certs():
    revoked = get_revoked_x509_with_cert_info()
    return render_template("x509/revoked_certs.html", title="Revoked X.509 Certificates", revoked=revoked, reason_names=REASON_NAMES)


@bp.route("/cert/<serial>")
@login_required
def cert_detail(serial):
    cert = get_x509_certs_by_id(serial)
    if cert is None or "error" in cert["data"]:
        flash(f"Certificate {serial} not found", "danger")
        return redirect(url_for("x509.all_certs"))

    now = datetime.now(UTC)
    not_before = datetime.fromisoformat(cert["data"]["not_before"])
    not_after = datetime.fromisoformat(cert["data"]["not_after"])
    status = "expired" if now > not_after else "not yet valid" if now < not_before else "valid"
    return render_template(
        "x509/cert_detail.html",
        title=f"Certificate {serial}",
        cert=cert,
        revocation=get_revocation(serial),
        status=status,
        days_left=(not_after - now).days,
        extensions=certificate_extensions(get_x509_cert(serial)),
        acme_order_id=acme.order_id_for_serial(serial),
        revocation_reasons=REVOCATION_REASONS,
        reason_names=REASON_NAMES,
    )


@bp.route("/download/<serial>")
@login_required
def download_cert(serial):
    """The certificate stored by step-ca: ?format=pem (default), der, or chain (with its intermediate)."""
    cert = get_x509_cert(serial) if serial.isascii() and serial.isdigit() else None
    if cert is None:
        flash(f"Certificate {serial} not found", "danger")
        return redirect(url_for("x509.active_certs"))

    common_names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    filename = re.sub(r"[^A-Za-z0-9._-]", "_", common_names[0].value if common_names else serial)
    file_format = request.args.get("format", "pem")
    if file_format == "der":
        content, filename, content_type = cert.public_bytes(serialization.Encoding.DER), f"{filename}.crt", "application/pkix-cert"
    elif file_format == "chain":
        try:
            intermediates = client.intermediates()
        except ca.CA_ERRORS as e:
            flash(f"Could not load the intermediate certificates from the CA: {e}", "danger")
            return redirect(url_for("x509.cert_detail", serial=serial))
        # The intermediate that issued it; step-ca usually has one
        issuers = [i for i in intermediates if i.subject == cert.issuer] or intermediates
        content = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in [cert, *issuers])
        filename, content_type = f"{filename}-chain.pem", "application/x-pem-file"
    else:
        content, filename, content_type = cert.public_bytes(serialization.Encoding.PEM), f"{filename}.pem", "application/x-pem-file"

    response = make_response(content)
    response.headers["Content-Type"] = content_type
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


# A CSR is a few kilobytes; refuse anything much bigger
MAX_CSR_BYTES = 64 * 1024


def submitted_csr():
    """The CSR from the uploaded file, or else from the text field."""
    upload = request.files.get("csr_file")
    if upload and upload.filename:
        content = upload.read(MAX_CSR_BYTES + 1)
        if len(content) > MAX_CSR_BYTES:
            raise SignError("The CSR file is too large")
        try:
            return content.decode("ascii")
        except UnicodeDecodeError as e:
            raise SignError("The CSR file is not a PEM file") from e
    return request.form.get("csr_pem", "")


@bp.route("/sign", methods=["POST"])
@login_required
@role_required("operator")
def sign_cert():
    provisioner_name = request.form.get("provisioner", "")
    valid_for = request.form.get("valid_for", "").strip()
    try:
        if valid_for:
            try:
                duration_seconds(valid_for)
            except ValueError as e:
                raise SignError(f"Validity: {e}") from e
        csr = submitted_csr()
        certificate = client.sign(csr, provisioner_name, request.form.get("passphrase", ""), not_after=valid_for or None)
    except SignError as e:
        audit("sign", "", success=False, detail=f"provisioner={provisioner_name}: {e}")
        flash(f"The certificate was not signed: {e}.", "danger")
        return redirect(url_for("x509.active_certs"))

    serial_number = str(certificate.serial_number)  # decimal, like step-ca's x509_certs key
    common_names = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    common_name = common_names[0].value if common_names else None
    save_generated_cert(serial_number, common_name, provisioner_name, csr)
    audit("sign", serial_number, detail=f"cn={common_name} provisioner={provisioner_name}")
    flash(f"Certificate {serial_number} created successfully", "success")
    return redirect(url_for("x509.cert_detail", serial=serial_number))


@bp.route("/csr/preview", methods=["POST"])
@login_required
@role_required("operator")
def csr_preview():
    """What a CSR asks for, shown by the sign form before signing."""
    csr = (request.get_json(silent=True) or {}).get("csr_pem", "")
    if len(csr) > MAX_CSR_BYTES:
        return jsonify({"error": "The CSR is too large"}), 400
    try:
        return jsonify(describe_csr(csr))
    except ValueError:
        return jsonify({"error": "This is not a PEM certificate signing request"}), 400


@bp.route("/revoke", methods=["POST"])
@login_required
@role_required("operator")
def revoke_cert():
    cert_id = request.form.get("cert_id", "")
    reasons = dict(REVOCATION_REASONS)
    reason = request.form.get("reason", "0")
    reason_code = int(reason) if reason.isascii() and reason.isdigit() else None
    if reason_code not in reasons:
        flash("Invalid revocation reason", "danger")
        return redirect(url_for("x509.active_certs"))

    cert = get_x509_certs_by_id(cert_id)

    if not cert:
        flash("Certificate not found", "danger")
        return redirect(url_for("x509.active_certs"))

    try:
        client.revoke(cert_id, reason_code=reason_code, reason=reasons[reason_code])
        audit("revoke", cert_id, detail=reasons[reason_code])
        flash(f"Certificate {cert_id} has been revoked successfully.", "success")
    except Exception as e:
        audit("revoke", cert_id, success=False, detail=str(e))
        flash(f"Failed to revoke certificate {cert_id} with error {e}.", "danger")

    return redirect(url_for("x509.cert_detail", serial=cert_id))
