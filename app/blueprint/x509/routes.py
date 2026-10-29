from cryptography import x509
from flask import flash, jsonify, make_response, redirect, render_template, request, url_for

from app.auth.decorator import login_required
from app.auth.roles import role_required
from app.blueprint.x509 import bp
from app.libs.audit import audit
from app.libs.cert_utils import describe_csr
from app.libs.provisioners import duration_seconds
from app.services import ca, certificates, provisioners
from app.services.certificates import REASON_NAMES, REVOCATION_REASONS
from app.stepca.client import SignError


@bp.route("/all")
@login_required
def all_certs():
    return render_template("x509/all_certs.html", title="X.509 All Certificates", certs=certificates.all_certificates())


@bp.route("/active")
@login_required
def active_certs():
    return render_template(
        "x509/active_certs.html",
        title="X.509 Active Certificates",
        certs=certificates.active(),
        signing_provisioners=provisioners.signing_provisioners(),
        revocation_reasons=REVOCATION_REASONS,
    )


@bp.route("/expiring")
@login_required
def expiring_certs():
    days = request.args.get("days", 30, type=int)
    days = days if days in (7, 30, 90) else 30
    return render_template("x509/expiring.html", title=f"Expiring within {days} days", certs=certificates.expiring(days), days=days)


@bp.route("/revoked")
@login_required
def revoked_certs():
    return render_template("x509/revoked_certs.html", title="Revoked X.509 Certificates", revoked=certificates.revoked(), reason_names=REASON_NAMES)


@bp.route("/cert/<serial>")
@login_required
def cert_detail(serial):
    view = certificates.view(serial)
    if view is None:
        flash(f"Certificate {serial} not found", "danger")
        return redirect(url_for("x509.all_certs"))
    return render_template(
        "x509/cert_detail.html", title=f"Certificate {serial}", view=view, revocation_reasons=REVOCATION_REASONS, reason_names=REASON_NAMES
    )


@bp.route("/download/<serial>")
@login_required
def download_cert(serial):
    """The certificate stored by step-ca: ?format=pem (default), der, or chain (with its intermediate)."""
    file_format = request.args.get("format", "pem")
    try:
        found = certificates.download(serial, file_format if file_format in certificates.FORMATS else "pem", ca.client().intermediates)
    except ca.CA_ERRORS as e:
        flash(f"Could not load the intermediate certificates from the CA: {e}", "danger")
        return redirect(url_for("x509.cert_detail", serial=serial))
    if found is None:
        flash(f"Certificate {serial} not found", "danger")
        return redirect(url_for("x509.active_certs"))
    content, filename, content_type = found
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
        certificate = ca.client().sign(csr, provisioner_name, request.form.get("passphrase", ""), not_after=valid_for or None)
    except SignError as e:
        audit("sign", "", success=False, detail=f"provisioner={provisioner_name}: {e}")
        flash(f"The certificate was not signed: {e}.", "danger")
        return redirect(url_for("x509.active_certs"))

    serial_number = str(certificate.serial_number)  # decimal, like step-ca's x509_certs key
    common_names = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    common_name = common_names[0].value if common_names else None
    certificates.record_signed(serial_number, common_name, provisioner_name, csr)
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

    if not certificates.exists(cert_id):
        flash("Certificate not found", "danger")
        return redirect(url_for("x509.active_certs"))

    try:
        ca.client().revoke(cert_id, reason_code=reason_code, reason=reasons[reason_code])
        audit("revoke", cert_id, detail=reasons[reason_code])
        flash(f"Certificate {cert_id} has been revoked successfully.", "success")
    except (RuntimeError, *ca.CA_ERRORS) as e:
        audit("revoke", cert_id, success=False, detail=str(e))
        flash(f"Failed to revoke certificate {cert_id} with error {e}.", "danger")

    return redirect(url_for("x509.cert_detail", serial=cert_id))
