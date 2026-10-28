import re
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from flask import flash, make_response, redirect, render_template, request, url_for

from app.auth.decorator import login_required
from app.auth.roles import role_required
from app.blueprint.x509 import bp
from app.libs.audit import audit
from app.libs.ca import client
from app.libs.db_step import get_active_provisioner_map, get_step_provisioners
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
    provisioner_map = get_active_provisioner_map(get_step_provisioners())
    return render_template(
        "x509/active_certs.html",
        title="X.509 Active Certificates",
        certs=certs,
        provisioners=provisioner_map,
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
    return render_template("x509/revoked_certs.html", title="Revoked X.509 Certificates", revoked=revoked)


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
        revocation_reasons=REVOCATION_REASONS,
    )


@bp.route("/download/<serial>")
@login_required
def download_cert(serial):
    cert = get_x509_cert(serial) if serial.isascii() and serial.isdigit() else None
    if cert is None:
        flash(f"Certificate {serial} not found", "danger")
        return redirect(url_for("x509.active_certs"))

    common_names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    filename = re.sub(r"[^A-Za-z0-9._-]", "_", common_names[0].value if common_names else serial)

    # Serve the PEM of the certificate stored by step-ca as a downloadable file
    response = make_response(cert.public_bytes(serialization.Encoding.PEM))
    response.headers["Content-Type"] = "application/x-pem-file"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}.pem"'
    return response


@bp.route("/sign", methods=["POST"])
@login_required
@role_required("operator")
def sign_cert():
    csr = request.form.get("csr_pem")
    passphrase = request.form.get("passphrase")
    provisioner_name = request.form.get("provisioner")

    try:

        certificate = client.sign(csr, provisioner_name, passphrase)

        if certificate:
            serial_number = str(certificate.serial_number)  # decimal, like step-ca's x509_certs key

            common_name = None
            for attribute in certificate.subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    common_name = attribute.value
                    break

            save_generated_cert(serial_number, common_name, provisioner_name, csr)
            audit("sign", serial_number, detail=f"cn={common_name} provisioner={provisioner_name}")

            flash(f"Certificate {serial_number} created successfully", "success")
            return redirect(url_for("x509.active_certs"))
        else:
            audit("sign", "", success=False, detail=f"provisioner={provisioner_name}")
            flash("Failed to sign certificate", "danger")
    except Exception as e:
        audit("sign", "", success=False, detail=f"provisioner={provisioner_name}: {e}")
        flash(f"Failed to sign certificate with error {e}", "danger")

    return redirect(url_for("x509.active_certs"))


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
