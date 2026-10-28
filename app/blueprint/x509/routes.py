import re

from flask import render_template, flash, redirect, make_response, url_for, request

from app.libs.db_x509 import *
from app.libs.db_step import *
from app.libs.stepapi import *

from app.blueprint.x509 import bp
from config import CA_URL
from app.auth.decorator import login_required


client = StepCAClient(CA_URL)


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
    # print("Active certs:", certs)
    return render_template("x509/active_certs.html", title="X.509 Active Certificates", certs=certs, provisioners=provisioner_map)


@bp.route("/revoked")
@login_required
def revoked_certs():
    revoked = get_revoked_x509_with_cert_info()
    return render_template("x509/revoked_certs.html", title="Revoked X.509 Certificates", revoked=revoked)


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
def sign_cert():
    csr = request.form.get("csr_pem")
    passphrase = request.form.get("passphrase")
    provisionner_name = request.form.get("provisioner")

    try:

        certificate = client.sign(csr, provisionner_name, passphrase)

        if certificate:
            print("Certificate signed successfully:", certificate)
            serial_number = str(certificate.serial_number)  # decimal, like step-ca's x509_certs key

            common_name = None
            for attribute in certificate.subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    common_name = attribute.value
                    break

            save_generated_cert(serial_number, common_name, provisionner_name, csr)

            flash(f"Certificate {serial_number} created successfully", "success")
            return redirect(url_for("x509.active_certs"))
        else:
            flash(f"Failed to sign certificate", "danger")
    except Exception as e:
        flash(f"Failed to sign certificate with error {e}", "danger")

    return redirect(url_for("x509.active_certs"))


@bp.route("/revoke", methods=["POST"])
@login_required
def revoke_cert():
    cert_id = request.form.get("cert_id")
    passphrase = request.form.get("passphrase")

    cert = get_x509_certs_by_id(cert_id)

    if not cert:
        flash(f"Certificate not found", "danger")
        return redirect(url_for("x509.active_certs"))

    try:
        client.revoke(cert_id, passphrase)
        flash(f"Certificate {cert_id} has been revoked successfully.", "success")
    except Exception as e:
        flash(f"Failed to revoke certificate {cert_id} with error {e}.", "danger")

    return redirect(url_for("x509.active_certs"))
