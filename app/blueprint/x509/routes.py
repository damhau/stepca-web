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

def revoked_certs():
    revoked = get_revoked_x509_with_cert_info()
    return render_template("x509/revoked_certs.html", title="Revoked X.509 Certificates", revoked=revoked)


@bp.route("/download/<serial>")
@login_required
def download_cert(serial):
    cert = get_generated_cert_by_serial(serial)
    if not cert:
        flash(f"Certificate {cert} not found", "danger")
        return redirect(url_for("x509/x509.active_certs"))


    # Serve the cert_pem as a downloadable file
    response = make_response(cert["certificate"])
    response.headers["Content-Type"] = "application/x-pem-file"
    response.headers["Content-Disposition"] = f'attachment; filename={cert["common_name"]}.pem'
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
            serial_number = format(certificate.serial_number, "x").lstrip("0")  # padding optional

            common_name = None
            for attribute in certificate.subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    common_name = attribute.value
                    break

            pem = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")
            # decoded_certificate = decode_certificate(resp)
            # print("Decoded certificate:", decoded_certificate)
            save_generated_cert(serial_number, common_name, provisionner_name, csr, pem)

            flash(f"Certificate {serial_number} created successfully", "success")
            return redirect(url_for("x509.active_certs"))
        else:
            flash(f"Failed to sign certificate", "danger")
    except Exception as e:
        flash(f"Failed to sign certificate with error {e}", "danger")

    return redirect(url_for("x509.active_certs"))


@bp.route("/revoke", methods=["POST"])

def revoke_cert():
    cert_id = request.form.get("cert_id")
    passphrase = request.form.get("passphrase")


    # Add your logic to use the cert_id + passphrase
    # Example: call Step CA API to revoke the certificate
    cert = get_x509_certs_by_id(cert_id)

    if not cert:
        flash(f"Certificate not found", "danger")
        return redirect(url_for("x509.active_certs"))

    try:
        client.revoke(cert_id, cert["provisioner"]["name"], passphrase)
        flash(f"Certificate {cert_id} has been revoked successfully.", "success")
    except Exception as e:
        flash(f"Failed to revoke certificate {cert_id} with error {e}.", "danger")

    return redirect(url_for("x509.active_certs"))
