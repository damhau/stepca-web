import base64
import subprocess

from cryptography.hazmat.primitives import serialization
from flask import abort, current_app, flash, jsonify, make_response, redirect, render_template, request, url_for

from app.auth.decorator import login_required
from app.auth.roles import role_required
from app.blueprint.step import bp
from app.libs.audit import audit
from app.libs.provisioners import ACME_CHALLENGES, durations_from_form
from app.libs.provisioners import edit_provisioner as edit_provisioner_record
from app.services import ca, provisioners


@bp.route("/provisioners", methods=["GET", "POST"])
@login_required
@role_required("admin", methods={"POST"})
def provisioner():
    if request.method == "POST":
        name = request.form.get("name", "")
        provisioner_type = request.form.get("type")
        try:
            claims = {"x509": {"enabled": True, "durations": durations_from_form(request.form)}}
        except ValueError as e:
            flash(f"Provisioner '{name}' was not created: {e}.", "danger")
            return redirect(url_for("step.provisioner"))

        if provisioner_type == "JWK":
            resp = ca.client().create_provisioner_jwk(name, request.form.get("passphrase", ""), claims=claims)
        elif provisioner_type == "ACME":
            offered = [challenge for challenge, _ in ACME_CHALLENGES]
            details = {
                "ACME": {
                    "requireEab": "require_eab" in request.form,
                    "forceCn": "force_cn" in request.form,
                    "challenges": [challenge for challenge in request.form.getlist("challenges") if challenge in offered],
                }
            }
            resp = ca.client().create_provisioner_acme(name=name, details=details, claims=claims)
        else:
            flash(f"Unknown provisioner type '{provisioner_type}'.", "danger")
            return redirect(url_for("step.provisioner"))

        audit("create_provisioner", name, success=bool(resp), detail=provisioner_type)
        if resp:
            flash(f"Provisioner '{name}' created successfully.", "success")
        else:
            flash(f"Failed to create provisioner '{name}'.", "danger")
        return redirect(url_for("step.provisioner"))

    provisioners = ca.client().list_provisioners()
    if provisioners is None:
        flash("Could not load the provisioners from the CA.", "danger")
    return render_template(
        "step/provisioners.html",
        title="StepCA Provisioners",
        provisioners=(provisioners or {}).get("provisioners", []),
        acme_challenges=ACME_CHALLENGES,
    )


@bp.route("/provisioner/<name>/edit", methods=["GET", "POST"])
@login_required
@role_required("admin")
def edit_provisioner(name):
    prov = ca.client().get_provisioner(name)
    if prov is None:
        flash(f"Could not load the provisioner '{name}' from the CA.", "danger")
        return redirect(url_for("step.provisioner"))

    if request.method == "POST":
        try:
            ca.client().update_provisioner(name, edit_provisioner_record(prov, request.form, app_provisioner=ca.client().provisioner_name))
        except (ValueError, RuntimeError) as e:
            audit("update_provisioner", name, success=False, detail=str(e))
            flash(f"Provisioner '{name}' was not updated: {e}", "danger")
            return redirect(url_for("step.edit_provisioner", name=name))
        audit("update_provisioner", name)
        flash(f"Provisioner '{name}' updated.", "success")
        return redirect(url_for("step.provisioner"))

    return render_template(
        "step/provisioner_edit.html",
        title=f"Edit provisioner {name}",
        prov=prov,
        acme_challenges=ACME_CHALLENGES,
        is_app_provisioner=name == ca.client().provisioner_name,
    )


@bp.route("/ca")
@login_required
def ca_status():
    return render_template("step/ca_status.html", title="CA status", **ca.ca_status())


def download(content, filename, content_type):
    response = make_response(content)
    response.headers["Content-Type"] = content_type
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@bp.route("/ca/<kind>.pem")
@login_required
def ca_certificates(kind):
    """The CA's roots or intermediates as one PEM file, fetched from the CA (which browsers may not reach)."""
    fetch = {"roots": ca.client().roots, "intermediates": ca.client().intermediates}.get(kind)
    if fetch is None:
        abort(404)
    try:
        certs = fetch()
    except ca.CA_ERRORS as e:
        flash(f"Could not load the {kind} from the CA: {e}", "danger")
        return redirect(url_for("step.ca_status"))
    return download(b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in certs), f"{kind}.pem", "application/x-pem-file")


@bp.route("/ca/crl")
@login_required
def ca_crl():
    try:
        der = ca.client().crl()
    except ca.CA_ERRORS as e:
        der = None
        flash(f"Could not load the CRL from the CA: {e}", "danger")
    if der is None:
        return redirect(url_for("step.ca_status"))
    if "pem" in request.args:
        pem = b"-----BEGIN X509 CRL-----\n" + base64.encodebytes(der) + b"-----END X509 CRL-----\n"
        return download(pem, "crl.pem", "application/x-pem-file")
    return download(der, "crl.crl", "application/pkix-crl")


@bp.route("/provisioner/<name>/delete", methods=["POST"])
@login_required
@role_required("admin")
def delete_provisioner(name):
    resp = ca.client().delete_provisioner(name)
    audit("delete_provisioner", name, success=bool(resp))
    if resp:
        flash(f"Provisioner '{name}' deleted successfully.", "success")
    else:
        flash(f"Failed to delete provisioner '{name}'.", "danger")
    return redirect(url_for("step.provisioner"))


def refuse_unless_admins_manageable():
    if provisioners.admins_manageable():
        return None
    flash("The app's identity on the CA is not a SUPER_ADMIN: manage admins with `step ca admin`.", "danger")
    return redirect(url_for("step.admins"))


@bp.route("/admins", methods=["GET", "POST"])
@login_required
@role_required("admin", methods={"POST"})
def admins():

    if request.method == "POST":
        if refused := refuse_unless_admins_manageable():
            return refused
        subject = request.form.get("subject", "")
        provisioner_id = request.form.get("provisioner", "")
        admin_type = {"1": 1, "2": 2}.get(request.form.get("type", ""))
        if not subject or admin_type is None:
            flash("An admin needs a subject and a type.", "danger")
            return redirect(url_for("step.admins"))

        resp = ca.client().create_admin(subject=subject, provisioner=provisioner_id, admin_type=admin_type)
        audit("create_admin", subject, success=bool(resp), detail=f"provisioner={provisioner_id} type={admin_type}")

        if resp:
            flash(f"Admin '{subject}' created successfully.", "success")
        else:
            flash(f"Failed to create admin '{subject}'.", "danger")
        return redirect(url_for("step.admins"))

    listed = ca.client().list_admins()
    if listed is None:
        flash("Could not load the admins from the CA.", "danger")
    return render_template(
        "step/admin.html",
        title="StepCA Admins",
        admins=provisioners.admin_rows((listed or {}).get("admins", [])),
        provisioners=provisioners.names_by_id(),
        manage_admins=provisioners.admins_manageable(),
    )


@bp.route("/admin/<id>/update", methods=["POST"])
@login_required
@role_required("admin")
def update_admin(id):
    if refused := refuse_unless_admins_manageable():
        return refused
    admin_type = request.form.get("type", type=int)
    ok = admin_type in (1, 2) and bool(ca.client().update_admin(id, admin_type))
    audit("update_admin", id, success=ok, detail=f"type={admin_type}")
    if not ok:
        flash(f"Failed to update admin '{id}'.", "danger")
    else:
        flash(f"Admin '{id}' updated.", "success")
    return redirect(url_for("step.admins"))


@bp.route("/admin/<id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def delete_admin(id):
    if refused := refuse_unless_admins_manageable():
        return refused
    resp = ca.client().delete_admin(id)
    audit("delete_admin", id, success=bool(resp))

    if resp:
        flash(f"Admin '{id}' deleted successfully.", "success")
        return redirect("/step/admins")
    else:
        flash(f"Failed to delete admin '{id}'.", "danger")
        return redirect("/step/admins")


def require_service_control():
    if not current_app.config["SERVICE_CONTROL_ENABLED"]:
        abort(404)


@bp.route("/service/<action>", methods=["POST"])
@login_required
@role_required("admin")
def stepca_service_action(action):
    require_service_control()
    if action not in ["start", "stop", "restart", "status"]:
        return jsonify({"error": "Invalid action"}), 400

    try:
        output = subprocess.check_output(["sudo", "/usr/local/bin/stepca_ctl.sh", action], stderr=subprocess.STDOUT, timeout=60)
        result = {"success": True, "output": output.decode()}
    except subprocess.CalledProcessError as e:
        result = {"success": False, "error": e.output.decode()}
    except (OSError, subprocess.TimeoutExpired) as e:
        result = {"success": False, "error": f"Cannot run the service control script: {e}"}
    if action != "status":
        audit(f"service_{action}", "step-ca", success=result["success"], detail=result.get("error", ""))
    return jsonify(result), 200 if result["success"] else 500


@bp.route("/service")
@login_required
@role_required("admin")
def step_service():
    require_service_control()
    return render_template("step/service.html", title="Service Control")
