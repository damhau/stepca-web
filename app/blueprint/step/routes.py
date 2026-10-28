import subprocess

from flask import abort, current_app, flash, jsonify, redirect, render_template, request, url_for

from app.auth.decorator import login_required
from app.auth.roles import role_required
from app.blueprint.step import bp
from app.libs.audit import audit
from app.libs.db_step import *
from app.libs.stepapi import *
from config import CA_URL

client = StepCAClient(CA_URL)


@bp.route("/provisioners", methods=["GET", "POST"])
@login_required
@role_required("admin", methods={"POST"})
def provisioner():
    if request.method == "POST":
        data = request.form.to_dict()

        resp = None
        if data.get("type") == "JWK":

            # Build full provisioner JSON
            provisioner_type = data["type"]

            # Send to backend
            claims = {
                "x509": {
                    "enabled": True,
                    "durations": {"default": data["duration_default"], "min": data["duration_min"], "max": data["duration_max"]},
                }
            }
            resp = client.create_provisioner_jwk(data["name"], data["passphrase"], claims=claims)

        elif data.get("type") == "ACME":
            # Convert checkbox to bool
            data["require_eab"] = "require_eab" in request.form

            # Build full provisioner JSON
            provisioner_type = data["type"]

            # Send to backend
            resp = client.create_provisioner_acme(
                name=data["name"],
                details={
                    provisioner_type: {
                        "require_eab": data["require_eab"],
                        "force_cn": data.get("force_cn") == "on",
                        "challenges": [int(c) for c in request.form.getlist("challenges")],
                    }
                },
                claims={
                    "x509": {
                        "enabled": True,
                        "durations": {
                            "default": data["duration_default"],
                            "min": data["duration_min"],
                            "max": data["duration_max"],
                        },
                    }
                },
            )

        else:
            flash(f"Unknown provisioner type '{data.get("type")}'.", "danger")
            return redirect(url_for("step.provisioner"))

        audit("create_provisioner", data["name"], success=bool(resp), detail=data.get("type"))
        if resp:
            flash(f"Provisioner '{data["name"]}' created successfully.", "success")
        else:
            flash(f"Failed to create provisioner '{data["name"]}'.", "danger")
        return redirect(url_for("step.provisioner"))

    provisioners = client.list_provisioners()
    if provisioners is None:
        flash("Could not load the provisioners from the CA.", "danger")
    return render_template("step/provisioners.html", title="StepCA Provisioners", provisioners=(provisioners or {}).get("provisioners", []))


@bp.route("/provisioner/<name>/delete", methods=["POST"])
@login_required
@role_required("admin")
def delete_provisioner(name):
    resp = client.delete_provisioner(name)
    audit("delete_provisioner", name, success=bool(resp))
    if resp:
        flash(f"Provisioner '{name}' deleted successfully.", "success")
        return redirect("/step/provisioners")
    else:
        flash(f"Failed to delete provisioner '{name}'.", "danger")
        return redirect("/step/provisioners")


@bp.route("/admins", methods=["GET", "POST"])
@login_required
@role_required("admin", methods={"POST"})
def admins():

    if request.method == "POST":
        subject = request.form.get("subject")
        provisioner_id = request.form.get("provisioner")
        admin_type = int(request.form.get("type"))

        resp = client.create_admin(subject=subject, provisioner=provisioner_id, admin_type=admin_type)
        audit("create_admin", subject, success=bool(resp), detail=f"provisioner={provisioner_id} type={admin_type}")

        if resp:
            flash(f"Admin '{subject}' created successfully.", "success")
        else:
            flash(f"Failed to create admin '{subject}'.", "danger")
        return redirect(url_for("step.admins"))

    admins = client.list_admins()
    if admins is None:
        flash("Could not load the admins from the CA.", "danger")
    provisioner_map = get_active_provisioner_map(get_step_provisioners())

    return render_template(
        "step/admin.html",
        title="StepCA Admins",
        admins=(admins or {}).get("admins", []),
        provisioners=provisioner_map,
        manage_admins=True,
    )


@bp.route("/admin/<id>/update", methods=["POST"])
@login_required
@role_required("admin")
def update_admin(id):
    admin_type = request.form.get("type", type=int)
    ok = admin_type in (1, 2) and bool(client.update_admin(id, admin_type))
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
    resp = client.delete_admin(id)
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
