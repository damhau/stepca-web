from flask import render_template, request, flash, redirect, jsonify
from app.libs.db_step import *
from app.blueprint.step import bp
from app.libs.stepapi import *
from config_db import CA_URL
import subprocess

client = StepCAClient(CA_URL)


@bp.route("/provisioners", methods=["GET", "POST"])
def provisioner():
    if request.method == "POST":
        data = request.form.to_dict()

        if data["type"] == "JWK":

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

        if data["type"] == "ACME":
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

        if resp:
            flash(f"Provisioner '{data["name"]}' created successfully.", "success")
        else:
            flash(f"Failed to create provisioner '{data["name"]}'.", "danger")

    provisioners = client.list_provisioners()
    return render_template("step/provisioners.html", title="StepCA Provisioners", provisioners=provisioners["provisioners"])


@bp.route("/provisioner/<name>/delete")
def delete_provisioner(name):
    resp = client.delete_provisioner(name)
    if resp:
        flash(f"Provisioner '{name}' deleted successfully.", "success")
        return redirect("/step/provisioners")
    else:
        flash(f"Failed to delete admin '{name}'.", "danger")
        return redirect("/step/provisioners")


@bp.route("/admins", methods=["GET", "POST"])
def admins():

    if request.method == "POST":
        subject = request.form.get("subject")
        provisioner_id = request.form.get("provisioner")
        admin_type = int(request.form.get("type"))
        print("subject:", subject)
        print("provisioner_id:", provisioner_id)
        print("admin_type:", admin_type)
        resp = client.create_admin(subject=subject, provisioner=provisioner_id, admin_type=admin_type)

        if resp:
            flash(f"Admin '{subject}' created successfully.", "success")
        else:
            flash(f"Failed to create admin '{subject}'.", "danger")

    admins = client.list_admins()
    print("admins:", admins)
    provisioner_map = get_active_provisioner_map(get_step_provisioners())
    print("provisioners:", provisioner_map)
    return render_template("step/admin.html", title="StepCA Admins", admins=admins["admins"], provisioners=provisioner_map)


@bp.route("/admin/<id>/delete")
def delete_admin(id):
    resp = client.delete_admin(id)

    if resp:
        flash(f"Admin '{id}' deleted successfully.", "success")
        return redirect("/step/admins")
    else:
        flash(f"Failed to delete admin '{id}'.", "danger")
        return redirect("/step/admins")


@bp.route("/service/<action>", methods=["POST"])
def stepca_service_action(action):
    if action not in ["start", "stop", "restart", "status"]:
        return jsonify({"error": "Invalid action"}), 400

    try:
        output = subprocess.check_output(["sudo", "/usr/local/bin/stepca_ctl.sh", action], stderr=subprocess.STDOUT)
        return jsonify({"success": True, "output": output.decode()})
    except subprocess.CalledProcessError as e:
        return jsonify({"success": False, "error": e.output.decode()}), 500


@bp.route("/service")
def step_service():
    return render_template("step/service.html", title="Service Control")
