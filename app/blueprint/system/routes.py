from flask import render_template, request, flash, redirect, url_for
from app.libs.db_step import *
from app.blueprint.system import bp
from app.libs.stepapi import *
from config import CA_URL
from app.auth.decorator import login_required

client = StepCAClient(CA_URL)

SETTINGS_FILE = "settings.json"


def load_config():
    if not os.path.exists(SETTINGS_FILE):
        return {
            "database": {"host": "", "user": "", "password": "", "name": "", "port": 5432},
            "ca": {"url": "", "fingerprint": ""},
        }
    with open(SETTINGS_FILE) as f:
        return json.load(f)


@bp.route("/config", methods=["GET", "POST"])
@login_required
def config():
    config_data = load_config()

    if request.method == "POST":
        # Get data from form
        config_data["database"]["host"] = request.form["db_host"]
        config_data["database"]["user"] = request.form["db_user"]
        config_data["database"]["password"] = request.form["db_password"]
        config_data["database"]["name"] = request.form["db_name"]
        config_data["database"]["port"] = int(request.form["db_port"])
        config_data["ca"]["url"] = request.form["ca_url"]

        # Write updated config to JSON
        with open(SETTINGS_FILE, "w") as f:
            json.dump(config_data, f, indent=2)

        flash("Configuration updated successfully!", "success")
        return redirect(url_for("system.config"))

    # Pass values to template
    return render_template(
        "system/config_edit.html",
        title="Application Configuration",
        db_host=config_data["database"]["host"],
        db_user=config_data["database"]["user"],
        db_password=config_data["database"]["password"],
        db_name=config_data["database"]["name"],
        db_port=config_data["database"]["port"],
        ca_url=config_data["ca"]["url"],
    )


# @bp.route("/config", methods=["GET", "POST"])
# def config():
#     if request.method == "POST":
#         # Get data from the form
#         db_host = request.form["db_host"]
#         db_user = request.form["db_user"]
#         db_password = request.form["db_password"]
#         db_name = request.form["db_name"]
#         db_port = request.form["db_port"]
#         ca_url = request.form["ca_url"]  # Add CA URL

#         # Save these changes to config.py
#         with open("config.py", "w") as config_file:
#             config_file.write(
#                 f"""
# DB_HOST = '{db_host}'
# DB_USER = '{db_user}'
# DB_PASSWORD = '{db_password}'
# DB_NAME = '{db_name}'
# DB_PORT = {db_port}
# CA_URL = '{ca_url}'  # Save CA URL here
# """
#             )

#         flash("Configuration updated successfully!", "success")
#         return redirect(url_for("config"))

#     return render_template(
#         "system/config_edit.html",
#         db_host=DB_HOST,
#         db_user=DB_USER,
#         db_password=DB_PASSWORD,
#         db_name=DB_NAME,
#         db_port=DB_PORT,
#         ca_url=CA_URL,
#     )  # Pass CA_URL to the template
