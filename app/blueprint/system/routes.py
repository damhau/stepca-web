from flask import render_template, request, flash, redirect, url_for
from app.libs.db_step import *
from app.blueprint.system import bp
from app.libs.stepapi import *
from config_db import CA_URL

client = StepCAClient(CA_URL)


@bp.route("/config", methods=["GET", "POST"])
def config():
    if request.method == "POST":
        # Get data from the form
        db_host = request.form["db_host"]
        db_user = request.form["db_user"]
        db_password = request.form["db_password"]
        db_name = request.form["db_name"]
        db_port = request.form["db_port"]
        ca_url = request.form["ca_url"]  # Add CA URL

        # Save these changes to config.py
        with open("config.py", "w") as config_file:
            config_file.write(
                f"""
DB_HOST = '{db_host}'
DB_USER = '{db_user}'
DB_PASSWORD = '{db_password}'
DB_NAME = '{db_name}'
DB_PORT = {db_port}
CA_URL = '{ca_url}'  # Save CA URL here
"""
            )

        flash("Configuration updated successfully!", "success")
        return redirect(url_for("config"))

    return render_template(
        "system/config_edit.html",
        db_host=DB_HOST,
        db_user=DB_USER,
        db_password=DB_PASSWORD,
        db_name=DB_NAME,
        db_port=DB_PORT,
        ca_url=CA_URL,
    )  # Pass CA_URL to the template
