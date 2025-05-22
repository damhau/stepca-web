from flask import Flask, render_template, jsonify, request, redirect, flash, url_for,send_file, session, make_response

from libs.db_acme import *
from libs.db_x509 import *
from libs.db_step import *
from libs.stepapi import *
from libs.db_init import create_jwk_keys_table
from libs.db_jwk import get_jwk_keys, add_jwk_key, delete_jwk_key, get_jwk_key_by_id
from libs.cert_utils import decode_certificate,extract_sans_from_csr
import subprocess
import urllib3
from datetime import datetime
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT, CA_URL, CA_FINGERPRINT
from io import BytesIO

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

create_jwk_keys_table()
create_generated_certs_table()


app = Flask(__name__)

app.secret_key = "super-secret-key" 

CONFIG_PATH = "ca.json"

client = StepCAClient(CA_URL)  # Use the CA URL from config.py

@app.route("/")
def home():
    certs = get_x509_certs()
    active_certs = get_x509_active_certs()
    revoked = get_revoked_x509_certs()
    provisioners = get_step_provisioners()
    active_provisioners = get_active_provisioner_map(provisioners)

    return render_template("index.html",
        total_certs=len(certs),
        active_certs=len(active_certs),
        revoked_certs=len(revoked),
        total_provisioners=len(active_provisioners),
    )

@app.route("/config", methods=["GET", "POST"])
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
            config_file.write(f"""
DB_HOST = '{db_host}'
DB_USER = '{db_user}'
DB_PASSWORD = '{db_password}'
DB_NAME = '{db_name}'
DB_PORT = {db_port}
CA_URL = '{ca_url}'  # Save CA URL here
""")
        
        flash("Configuration updated successfully!", "success")
        return redirect(url_for("config"))

    return render_template("config_edit.html", 
                           db_host=DB_HOST, 
                           db_user=DB_USER, 
                           db_password=DB_PASSWORD, 
                           db_name=DB_NAME, 
                           db_port=DB_PORT,
                           ca_url=CA_URL)  # Pass CA_URL to the template


@app.route("/step/provisioner/add")
def step_provisioner_add_page():
    return render_template("step_provisioner_create.html", title="New Admin Provisioner")

@app.route("/api/step/provisioner/add", methods=["POST"])
def api_add_admin_provisioner():
    data = request.json
    name = data.get("name")
    if not name:
        return jsonify({"error": "Missing provisioner name"}), 400

    result = add_jwk_admin_provisioner(name)

    if result["success"]:
        return jsonify({
            "success": True,
            "password": result["password"],
            "output": result["stdout"]
        })
    else:
        return jsonify({
            "success": False,
            "error": result["error"]
        }), 500


@app.route("/api/step/service/<action>", methods=["POST"])
def stepca_service_action(action):
    if action not in ["start", "stop", "restart", "status"]:
        return jsonify({"error": "Invalid action"}), 400

    try:
        output = subprocess.check_output(["sudo", "/usr/local/bin/stepca_ctl.sh", action], stderr=subprocess.STDOUT)
        return jsonify({"success": True, "output": output.decode()})
    except subprocess.CalledProcessError as e:
        return jsonify({"success": False, "error": e.output.decode()}), 500

@app.route("/step/service")
def step_service():
    return render_template("step_service.html", title="Service Control")

@app.route("/api/step/config/validate", methods=["POST"])
def api_validate_step_config():
    try:
        data = request.get_json()
        config_str = data.get("config", "")
        parsed = json.loads(config_str)
        return jsonify({"success": True, "message": "JSON is valid."})
    except Exception as e:
        return jsonify({"success": False, "message": f"Invalid JSON: {str(e)}"}), 400

@app.route("/step/config", methods=["GET", "POST"])
def step_config():
    config_json = ""
    error = None
    success = None

    if request.method == "POST":
        try:
            # Try to parse JSON for validation
            json_data = request.form["config"]
            parsed = json.loads(json_data)

            # If valid, save to file
            with open(CONFIG_PATH, "w") as f:
                f.write(json.dumps(parsed, indent=2))
            success = "Config saved successfully."
        except Exception as e:
            error = f"Failed to save config: {str(e)}"
        config_json = request.form["config"]
    else:
        try:
            with open(CONFIG_PATH, "r") as f:
                config_json = f.read()
        except Exception as e:
            error = f"Failed to read config: {str(e)}"

    return render_template("step_config.html", title="StepCA Config", config=config_json, error=error, success=success)

### ACME Routes

@app.route("/acme/accounts")
def acme_accounts():
    accounts = get_acme_accounts()
    # print("Accounts:", accounts)
    return render_template("acme_accounts.html", title="ACME Accounts", accounts=accounts)

@app.route("/acme/orders")
def acme_orders():
    orders = get_acme_orders()
    return render_template("acme_orders.html", title="ACME Orders", orders=orders)

@app.route("/acme/certs")
def acme_certs():
    certs = get_acme_certs()
    return render_template("acme_certs.html", title="ACME Certificates", certs=certs)

@app.route("/acme/authzs")
def acme_authzs():
    authzs = get_acme_authzs()
    return render_template("acme_authzs.html", title="ACME Authorizations", authzs=authzs)

@app.route("/acme/challenges")
def acme_challenges():
    challenges = get_acme_challenges()
    return render_template("acme_challenges.html", title="ACME Challenges", challenges=challenges)


@app.route("/api/acme/authzs")
def api_get_authzs():
    authzs = get_acme_authzs()
    if authzs:
        return jsonify(authzs)
    return jsonify({"error": "Certificate not found"}), 404

@app.route("/api/acme/orders")
def api_get_orders():
    orders = get_acme_orders()
    if orders:
        return jsonify(orders)
    return jsonify({"error": "Certificate not found"}), 404

@app.route("/api/acme/certs")
def api_get_certs():
    cert = get_acme_certs()
    if cert:
        return jsonify(cert)
    return jsonify({"error": "Certificate not found"}), 404

@app.route("/api/acme/certs/<cert_id>")
def api_get_cert(cert_id):
    cert = get_acme_cert_by_id(cert_id)
    if cert:
        return jsonify(cert)
    return jsonify({"error": "Certificate not found"}), 404

# X.509 Routes

@app.route("/x509/certs")
def x509_certs():
    certs = get_x509_certs()
    return render_template("x509_certs.html", title="X.509 All Certificates", certs=certs)

@app.route("/x509/active_certs")
def x509_active_certs():
    certs = get_x509_active_certs()
    provisioner_map = get_active_provisioner_map(get_step_provisioners())
    # print("Active certs:", certs)
    return render_template("x509_active_certs.html", title="X.509 Active Certificates", certs=certs, provisioners=provisioner_map)


@app.route("/api/x509/active_certs")
def api_get_x509_active_certs():
    certs = get_x509_active_certs()
    if certs:
        return jsonify(certs)
    return jsonify({"error": "Certificate not found"}), 404


@app.route("/api/x509/certs")
def api_get_x509_certs():
    cert = get_x509_certs()
    if cert:
        return jsonify(cert)
    return jsonify({"error": "Certificate not found"}), 404

@app.route("/api/x509/certs_data")
def api_get_x509_certs_data():
    cert = get_x509_certs_data()
    if cert:
        return jsonify(cert)
    return jsonify({"error": "Certificate not found"}), 404

@app.route("/api/x509/certs/<id>")
def api_get_x509_certs_by_id(id):
    cert = get_x509_certs_by_id(id)

    if cert:
        return jsonify(cert)
    return jsonify({"error": "Certificate not found"}), 404

@app.route("/api/x509/certs_data/<id>")
def api_get_x509_certs_data_by_id(id):
    cert = get_x509_certs_data_by_id(id)

    if cert:
        return jsonify(cert)
    return jsonify({"error": "Certificate not found"}), 404


@app.route("/api/x509/generated_certs")
def api_get_x509_generated_certs():
    cert = get_generated_certs()
    if cert:
        return jsonify(cert)
    return jsonify({"error": "Certificate not found"}), 404


@app.route("/x509/revoked")
def x509_revoked():
    revoked = get_revoked_x509_with_cert_info()
    return render_template("x509_revoked.html", title="Revoked X.509 Certificates", revoked=revoked)

@app.route("/api/x509/revoked")
def api_x509_revoked():
    revoked = get_revoked_x509_with_cert_info()
    return jsonify(revoked)

@app.route("/step/provisioners")
def step_provisioners():
    provisioners = client.list_provisioners()
    print("Provisioners:", provisioners["provisioners"])
    return render_template("step_provisioners.html", title="StepCA Provisioners", provisioners=provisioners["provisioners"])

@app.route("/api/step/provisioners")
def api_get_step_provisioners():
    provisioners = client.list_provisioners()
    print("Provisioners:", provisioners["provisioners"])
    if provisioners:
        return jsonify(provisioners)
    return jsonify({"error": "provisioners not found"}), 404


@app.route("/api/step/provisioner/<name>")
def api_get_step_provisioner(name):
    provisioner = client.get_provisioner(name)
    print("provisioner:", provisioner)
    if provisioner:
        return jsonify(provisioner)
    return jsonify({"error": "provisioner {name} not found"}), 404

@app.route("/api/stepdb/provisioners")
def api_get_stepdb_provisioners():
    provisioners = get_step_provisioners()
    print("Provisioners:", provisioners)
    if provisioners:
        return jsonify(provisioners)
    return jsonify({"error": "provisioners not found"}), 404

@app.route("/api/stepdb/admins")
def api_get_stepdb_admins():
    admins = get_step_admins()
    print("admins:", admins)
    if admins:
        return jsonify(admins)
    return jsonify({"error": "admins not found"}), 404



@app.route("/step/provisioners", methods=["GET", "POST"])
def step_provisioner():
    if request.method == "POST":
        data = request.form.to_dict()

        if data["type"] == "JWK":

            # Build full provisioner JSON
            provisioner_type = data["type"]

            # Send to backend
            claims = {
                    "x509": {
                        "enabled": True,
                        "durations": {
                            "default": data["duration_default"],
                            "min": data["duration_min"],
                            "max": data["duration_max"]
                        }
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
                        "challenges": [int(c) for c in request.form.getlist("challenges")]
                    }
                },
                claims={
                    "x509": {
                        "enabled": True,
                        "durations": {
                            "default": data["duration_default"],
                            "min": data["duration_min"],
                            "max": data["duration_max"]
                        }
                    }
                }
            )


    if resp:
        flash(f"Provisioner '{data["name"]}' created successfully.", "success")
    else:
        flash(f"Failed to create provisioner '{data["name"]}'.", "danger")

    provisioners = client.list_provisioners()
    return render_template("step_provisioners.html", title="StepCA Provisioners", provisioners=provisioners["provisioners"])


@app.route("/step/provisioner/<name>/delete")
def delete_provisioner(name):
    resp = client.delete_provisioner(name)
    if resp:
        flash(f"Provisioner '{name}' deleted successfully.", "success")
        return redirect("/step/provisioners")
    else:
        flash(f"Failed to delete admin '{name}'.", "danger")
        return redirect("/step/provisioners")


@app.route("/api/step/admins")
def api_get_step_admins():
    admins = client.list_admins()
    print("admins:", admins)
    if admins:
        return jsonify(admins)
    return jsonify({"error": "Certificate not found"}), 404


@app.route("/api/step/provisionermap")
def api_get_step_provisionermap():
    provisioner_map = get_active_provisioner_map(get_step_provisioners())
    print(f"admins: provisioner_map")
    if provisioner_map:
        return jsonify(provisioner_map)
    return jsonify({"error": "Certificate not found"}), 404


@app.route("/step/admins", methods=["GET", "POST"])
def step_admins():

    if request.method == "POST":
        subject = request.form.get('subject')
        provisioner_id = request.form.get('provisioner')
        admin_type = int(request.form.get('type'))
        print("subject:", subject)
        print("provisioner_id:", provisioner_id)
        print("admin_type:", admin_type)
        resp = client.create_admin(
            subject=subject,
            provisioner=provisioner_id,
            admin_type=admin_type
        )

        if resp:
            flash(f"Admin '{subject}' created successfully.", "success")
        else:
            flash(f"Failed to create admin '{subject}'.", "danger")

    admins = client.list_admins()
    print("admins:", admins)    
    provisioner_map = get_active_provisioner_map(get_step_provisioners())
    print("provisioners:", provisioner_map)
    return render_template("step_admin.html", title="StepCA Admins", admins=admins["admins"], provisioners=provisioner_map)


@app.route("/step/admin/<id>/delete")
def delete_admin(id):
    resp = client.delete_admin(id)

    if resp:
        flash(f"Admin '{id}' deleted successfully.", "success")
        return redirect("/step/admins")
    else:
        flash(f"Failed to delete admin '{id}'.", "danger")
        return redirect("/step/admins")

    # if success:
    #     return redirect("/step/admins")
    # return "Error deleting admin", 400

# @app.route("/api/step/admins")
# def api_get_step_admins():
#     admins = get_step_admins()
#     if admins:
#         return jsonify(admins)
#     return jsonify({"error": "No admin entries found"}), 404

# @app.route("/api/x509/certs_data/<id>")
# def api_get_x509_certs_data_by_id(id):
#     cert_data = get_x509_certs_data_by_id(id)
#     if cert_data:
#         # Assuming cert_data contains a 'data' field with the actual certificate in PEM format
#         cert_pem = cert_data["data"]["pem"]

#         # Convert the certificate to a BytesIO stream for download
#         return send_file(BytesIO(cert_pem.encode('utf-8')), as_attachment=True, download_name=f"{id}.pem", mimetype="application/x-x509-ca-cert")

#     return jsonify({"error": "Certificate not found"}), 404

# @app.route("/x509/revoke/<cert_id>")
# def revoke_x509_cert(cert_id):
#     # Assuming you have a function to revoke a certificate
#     passphrase = request.form.get('passphrase')
#     print("Revoke cert_id:", cert_id)
#     cert = get_x509_certs_by_id(cert_id)
#     print("cert:", cert)

#     success = client.revoke(cert_id, cert["provisioner"]["name"])
#     if success:
#         flash(f"Certificate {cert_id} has been revoked successfully.", "success")
#     else:
#         flash(f"Failed to revoke certificate {cert_id}.", "danger")

#     return redirect(url_for("x509_certs"))  # Redirect back to the certificate list page


@app.route('/x509/revoke/', methods=['POST'])
def revoke_x509_cert():
    cert_id = request.form.get('cert_id')
    passphrase = request.form.get('passphrase')
    print("Revoke cert_id:", cert_id)
    print("Revoke passphrase:", passphrase)

    # Add your logic to use the cert_id + passphrase
    # Example: call Step CA API to revoke the certificate
    cert = get_x509_certs_by_id(cert_id)
    print("cert:", cert)
    success = client.revoke(cert_id, cert["provisioner"]["name"], passphrase)
    if success:
        flash(f"Certificate {cert_id} has been revoked successfully.", "success")
    else:
        flash(f"Failed to revoke certificate {cert_id}.", "danger")
    return redirect(url_for("x509_active_certs")) 


@app.route('/x509/sign/', methods=['POST'])
def sign_x509_cert():
    csr = request.form.get('csr_pem')
    passphrase = request.form.get('passphrase')
    provisionner_name = request.form.get('provisioner')
    


    certificate = client.sign(csr, provisionner_name, passphrase)

    if certificate:
        print("Certificate signed successfully:", certificate)
        serial_number = format(certificate.serial_number, 'x').lstrip('0') # padding optional

        common_name = None
        for attribute in certificate.subject:
            if attribute.oid == x509.NameOID.COMMON_NAME:
                common_name = attribute.value
                break

        pem = certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        # decoded_certificate = decode_certificate(resp)
        # print("Decoded certificate:", decoded_certificate)
        save_generated_cert(serial_number, common_name, provisionner_name, csr, pem)

        flash(f'Certificate {serial_number} created successfully', 'success')
        return redirect(url_for('x509_active_certs'))
    else:
        flash(f"Failed to sign certificate", "danger")
    
    return redirect(url_for("x509_active_certs")) 



@app.route('/x509//download/<serial>')
def download_cert(serial):
    cert = get_generated_cert_by_serial(serial)
    if not cert:
        flash(f"Certificate {cert} not found", "danger")
        return redirect(url_for("x509_active_certs"))
    print("cert:", cert)

    # Serve the cert_pem as a downloadable file
    response = make_response(cert["certificate"])
    response.headers['Content-Type'] = 'application/x-pem-file'
    response.headers['Content-Disposition'] = f'attachment; filename={cert["common_name"]}.pem'
    return response













@app.route("/api/step/version")
def api_get_step_version():
    version = client.version()
    print("version:", version)
    if version:
        return jsonify(version)
    return jsonify({"error": "version not found"}), 404


@app.route("/jwk/keys")
def jwk_keys_page():
    keys = get_jwk_keys()
    provisioner_map = get_active_provisioner_map(get_step_provisioners())
    return render_template("jwk_keys.html", title="JWK Keys", keys=keys, provisioners=provisioner_map)

@app.route("/api/jwk_keys", methods=["POST"])
def api_add_jwk_key():
    data = request.json
    name = data.get("name")
    jwk = data.get("jwk")
    if not name or not jwk:
        return jsonify({"error": "Missing fields"}), 400

    add_jwk_key(name, jwk)
    return jsonify({"success": True})

@app.route("/api/jwk_keys/<int:key_id>", methods=["DELETE"])
def api_delete_jwk_key(key_id):
    delete_jwk_key(key_id)
    return jsonify({"success": True})


@app.route("/api/jwk_keys/<int:key_id>")
def get_key(key_id):
    key = get_jwk_key_by_id(key_id)
    if key is None:
        return jsonify({'error': 'Key not found'}), 404

    return jsonify(key)


@app.template_filter('format_date')
def format_date(value):
    # Convert seconds to datetime object and return formatted string
    return datetime.utcfromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')

if __name__ == "__main__":
    app.run(debug=True)