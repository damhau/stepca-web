from flask import Flask, render_template, jsonify, request

from libs.db_acme import *
from libs.db_x509 import *
from libs.db_step import *
from libs.stepcli_wrapper import add_jwk_admin_provisioner
import subprocess

app = Flask(__name__)

CONFIG_PATH = "ca.json"


@app.route("/")
def home():
    certs = get_x509_certs()
    revoked = get_revoked_x509_certs()
    provisioners = get_step_provisioners()

    return render_template("index.html",
        total_certs=len(certs),
        revoked_certs=len(revoked),
        total_provisioners=len(provisioners),
    )

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
    return render_template("x509_certs.html", title="X.509 Certificates", certs=certs)

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
    provisioners = get_step_provisioners()
    return render_template("step_provisioners.html", title="StepCA Provisioners", provisioners=provisioners)

@app.route("/api/step/provisioners")
def api_get_step_provisioners():
    provisioners = get_step_provisioners()

    if provisioners:
        return jsonify(provisioners)
    return jsonify({"error": "Certificate not found"}), 404


@app.route("/step/admins")
def step_admins():
    admins = get_step_admins()
    return render_template("step_admin.html", title="StepCA Admins", admins=admins)

@app.route("/api/step/admins")
def api_get_step_admins():
    admins = get_step_admins()
    if admins:
        return jsonify(admins)
    return jsonify({"error": "No admin entries found"}), 404





if __name__ == "__main__":
    app.run(debug=True)