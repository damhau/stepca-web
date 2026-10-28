from flask import jsonify

from app.auth.decorator import login_required
from app.blueprint.x509 import api_bp
from app.libs.db_x509 import *


@api_bp.route("/certs/<id>")
@login_required
def api_get_x509_certs_by_id(id):
    cert = get_x509_certs_by_id(id)
    if cert:
        return jsonify(cert)
    return jsonify({"error": "Certificate not found"}), 404


@api_bp.route("/certs")
@login_required
def api_get_x509_certs():
    certs = get_x509_certs()

    return jsonify(certs)