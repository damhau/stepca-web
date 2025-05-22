from flask import jsonify

from app.libs.db_x509 import *


from app.blueprint.x509 import api_bp   


@api_bp.route("/certs/<id>")
def api_get_x509_certs_by_id(id):
    cert = get_x509_certs_by_id(id)

    if cert:
        return jsonify(cert)
    return jsonify({"error": "Certificate not found"}), 404