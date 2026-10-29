from flask import jsonify

from app.blueprint.api_json import as_json
from app.blueprint.x509 import api_bp
from app.services import certificates
from app.stepca import store


@api_bp.route("/certs/<serial>")
def api_get_x509_certs_by_id(serial):
    certificate = store.certificate(serial) if certificates.is_serial(serial) else None
    if certificate is None:
        return jsonify({"error": "Certificate not found"}), 404
    return jsonify(as_json(certificate))


@api_bp.route("/certs")
def api_get_x509_certs():
    return jsonify(as_json(certificates.all_certificates()))
