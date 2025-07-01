from flask import jsonify

from app.libs.db_acme import *

from app.blueprint.acme import api_bp



@api_bp.route("/accounts")
def accounts():
    accounts = get_acme_accounts()
    if accounts:
        return jsonify(accounts)
    return jsonify({"error": "Accounts not found"}), 404

@api_bp.route("/orders")
def orders():
    orders = get_acme_orders()
    if orders:
        return jsonify(orders)
    return jsonify({"error": "Orders not found"}), 404

@api_bp.route("/certs")
def certs():
    certs = get_acme_certs()
    if certs:
        return jsonify(certs)
    return jsonify({"error": "Certificates not found"}), 404

@api_bp.route("/authzs")
def authzs():
    authzs = get_acme_authzs()
    if authzs:
        return jsonify(authzs)
    return jsonify({"error": "Authorizations not found"}), 404

@api_bp.route("/challenges")
def challenges():
    challenges = get_acme_challenges()
    if challenges:
        return jsonify(challenges)
    return jsonify({"error": "Challenges not found"}), 404



