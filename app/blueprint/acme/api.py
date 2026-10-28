from flask import jsonify

from app.blueprint.acme import api_bp
from app.libs.db_acme import *


@api_bp.route("/accounts")
def accounts():
    accounts = get_acme_accounts()
    return jsonify(accounts)

@api_bp.route("/orders")
def orders():
    orders = get_acme_orders()
    return jsonify(orders)

@api_bp.route("/certs")
def certs():
    certs = get_acme_certs()
    return jsonify(certs)

@api_bp.route("/authzs")
def authzs():
    authzs = get_acme_authzs()
    return jsonify(authzs)

@api_bp.route("/challenges")
def challenges():
    challenges = get_acme_challenges()
    return jsonify(challenges)



