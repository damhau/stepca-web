from flask import jsonify

from app.blueprint.acme import api_bp
from app.blueprint.api_json import as_json
from app.services import acme


@api_bp.route("/accounts")
def accounts():
    return jsonify(as_json(acme.accounts()))


@api_bp.route("/orders")
def orders():
    return jsonify([as_json(row.order) for row in acme.orders()])


@api_bp.route("/certs")
def certs():
    return jsonify(as_json(acme.certificates()))


@api_bp.route("/authzs")
def authzs():
    return jsonify([as_json(authorization) for authorization, _ in acme.authorizations()])


@api_bp.route("/challenges")
def challenges():
    return jsonify([as_json(challenge) for challenge, _ in acme.challenges()])
