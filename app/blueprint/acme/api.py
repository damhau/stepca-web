from dataclasses import asdict, is_dataclass
from datetime import datetime

from flask import jsonify

from app.blueprint.acme import api_bp
from app.services import acme


def as_json(value):
    """Records as JSON-ready data, with dates in ISO 8601."""
    if is_dataclass(value):
        return as_json(asdict(value))
    if isinstance(value, dict):
        return {key: as_json(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [as_json(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


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
