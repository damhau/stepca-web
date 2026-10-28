from flask import Blueprint

bp = Blueprint('acme', __name__, url_prefix='/acme')
api_bp = Blueprint('acme_api', __name__, url_prefix='/api/acme')


from app.blueprint.acme import api, routes  # noqa: E402, F401  registers the routes on the blueprint
