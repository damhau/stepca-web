from flask import Blueprint

bp = Blueprint("system", __name__, url_prefix="/system")


from app.blueprint.system import routes  # noqa: E402, F401  registers the routes on the blueprint
