from flask import Blueprint

bp = Blueprint('step', __name__, url_prefix='/step')


from app.blueprint.step import routes  # noqa: E402, F401  registers the routes on the blueprint
