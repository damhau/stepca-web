from flask import Blueprint

bp = Blueprint("system", __name__, url_prefix="/system")


from app.blueprint.system import routes
