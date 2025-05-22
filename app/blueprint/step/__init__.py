from flask import Blueprint

bp = Blueprint('step', __name__, url_prefix='/step')


from app.blueprint.step import routes
