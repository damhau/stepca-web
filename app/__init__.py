from datetime import datetime
from flask import Flask

from config import Config
from app.extensions import db


from sqlalchemy import inspect
from app.models.x509 import GeneratedCert




def create_app(config_class=Config):
    app = Flask(__name__)

    app.config.from_object(config_class)

    # Initialize Flask extensions here
    db.init_app(app)


    with app.app_context():
        insp = inspect(db.engine)
        if "generated_certs" not in insp.get_table_names():
            GeneratedCert.__table__.create(bind=db.engine, checkfirst=True)


    # Register blueprints here
    from app.blueprint.home import bp as main_bp
    app.register_blueprint(main_bp)

    from app.blueprint.acme import bp as acme_bp
    app.register_blueprint(acme_bp)

    from app.blueprint.acme import api_bp as acme_api_bp
    app.register_blueprint(acme_api_bp)

    from app.blueprint.x509 import bp as x509_bp
    app.register_blueprint(x509_bp)

    from app.blueprint.x509 import api_bp as x509_api_bp
    app.register_blueprint(x509_api_bp)

    from app.blueprint.step import bp as step_bp
    app.register_blueprint(step_bp)

    # Register authentication blueprint
    from app.blueprint.auth.routes import auth_bp
    app.register_blueprint(auth_bp)

    from app.blueprint.system import bp as system_bp

    app.register_blueprint(system_bp)

    # from app.blueprint.questions import bp as questions_bp
    # app.register_blueprint(questions_bp, url_prefix='/questions')

    @app.template_filter("format_date")
    def format_date(value):
        # Convert seconds to datetime object and return formatted string
        return datetime.utcfromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")

    return app
