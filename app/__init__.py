import logging
import os
from datetime import UTC, datetime

from flask import Flask

from app.extensions import csrf, db
from app.models.audit import AuditEvent  # noqa: F401  registers the model for create_all
from app.models.x509 import GeneratedCert  # noqa: F401  registers the model for create_all
from config import CA_URL, DB_HOST, Config


def create_app(config_class=Config):
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    app = Flask(__name__)

    app.config.from_object(config_class)
    if not app.config.get("SECRET_KEY"):
        raise RuntimeError('SECRET_KEY is not set. Generate one with: python -c "import secrets; print(secrets.token_hex(32))"')
    missing = [name for name, value in (("CA_URL", CA_URL), ("DATABASE_HOST", DB_HOST)) if not value]
    if missing:
        raise RuntimeError(f"Missing configuration: {', '.join(missing)} (see .env.example)")

    # Initialize Flask extensions here
    db.init_app(app)
    # Every POST/PUT/PATCH/DELETE must carry the session's CSRF token
    csrf.init_app(app)

    # Every route requires a session unless explicitly listed as public
    from app.auth.decorator import require_login
    app.before_request(require_login)

    from app.auth.roles import current_role, role_at_least

    @app.context_processor
    def role_helpers():
        # Templates show only the actions the user's role allows: {% if can("operator") %}
        return {"current_role": current_role(), "can": lambda minimum: role_at_least(current_role(), minimum)}


    with app.app_context():
        # Only the app's own SQLite tables: step-ca's database is never modified
        db.create_all(bind_key="app")


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


    @app.template_filter("format_date")
    def format_date(value):
        # Convert seconds to datetime object and return formatted string
        return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%d %H:%M:%S")

    return app
