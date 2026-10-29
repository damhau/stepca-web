import logging
import os
from datetime import UTC, datetime

from flask import Flask, render_template
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix

from app.extensions import CONTENT_SECURITY_POLICY, csrf, db, limiter
from app.models.audit import AuditEvent  # noqa: F401  registers the model for create_all
from app.models.x509 import GeneratedCert  # noqa: F401  registers the model for create_all
from config import CA_URL, DB_HOST, Config

log = logging.getLogger(__name__)


def check_ldap_config(config):
    from app.libs.auth.ldap_backend import ldap_transport

    if config["LDAP_CA_FILE"] and not os.path.isfile(config["LDAP_CA_FILE"]):
        raise RuntimeError(f"LDAP_CA_FILE {config['LDAP_CA_FILE']} does not exist")
    if ldap_transport(config) == "cleartext":
        log.warning("LDAP_URL is ldap:// without LDAP_START_TLS: user passwords cross the network in cleartext. Use ldaps:// or set LDAP_START_TLS=true")


def format_datetime(value):
    """One format for every date shown: "2025-05-22 14:03 UTC".

    Takes a datetime (naive ones are UTC), epoch seconds, or an ISO 8601 string such as Go's RFC 3339
    with nanoseconds. Go's zero time, which step-ca uses for "never", shows as a dash.
    """
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    elif isinstance(value, int | float):
        value = datetime.fromtimestamp(value, UTC)
    if not isinstance(value, datetime) or value.year == 1:
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def create_app(config_class=Config):
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    app = Flask(__name__)

    app.config.from_object(config_class)
    if not app.config.get("SECRET_KEY"):
        raise RuntimeError('SECRET_KEY is not set. Generate one with: python -c "import secrets; print(secrets.token_hex(32))"')
    missing = [name for name, value in (("CA_URL", CA_URL), ("DATABASE_HOST", DB_HOST)) if not value]
    if missing:
        raise RuntimeError(f"Missing configuration: {', '.join(missing)} (see .env.example)")
    if app.config["AUTH_BACKEND"] == "ldap":
        check_ldap_config(app.config)

    if app.config["TRUSTED_PROXIES"]:
        # Behind reverse proxies: take the client address and scheme from their X-Forwarded-* headers
        proxies = app.config["TRUSTED_PROXIES"]
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=proxies, x_proto=proxies)

    # Initialize Flask extensions here
    db.init_app(app)
    # Every POST/PUT/PATCH/DELETE must carry the session's CSRF token
    csrf.init_app(app)
    limiter.init_app(app)
    # Security headers. HTTPS is terminated by a reverse proxy, so no redirect to it here;
    # HSTS is only sent over HTTPS, and only when the UI is served over HTTPS (SESSION_COOKIE_SECURE)
    Talisman(
        app,
        force_https=False,
        strict_transport_security=app.config["SESSION_COOKIE_SECURE"],
        session_cookie_secure=app.config["SESSION_COOKIE_SECURE"],
        frame_options="DENY",
        content_security_policy=CONTENT_SECURITY_POLICY,
        referrer_policy="same-origin",
    )

    @app.errorhandler(429)
    def too_many_requests(error):
        return render_template("auth/login.html", error="Too many failed sign-ins from your address: try again later."), 429

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


    app.add_template_filter(format_datetime, "datetime")

    return app
