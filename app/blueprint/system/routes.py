from flask import current_app, render_template

from app.auth.decorator import login_required
from app.auth.roles import role_required
from app.blueprint.system import bp
from app.libs.audit import recent_events
from config import (
    CA_ADMIN_PROVISIONER_NAME,
    CA_FINGERPRINT,
    CA_ROOT,
    CA_URL,
    DB_HOST,
    DB_NAME,
    DB_PASSWORD,
    DB_PORT,
    DB_USER,
)


def effective_settings():
    """The configuration in effect, grouped for display. Secrets are never shown."""
    config = current_app.config
    return [
        (
            "Step CA database (read-only)",
            [
                ("Host", DB_HOST),
                ("Port", DB_PORT),
                ("Database", DB_NAME),
                ("User", DB_USER),
                ("Password", "set" if DB_PASSWORD else "not set"),
            ],
        ),
        (
            "Step CA",
            [
                ("URL", CA_URL),
                ("Root fingerprint", CA_FINGERPRINT or "not set"),
                ("Root certificate", CA_ROOT or "downloaded from the CA and pinned with the fingerprint"),
                ("Admin provisioner", CA_ADMIN_PROVISIONER_NAME),
            ],
        ),
        (
            "Authentication",
            [
                ("Backend", config["AUTH_BACKEND"]),
                ("LDAP URL", config["LDAP_URL"] if config["AUTH_BACKEND"] == "ldap" else "—"),
                ("Admin group", config["ROLE_ADMIN_GROUP"] or "—"),
                ("Operator group", config["ROLE_OPERATOR_GROUP"] or "—"),
                ("Viewer group", config["ROLE_VIEWER_GROUP"] or "—"),
                ("Default role", config["DEFAULT_ROLE"]),
                ("Session lifetime", str(config["PERMANENT_SESSION_LIFETIME"])),
            ],
        ),
        (
            "Application",
            [
                ("App database", config["SQLALCHEMY_BINDS"]["app"]),
                ("Service control", "enabled" if config["SERVICE_CONTROL_ENABLED"] else "disabled"),
            ],
        ),
    ]


@bp.route("/config")
@login_required
@role_required("admin")
def config():
    return render_template("system/config.html", title="Configuration", settings=effective_settings())


@bp.route("/audit")
@login_required
@role_required("admin")
def audit_log():
    return render_template("system/audit.html", title="Audit Log", events=recent_events())
