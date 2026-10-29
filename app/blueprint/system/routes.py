from flask import render_template

from app.auth.decorator import login_required
from app.auth.roles import role_required
from app.blueprint.system import bp
from app.libs.audit import recent_events
from app.services.system import config_warnings, effective_settings


@bp.route("/config")
@login_required
@role_required("admin")
def config():
    return render_template("system/config.html", title="Configuration", settings=effective_settings(), warnings=config_warnings())


@bp.route("/audit")
@login_required
@role_required("admin")
def audit_log():
    return render_template("system/audit.html", title="Audit Log", events=recent_events())
