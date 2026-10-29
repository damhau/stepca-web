import logging

from flask import session

from app.extensions import db
from app.models.audit import AuditEvent

log = logging.getLogger("stepca_web.audit")


def audit(action, target="", success=True, detail="", user=None):
    """Record an action in the audit log (and on stdout)."""
    event = AuditEvent(
        user=user or session.get("user_id", "-"),
        role=session.get("role"),
        action=action,
        target=str(target),
        success=success,
        detail=str(detail)[:2000],
    )
    db.session.add(event)
    db.session.commit()
    log.info("user=%s role=%s action=%s target=%s success=%s", event.user, event.role, action, target, success)

