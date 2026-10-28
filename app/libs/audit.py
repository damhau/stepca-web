from flask import session

from app.extensions import db
from app.models.audit import AuditEvent


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
    print(f"AUDIT user={event.user} role={event.role} action={action} target={target} success={success}")


def recent_events(limit=500):
    return AuditEvent.query.order_by(AuditEvent.id.desc()).limit(limit).all()
