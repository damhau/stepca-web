from app.extensions import db


class AuditEvent(db.Model):
    """Who did what in the app. Lives in the app's own SQLite database."""

    __bind_key__ = 'app'
    __tablename__ = 'audit_log'
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp(), index=True)
    user = db.Column(db.String, nullable=False)
    role = db.Column(db.String)
    action = db.Column(db.String, nullable=False)
    target = db.Column(db.String)
    success = db.Column(db.Boolean, nullable=False)
    detail = db.Column(db.Text)
