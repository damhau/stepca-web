from app.extensions import db


class InventoryCertificate(db.Model):
    """A certificate from step-ca's x509_certs, parsed once (certificates never change), in the app's own
    database so that lists can be filtered, sorted and paged in SQL. Kept in sync by services.inventory."""

    __bind_key__ = "app"
    __tablename__ = "inventory_certificates"
    serial = db.Column(db.String, primary_key=True)  # decimal, like the x509_certs key
    serial_hex = db.Column(db.String, nullable=False)
    subject = db.Column(db.Text, nullable=False)
    common_name = db.Column(db.String, index=True)
    issuer = db.Column(db.Text, nullable=False)
    # UTC, without a time zone (SQLite has none)
    not_before = db.Column(db.DateTime, index=True)
    not_after = db.Column(db.DateTime, index=True)
    key = db.Column(db.String, nullable=False)  # "RSA 2048", "secp256r1", "Ed25519"
    dns_names = db.Column(db.JSON, nullable=False)
    provisioner_id = db.Column(db.String)
    provisioner_name = db.Column(db.String, index=True)
    provisioner_type = db.Column(db.String)
    # Set when the stored certificate doesn't parse
    error = db.Column(db.Text)
    # Lower-case serial, hex serial, subject and DNS names, for the text filter
    search = db.Column(db.Text, nullable=False)


class InventoryRevocation(db.Model):
    """A revocation from step-ca's revoked_x509_certs (revocations never change either)."""

    __bind_key__ = "app"
    __tablename__ = "inventory_revocations"
    serial = db.Column(db.String, primary_key=True)
    reason_code = db.Column(db.Integer)
    reason = db.Column(db.String, nullable=False)
    revoked_at = db.Column(db.DateTime)
    provisioner_id = db.Column(db.String)
    mtls = db.Column(db.Boolean, nullable=False)
    acme = db.Column(db.Boolean, nullable=False)
