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
    lifetime_seconds = db.Column(db.Integer)
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


# --- ACME: copies of step-ca's acme_* tables, kept in sync by services.acme_inventory --------------------
# Unlike certificates, ACME objects change until they are final (an order is pending, ready, then valid or
# invalid); the sync re-reads the ones that still can.


class InventoryAcmeOrder(db.Model):
    __bind_key__ = "app"
    __tablename__ = "inventory_acme_orders"
    id = db.Column(db.String, primary_key=True)
    account_id = db.Column(db.String, nullable=False, index=True)
    provisioner_id = db.Column(db.String)
    identifiers = db.Column(db.JSON, nullable=False)  # [{"type": "dns", "value": "..."}]
    authorization_ids = db.Column(db.JSON, nullable=False)
    status = db.Column(db.String, nullable=False, index=True)
    certificate_id = db.Column(db.String, index=True)
    not_before = db.Column(db.DateTime)
    not_after = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, index=True)
    expires_at = db.Column(db.DateTime)
    error = db.Column(db.Text)
    # Lower-case id, account id and identifiers, for the text filter
    search = db.Column(db.Text, nullable=False)


class InventoryAcmeAuthorization(db.Model):
    __bind_key__ = "app"
    __tablename__ = "inventory_acme_authorizations"
    id = db.Column(db.String, primary_key=True)
    account_id = db.Column(db.String, nullable=False)
    identifier_type = db.Column(db.String, nullable=False)
    identifier_value = db.Column(db.String, nullable=False)
    status = db.Column(db.String, nullable=False, index=True)
    wildcard = db.Column(db.Boolean, nullable=False)
    challenge_ids = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, index=True)
    expires_at = db.Column(db.DateTime)
    error = db.Column(db.Text)
    search = db.Column(db.Text, nullable=False)


class InventoryAcmeChallenge(db.Model):
    __bind_key__ = "app"
    __tablename__ = "inventory_acme_challenges"
    id = db.Column(db.String, primary_key=True)
    account_id = db.Column(db.String, nullable=False)
    type = db.Column(db.String, nullable=False)
    status = db.Column(db.String, nullable=False, index=True)
    value = db.Column(db.String, nullable=False)
    validated_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, index=True)
    error = db.Column(db.Text)
    search = db.Column(db.Text, nullable=False)


class InventoryAcmeCertificate(db.Model):
    """An ACME certificate, with its leaf parsed once (they never change)."""

    __bind_key__ = "app"
    __tablename__ = "inventory_acme_certificates"
    id = db.Column(db.String, primary_key=True)
    account_id = db.Column(db.String, nullable=False)
    order_id = db.Column(db.String, nullable=False, index=True)
    created_at = db.Column(db.DateTime, index=True)
    serial = db.Column(db.String, index=True)  # decimal, None when the leaf doesn't parse
    subject = db.Column(db.Text)
    dns_names = db.Column(db.JSON, nullable=False)
    not_before = db.Column(db.DateTime)
    not_after = db.Column(db.DateTime)
    error = db.Column(db.Text)
    search = db.Column(db.Text, nullable=False)


class InventoryAcmeOrderAuthorization(db.Model):
    """Which order an authorization belongs to (an order lists its authorizations when it is created)."""

    __bind_key__ = "app"
    __tablename__ = "inventory_acme_order_authorizations"
    authorization_id = db.Column(db.String, primary_key=True)
    order_id = db.Column(db.String, nullable=False, index=True)


class InventoryAcmeAuthorizationChallenge(db.Model):
    """Which authorization a challenge belongs to."""

    __bind_key__ = "app"
    __tablename__ = "inventory_acme_authorization_challenges"
    challenge_id = db.Column(db.String, primary_key=True)
    authorization_id = db.Column(db.String, nullable=False, index=True)
