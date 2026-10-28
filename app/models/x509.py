from app.extensions import db

class X509Cert(db.Model):
    __tablename__ = 'x509_certs'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)

class X509CertData(db.Model):
    __tablename__ = 'x509_certs_data'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)

class RevokedX509Cert(db.Model):
    __tablename__ = 'revoked_x509_certs'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)

class GeneratedCert(db.Model):
    """Certificates signed from this UI, stored in the app's own SQLite database.
    The certificate itself is read from step-ca's x509_certs."""
    __bind_key__ = 'app'
    __tablename__ = 'generated_certs'
    id = db.Column(db.Integer, primary_key=True)
    serial = db.Column(db.String, nullable=False)  # decimal, like the x509_certs key
    common_name = db.Column(db.String, nullable=False)
    provisioner = db.Column(db.String, nullable=False)
    csr = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())