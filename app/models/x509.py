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
    __tablename__ = 'generated_certs'
    id = db.Column(db.Integer, primary_key=True)
    serial = db.Column(db.String, nullable=False)
    common_name = db.Column(db.String, nullable=False)
    provisioner = db.Column(db.String, nullable=False)
    csr = db.Column(db.Text, nullable=False)
    certificate = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.current_timestamp())