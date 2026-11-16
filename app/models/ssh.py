from app.extensions import db


class SshCert(db.Model):
    """Decimal serial -> the SSH certificate in OpenSSH's wire format (what `ssh-keygen` shows base64-encoded)."""

    __tablename__ = 'ssh_certs'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)


class RevokedSshCert(db.Model):
    """Decimal serial -> the JSON of step-ca's RevokedCertificateInfo, like revoked_x509_certs."""

    __tablename__ = 'revoked_ssh_certs'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)
