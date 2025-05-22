from app.extensions import db

class AcmeAccount(db.Model):
    __tablename__ = 'acme_accounts'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)

class AcmeOrder(db.Model):
    __tablename__ = 'acme_orders'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)

class AcmeCert(db.Model):
    __tablename__ = 'acme_certs'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)

class AcmeAuthz(db.Model):
    __tablename__ = 'acme_authzs'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)

class AcmeChallenge(db.Model):
    __tablename__ = 'acme_challenges'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)