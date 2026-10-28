from app.extensions import db


class StepProvisioner(db.Model):
    __tablename__ = 'provisioners'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)


class StepAdmin(db.Model):
    __tablename__ = 'admins'
    nkey = db.Column(db.LargeBinary, primary_key=True)
    nvalue = db.Column(db.LargeBinary)
