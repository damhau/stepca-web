import json
import logging

from app.extensions import db
from app.models.acme import AcmeAccount, AcmeAuthz, AcmeCert, AcmeChallenge, AcmeOrder

from .cert_utils import parse_cert

log = logging.getLogger(__name__)



def get_acme_accounts():
    accounts = []
    for row in db.session.query(AcmeAccount).all():
        try:
            key = row.nkey.decode('utf-8', errors='ignore')
            value = json.loads(row.nvalue)
            accounts.append({"nkey": key, "data": value})
        except Exception as e:
            log.warning("Cannot parse account: %s", e)
    return accounts


def get_acme_orders():
    orders = []
    for row in db.session.query(AcmeOrder).all():
        try:
            key = row.nkey.hex()
            value = json.loads(row.nvalue)
            orders.append({"nkey": key, "data": value})
        except Exception as e:
            log.warning("Cannot parse order: %s", e)
    return orders


def get_acme_certs():
    certs = []
    for row in db.session.query(AcmeCert).all():
        try:
            key = row.nkey.hex()
            value = json.loads(row.nvalue)
            parsed_info = parse_cert(value["leaf"]) if "leaf" in value else {}
            certs.append({"nkey": key, "data": {**value, **parsed_info}})
        except Exception as e:
            log.warning("Cannot parse ACME cert: %s", e)
    return certs


def get_acme_authzs():
    authzs = []
    for row in db.session.query(AcmeAuthz).all():
        try:
            key = row.nkey.hex()
            value = json.loads(row.nvalue)
            authzs.append({"nkey": key, "data": value})
        except Exception as e:
            log.warning("Cannot parse ACME authz: %s", e)
    return authzs


def get_acme_challenges():
    challenges = []
    for row in db.session.query(AcmeChallenge).all():
        try:
            key = row.nkey.hex()
            value = json.loads(row.nvalue)
            challenges.append({"nkey": key, "data": value})
        except Exception as e:
            log.warning("Cannot parse ACME challenge: %s", e)
    return challenges
