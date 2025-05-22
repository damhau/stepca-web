# import json
# from .cert_utils import parse_cert
# from .db_conn import get_connection

# def get_acme_accounts():
#     conn = get_connection()
#     cur = conn.cursor()
#     cur.execute("SELECT nkey, nvalue FROM acme_accounts")
#     accounts = []
#     for row in cur.fetchall():
#         try:
#             # Assume nkey is stored as UTF-8 text; if not, adjust accordingly.
#             key = bytes(row[0]).decode('utf-8', errors='ignore')
#             value = json.loads(bytes(row[1]))
#             accounts.append({
#                 "nkey": key,
#                 "data": value
#             })
#         except Exception as e:
#             print("Error parsing account:", e)
#     conn.close()
#     return accounts

# def get_acme_orders():
#     conn = get_connection()
#     cur = conn.cursor()
#     cur.execute("SELECT nkey, nvalue FROM acme_orders")
#     orders = []
#     for row in cur.fetchall():
#         try:
#             key = bytes(row[0]).hex()
#             value = json.loads(bytes(row[1]))
#             orders.append({
#                 "nkey": key,
#                 "data": value
#             })
#         except Exception as e:
#             print("Error parsing order:", e)
#     conn.close()
#     return orders

# def get_acme_certs():
#     conn = get_connection()
#     cur = conn.cursor()
#     cur.execute("SELECT nkey, nvalue FROM acme_certs")
#     certs = []

#     for row in cur.fetchall():
#         try:
#             key = bytes(row[0]).hex()
#             value = json.loads(bytes(row[1]))

#             # Try to parse the leaf certificate if present
#             parsed_info = {}
#             if "leaf" in value:
#                 parsed_info = parse_cert(value["leaf"])

#             certs.append({
#                 "nkey": key,
#                 "data": {
#                     **value,
#                     **parsed_info
#                 }
#             })
#         except Exception as e:
#             print("❌ Error parsing ACME cert:", e)
#     conn.close()
#     return certs

# def get_acme_authzs():
#     conn = get_connection()
#     cur = conn.cursor()
#     cur.execute("SELECT nkey, nvalue FROM acme_authzs")
#     authzs = []
#     for row in cur.fetchall():
#         try:
#             key = bytes(row[0]).hex()
#             value = json.loads(bytes(row[1]))
#             authzs.append({
#                 "nkey": key,
#                 "data": value
#             })
#         except Exception as e:
#             print("Error parsing ACME authz:", e)
#     conn.close()
#     return authzs

# def get_acme_challenges():
#     conn = get_connection()
#     cur = conn.cursor()
#     cur.execute("SELECT nkey, nvalue FROM acme_challenges")
#     challenges = []
#     for row in cur.fetchall():
#         try:
#             key = bytes(row[0]).hex()
#             value = json.loads(bytes(row[1]))
#             challenges.append({
#                 "nkey": key,
#                 "data": value
#             })
#         except Exception as e:
#             print("Error parsing ACME challenge:", e)
#     conn.close()
#     return challenges


# def get_acme_cert_by_id(cert_id: str):
#     conn = get_connection()
#     cur = conn.cursor()
#     cur.execute("SELECT nkey, nvalue FROM acme_certs")
#     certs = []

#     for row in cur.fetchall():
#         try:
#             key = bytes(row[0]).hex()
#             value = json.loads(bytes(row[1]))

#             # Try to parse the leaf certificate if present
#             parsed_info = {}
#             if "leaf" in value:
#                 parsed_info = parse_cert(value["leaf"])

#             certs.append({
#                 "nkey": key,
#                 "data": {
#                     **value,
#                     **parsed_info
#                 }
#             })
#         except Exception as e:
#             print("❌ Error parsing ACME cert:", e)
#     for cert in certs:
#         if cert["data"]["id"] == cert_id:
#             return cert

#     return None



import json
from .cert_utils import parse_cert
from app.models.acme import AcmeAccount, AcmeOrder, AcmeCert, AcmeAuthz, AcmeChallenge
from app.extensions import db


def get_acme_accounts():
    accounts = []
    for row in db.session.query(AcmeAccount).all():
        try:
            key = row.nkey.decode('utf-8', errors='ignore')
            value = json.loads(row.nvalue)
            accounts.append({"nkey": key, "data": value})
        except Exception as e:
            print("Error parsing account:", e)
    return accounts


def get_acme_orders():
    orders = []
    for row in db.session.query(AcmeOrder).all():
        try:
            key = row.nkey.hex()
            value = json.loads(row.nvalue)
            orders.append({"nkey": key, "data": value})
        except Exception as e:
            print("Error parsing order:", e)
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
            print("❌ Error parsing ACME cert:", e)
    return certs


def get_acme_authzs():
    authzs = []
    for row in db.session.query(AcmeAuthz).all():
        try:
            key = row.nkey.hex()
            value = json.loads(row.nvalue)
            authzs.append({"nkey": key, "data": value})
        except Exception as e:
            print("Error parsing ACME authz:", e)
    return authzs


def get_acme_challenges():
    challenges = []
    for row in db.session.query(AcmeChallenge).all():
        try:
            key = row.nkey.hex()
            value = json.loads(row.nvalue)
            challenges.append({"nkey": key, "data": value})
        except Exception as e:
            print("Error parsing ACME challenge:", e)
    return challenges


def get_acme_cert_by_id(cert_id: str):
    for row in db.session.query(AcmeCert).all():
        try:
            key = row.nkey.hex()
            value = json.loads(row.nvalue)
            parsed_info = parse_cert(value["leaf"]) if "leaf" in value else {}
            data = {**value, **parsed_info}
            if data.get("id") == cert_id:
                return {"nkey": key, "data": data}
        except Exception as e:
            print("❌ Error parsing ACME cert:", e)
    return None