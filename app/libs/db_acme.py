import json
from .cert_utils import parse_cert
from .db_conn import get_connection

def get_acme_accounts():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT nkey, nvalue FROM acme_accounts")
    accounts = []
    for row in cur.fetchall():
        try:
            # Assume nkey is stored as UTF-8 text; if not, adjust accordingly.
            key = bytes(row[0]).decode('utf-8', errors='ignore')
            value = json.loads(bytes(row[1]))
            accounts.append({
                "nkey": key,
                "data": value
            })
        except Exception as e:
            print("Error parsing account:", e)
    conn.close()
    return accounts

def get_acme_orders():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT nkey, nvalue FROM acme_orders")
    orders = []
    for row in cur.fetchall():
        try:
            key = bytes(row[0]).hex()
            value = json.loads(bytes(row[1]))
            orders.append({
                "nkey": key,
                "data": value
            })
        except Exception as e:
            print("Error parsing order:", e)
    conn.close()
    return orders

def get_acme_certs():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT nkey, nvalue FROM acme_certs")
    certs = []

    for row in cur.fetchall():
        try:
            key = bytes(row[0]).hex()
            value = json.loads(bytes(row[1]))

            # Try to parse the leaf certificate if present
            parsed_info = {}
            if "leaf" in value:
                parsed_info = parse_cert(value["leaf"])

            certs.append({
                "nkey": key,
                "data": {
                    **value,
                    **parsed_info
                }
            })
        except Exception as e:
            print("❌ Error parsing ACME cert:", e)
    conn.close()
    return certs

def get_acme_authzs():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT nkey, nvalue FROM acme_authzs")
    authzs = []
    for row in cur.fetchall():
        try:
            key = bytes(row[0]).hex()
            value = json.loads(bytes(row[1]))
            authzs.append({
                "nkey": key,
                "data": value
            })
        except Exception as e:
            print("Error parsing ACME authz:", e)
    conn.close()
    return authzs

def get_acme_challenges():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT nkey, nvalue FROM acme_challenges")
    challenges = []
    for row in cur.fetchall():
        try:
            key = bytes(row[0]).hex()
            value = json.loads(bytes(row[1]))
            challenges.append({
                "nkey": key,
                "data": value
            })
        except Exception as e:
            print("Error parsing ACME challenge:", e)
    conn.close()
    return challenges




# def parse_cert(leaf_b64):
#     try:
#         # Step 1: base64 decode
#         pem_bytes = base64.b64decode(leaf_b64)

#         # Step 2: extract the PEM certificate block
#         pem_str = pem_bytes.decode("utf-8", errors="ignore")
#         pem_match = re.search(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", pem_str, re.DOTALL)
#         if not pem_match:
#             return {"subject": "[invalid PEM format]", "not_before": "—", "not_after": "—", "serial": "—"}

#         cert_pem = f"-----BEGIN CERTIFICATE-----{pem_match.group(1)}-----END CERTIFICATE-----"

#         # Step 3: parse with x509
#         cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"), default_backend())
#         # Try to get Subject Alternative Names
#         try:
#             san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
#             san = san_ext.value.get_values_for_type(x509.DNSName)
#         except x509.ExtensionNotFound:
#             san = []

#         return {
#             "subject": cert.subject.rfc4514_string(),
#             "issuer": cert.issuer.rfc4514_string(),
#             "not_before": cert.not_valid_before.isoformat(),
#             "not_after": cert.not_valid_after.isoformat(),
#             "serial": format(cert.serial_number, "x"), 
#             "dns_names": san
#         }
#     except Exception as e:
#         return {
#             "subject": "[error decoding cert]",
#             "issuer": "[error decoding cert]",
#             "dns_names": [],
#             "not_before": "—",
#             "not_after": "—",
#             "serial": "—",
#             "error": str(e)
#         }

def get_acme_cert_by_id(cert_id: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT nkey, nvalue FROM acme_certs")
    certs = []

    for row in cur.fetchall():
        try:
            key = bytes(row[0]).hex()
            value = json.loads(bytes(row[1]))

            # Try to parse the leaf certificate if present
            parsed_info = {}
            if "leaf" in value:
                parsed_info = parse_cert(value["leaf"])

            certs.append({
                "nkey": key,
                "data": {
                    **value,
                    **parsed_info
                }
            })
        except Exception as e:
            print("❌ Error parsing ACME cert:", e)
    for cert in certs:
        if cert["data"]["id"] == cert_id:
            return cert

    return None


# def get_acme_cert_by_id(cert_id: str):
#     conn = get_connection()
#     cur = conn.cursor()
#     cur.execute("SELECT nvalue FROM acme_certs WHERE nkey = %s", (bytes.fromhex(cert_id),))
#     row = cur.fetchone()
#     conn.close()

#     if row:
#         try:
#             value = json.loads(bytes(row[0]))
#             if "leaf" in value:
#                 parsed = parse_cert(value["leaf"])
#                 return {**value, **parsed}
#             return value
#         except Exception as e:
#             return {"error": f"Failed to parse cert: {str(e)}"}
#     return None


