
import json

from .cert_utils import parse_cert_from_bytes
from .db_conn import get_connection
from .db_step import get_step_provisioners

def get_x509_certs():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT nkey, nvalue FROM x509_certs")
    rows = cur.fetchall()
    conn.close()

    certs = []
    for row in rows:
        try:
            cert_id = bytes(row[0]).hex()
            cert_bytes = bytes(row[1])  # raw cert
            # Try to decode directly (assuming DER or PEM)
            parsed = parse_cert_from_bytes(cert_bytes)
            cert_metadata = get_x509_certs_data_by_id(cert_id)

            certs.append({
                "nkey": cert_id,
                "data": parsed,
                "provisioner": cert_metadata["data"]["provisioner"]
            })
        except Exception as e:
            certs.append({
                "nkey": bytes(row[0]).hex(),
                "data": {"subject": "[error decoding cert]", "error": str(e)}
            })
    return certs


def get_x509_certs_by_id(id: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT nkey, nvalue FROM x509_certs")
    rows = cur.fetchall()
    conn.close()

    certs = []
    for row in rows:
        try:
            cert_id = bytes(row[0]).hex()
            cert_bytes = bytes(row[1])  # raw cert
            # Try to decode directly (assuming DER or PEM)
            parsed = parse_cert_from_bytes(cert_bytes)
            cert_metadata = get_x509_certs_data_by_id(cert_id)

            certs.append({
                "nkey": cert_id,
                "data": parsed,
                "provisioner": cert_metadata["data"]["provisioner"]
            })
        except Exception as e:
            certs.append({
                "nkey": bytes(row[0]).hex(),
                "data": {"subject": "[error decoding cert]", "error": str(e)}
            })
    for cert in certs:
        if cert["nkey"] == id:
            return cert
    return None

def get_x509_certs_data():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT nkey, nvalue FROM x509_certs_data")
    rows = cur.fetchall()
    conn.close()

    results = []
    for row in rows:
        try:
            serial = bytes(row[0]).hex()
            value = json.loads(bytes(row[1]))
            results.append({
                "nkey": serial,
                "data": value
            })
        except Exception as e:
            results.append({
                "nkey": bytes(row[0]).hex(),
                "data": {"error": str(e)}
            })
    return results

def get_x509_certs_data_by_id(id: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT nkey, nvalue FROM x509_certs_data")
    rows = cur.fetchall()
    conn.close()

    results = []
    for row in rows:
        try:
            serial = bytes(row[0]).hex()
            value = json.loads(bytes(row[1]))
            results.append({
                "nkey": serial,
                "data": value
            })
        except Exception as e:
            results.append({
                "nkey": bytes(row[0]).hex(),
                "data": {"error": str(e)}
            })

    for result in results:


        if result["nkey"] == id:
            return result
    return None

def get_revoked_x509_certs():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT nkey, nvalue FROM revoked_x509_certs")
    rows = cur.fetchall()
    conn.close()

    certs = []
    for row in rows:
        try:
            serial = bytes(row[0]).hex()
            value = json.loads(bytes(row[1]))
            certs.append({
                "nkey": serial,
                "data": value
            })
        except Exception as e:
            certs.append({
                "nkey": bytes(row[0]).hex(),
                "data": {"error": str(e)}
            })
    return certs


def get_revoked_x509_with_cert_info():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT nkey, nvalue FROM revoked_x509_certs")
    revocations = []
    rows = cur.fetchall()


    # Load x509 certs metadata once
    all_cert_data = get_x509_certs()
    cert_map = {c["nkey"]: c["data"] for c in all_cert_data if "nkey" in c}
    # print("Cert map:", cert_map)
    provisioners = get_step_provisioners()  # however you load them
    prov_map = {p["data"]["id"]: p["data"]["name"] for p in provisioners if "data" in p}
    
    for row in rows:
        try:
            key = bytes(row[0]).hex()
            
            value = json.loads(bytes(row[1]))
            serial_hex = value["Serial"].lower()

            cert_info = cert_map.get(serial_hex, None)
            
            prov_id = value.get("ProvisionerID")
            provisioner_name = prov_map.get(prov_id, "—")
            
            value["provisioner_name"] = provisioner_name

            revocations.append({
                "nkey": key,
                "data": value,
                "cert": cert_info
            })
        except Exception as e:
            revocations.append({
                "nkey": bytes(row[0]).hex(),
                "data": {"error": str(e)}
            })
    conn.close()
    return revocations
