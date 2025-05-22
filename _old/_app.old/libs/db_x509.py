
import json

from .cert_utils import parse_cert_from_bytes
from .db_conn import get_connection
from .db_step import get_step_provisioners
from datetime import datetime
import pytz 

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

def revoke_certificate(cert_id):
    conn = get_connection()
    cur = conn.cursor()
    
    try:
        # Example SQL for marking a certificate as revoked
        cur.execute("UPDATE x509_certs SET revoked = TRUE WHERE nkey = %s", (cert_id,))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error revoking certificate {cert_id}: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()


def get_x509_active_certs():
    def filter_non_revoked_certs(x509_certs, revoked_certs):
        # Step 1: Extract serial numbers from revoked certificates
        revoked_serials = {cert['data']['Serial'] for cert in revoked_certs}

        # Step 2: Filter the x509 certificates to exclude revoked ones and check for valid dates
        non_revoked_certs = []

        for cert in x509_certs:
            cert_serial = cert['nkey']
            cert_data = cert['data']
            cert_not_before = cert_data.get("not_before")
            cert_not_after = cert_data.get("not_after")

            # Check if the certificate is revoked
            if cert_serial in revoked_serials:
                continue

            # Check for valid date range
            try:
                # Parse the 'not_before' and 'not_after' fields as aware datetime objects
                not_before_dt = datetime.fromisoformat(cert_not_before.replace("Z", "+00:00")).astimezone(pytz.UTC)
                not_after_dt = datetime.fromisoformat(cert_not_after.replace("Z", "+00:00")).astimezone(pytz.UTC)
                current_dt = datetime.utcnow().replace(tzinfo=pytz.UTC)

                if not_before_dt > current_dt:
                    pass 
                elif not_after_dt < current_dt:
                    pass 
                else:

                    
                    non_revoked_certs.append(cert)



            except Exception as e:
                print(f"Error processing certificate {cert_serial}: {e}")
                # You can choose to include certificates with invalid dates if needed:
                # non_revoked_certs.append(cert)  # Uncomment this if you want to include them

        # Step 3: Return the non-revoked certificates

        # # Check if this cert exists in generated_certs
        # for cert in non_revoked_certs:
        #     nkey = cert['nkey']
        #     cur.execute("SELECT 1 FROM generated_certs WHERE common_name = %s", (data['subject']['CN'],))
        #     exists = cur.fetchone() is not None

        #     certs.append({
        #         "nkey": nkey,
        #         "data": data,
        #         "is_generated": exists
        #     })
        generated_certs = get_generated_certs()
        serials_from_first = {item["serial"] for item in generated_certs}

        updated_second_list = []
        for item in non_revoked_certs:
            # Make a deep copy if you don't want to modify the original input
            new_item = item.copy()
            new_item["data"] = item["data"].copy()
            
            # If serial matches, add 'generated': True
            if new_item["data"]["serial"] in serials_from_first:
                new_item["data"]["generated"] = True
            else:
                new_item["data"]["generated"] = False
            
            updated_second_list.append(new_item)

        return updated_second_list

    # Example usage:
    x509_certs = get_x509_certs()  # Get the list of all x509 certificates
    revoked_certs = get_revoked_x509_certs()  # Get the list of revoked certificates

    # Filter non-revoked certificates
    non_revoked_certs = filter_non_revoked_certs(x509_certs, revoked_certs)

    # Output the non-revoked certificates
    return non_revoked_certs


def create_generated_certs_table():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS generated_certs (
            id SERIAL PRIMARY KEY,
            serial TEXT NOT NULL,
            common_name TEXT NOT NULL,
            provisioner TEXT NOT NULL,
            csr TEXT NOT NULL,
            certificate TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def save_generated_cert(serial, common_name, provisioner, csr_pem, cert_pem):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO generated_certs (serial, common_name, provisioner, csr, certificate)
        VALUES (%s, %s, %s, %s,  %s)
    """, (serial, common_name, provisioner, csr_pem, cert_pem))
    conn.commit()
    conn.close()

def get_generated_certs():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, serial, common_name, provisioner, created_at, csr, certificate FROM generated_certs ORDER BY created_at DESC
    """)
    rows = cur.fetchall()
    conn.close()
    certs = []
    for row in rows:
        certs.append({
            "id": row[0],
            "serial": row[1],
            "common_name": row[2],
            "provisioner": row[3],
            "created_at": row[4],
            "csr": row[5],
            "certificate": row[6]
        })
    return certs




def get_generated_cert_by_serial(serial):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, serial, common_name, provisioner, created_at, csr, certificate FROM generated_certs WHERE serial = %s", (serial,))
    row = cur.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "serial": row[1], "common_name": row[2], "provisioner": row[3], "created_at": row[4], "csr": row[5], "certificate": row[6]}
    return None