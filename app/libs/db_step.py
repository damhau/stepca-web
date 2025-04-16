
import base64
import json
from .db_conn import get_connection


def get_step_provisioners():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT nkey, nvalue FROM provisioners")
    accounts = []
    for row in cur.fetchall():
        try:
            # Assume nkey is stored as UTF-8 text; if not, adjust accordingly.
            key = bytes(row[0]).decode('utf-8', errors='ignore')
            value = json.loads(bytes(row[1]))

            details_bytes = base64.b64decode(value["details"])
            # Step 2: parse JSON
            details_json = json.loads(details_bytes)



            accounts.append({
                "nkey": key,
                "data": value,
                "details": details_json
            })
        except Exception as e:
            print("Error parsing account:", e)
    conn.close()
    return accounts

def get_step_admins():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT nkey, nvalue FROM admins")
    admins = []
    for row in cur.fetchall():
        try:
            key = bytes(row[0]).decode("utf-8", errors="ignore")
            value = json.loads(bytes(row[1]))
            admins.append({
                "nkey": key,
                "data": value
            })
        except Exception as e:
            print("Error parsing admin:", e)
    conn.close()
    return admins
