
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

def get_active_provisioner_map(provisioners):
    """
    Returns a map (dictionary) where the key is the 'id' and the value is the 'name'
    from a list of provisioner data, excluding provisioners that have 'deletedAt' set
    to '0001-01-01T00:00:00Z'.

    :param provisioners: List of provisioner dictionaries
    :return: A dictionary with provisioner 'id' as the key and 'name' as the value
    """
    provisioner_map = {
        provisioner['data']['id']: provisioner['data']['name']
        for provisioner in provisioners
        if provisioner['data'].get('deletedAt', '') == '0001-01-01T00:00:00Z'
    }
    return provisioner_map






def get_step_admins():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT nkey, nvalue FROM admins")
    admins = []
    for row in cur.fetchall():
        
        try:
            key = bytes(row[0]).decode("utf-8", errors="ignore")
            value = json.loads(bytes(row[1]))
            if value.get("deletedAt", "") == "0001-01-01T00:00:00Z":

                admins.append({
                    "nkey": key,
                    "data": value
                })
        except Exception as e:
            print("Error parsing admin:", e)
    conn.close()
    return admins

