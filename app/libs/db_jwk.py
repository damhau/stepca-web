from .db_conn import get_connection
import json

def get_jwk_keys():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name, jwk FROM jwk_keys ORDER BY id ASC")
    keys = [{"id": row[0], "name": row[1], "jwk": row[2]} for row in cur.fetchall()]
    conn.close()
    return keys

def add_jwk_key(name, jwk_json):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO jwk_keys (name, jwk) VALUES (%s, %s)", (name, json.dumps(jwk_json)))
    conn.commit()
    conn.close()

def delete_jwk_key(key_id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM jwk_keys WHERE id = %s", (key_id,))
    conn.commit()
    conn.close()


def get_jwk_key_by_id(id):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name, jwk FROM jwk_keys WHERE id = %s", (id,))
    row = cur.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "provisioner_name": row[1], "jwk": row[2]}
    return None


def get_jwk_key_by_provisioner_name(provisioner_name):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name, jwk FROM jwk_keys WHERE name = %s", (provisioner_name,))
    row = cur.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "provisioner_name": row[1], "jwk": row[2]}
    return None


