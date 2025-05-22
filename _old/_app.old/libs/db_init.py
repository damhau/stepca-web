from .db_conn import get_connection

def create_jwk_keys_table():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS jwk_keys (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            jwk JSONB NOT NULL
        )
    """)
    conn.commit()
    conn.close()