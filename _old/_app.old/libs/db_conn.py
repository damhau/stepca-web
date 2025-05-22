import psycopg2

from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, DB_PORT

def get_connection():
    return psycopg2.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        dbname=DB_NAME,
        port=DB_PORT
    )