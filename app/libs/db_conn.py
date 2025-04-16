import psycopg2

def get_connection():
    # Update with your PostgreSQL credentials.
    return psycopg2.connect(host='localhost', user='step-ca',
                              password='step-ca', 
                              dbname='step_ca_db', port=5432)
