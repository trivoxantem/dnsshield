import psycopg2
import sys

try:
    conn = psycopg2.connect(
        dbname='nexadb',
        user='nexa2025',
        password='Nexa12345678',
        host='nexa.c0lewiuc69lh.us-east-1.rds.amazonaws.com',
        port='5432'
    )
    cur = conn.cursor()
    cur.execute("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname='public' ORDER BY tablename;")
    rows = cur.fetchall()
    print('TABLES:')
    for r in rows:
        print('-', r[0])
    cur.close()
    conn.close()
except Exception as e:
    print('ERROR:', e)
    sys.exit(1)
