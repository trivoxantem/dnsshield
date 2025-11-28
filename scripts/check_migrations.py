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
    cur.execute("SELECT id, app, name, applied FROM django_migrations WHERE app='app' ORDER BY applied;")
    rows = cur.fetchall()
    print('MIGRATIONS for app:')
    for r in rows:
        print(r)
    cur.close()
    conn.close()
except Exception as e:
    print('ERROR:', e)
    sys.exit(1)
