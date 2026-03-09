from argon2 import PasswordHasher
import psycopg2

ph = PasswordHasher()

DB_CONFIG = {
    "dbname": "mensajes",
    "user": "mensajes_user",
    "password": "PasswordSegura123!",
    "host": "localhost",
    "port": 5432
}

def get_connection():
    return psycopg2.connect(**DB_CONFIG)
