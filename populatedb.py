from argon2 import PasswordHasher
from psycopg2 import pool

import psycopg2

ph = PasswordHasher()

DB_CONFIG = {
    "dbname": "mensajes",
    "user": "mensajes_user",
    "password": "PasswordSegura123!",
    "host": "localhost",
    "port": 5432
}

try:
    conexion_pool = pool.ThreadedConnectionPool(1, 90, **DB_CONFIG)
except psycopg2.DatabaseError as e:
    print(f"Error al inicializar el pool: {e}")
    conexion_pool = None

def get_connection():
    """Obtiene una conexión libre del pool."""
    if conexion_pool:
        return conexion_pool.getconn()
    else:
        raise Exception("El pool de conexiones no está disponible.")

def release_connection(conn):
    """Devuelve la conexión al pool para que otro hilo pueda usarla."""
    if conexion_pool and conn:
        conexion_pool.putconn(conn)