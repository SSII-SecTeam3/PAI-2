from servidor.util.populatedb import get_connection, release_connection
from argon2 import PasswordHasher
import psycopg2

def reset_database():
    ph = PasswordHasher()
    users_to_create = [
        ("prueba1", "1234"),
        ("prueba2", "1234")
    ]
    
    conn = get_connection()
    try:
        cur = conn.cursor()
        
        # 1. Limpieza total de las tablas
        print(">> Reiniciando la base de datos...")
        cur.execute("DELETE FROM messages; DELETE FROM users;")
        
        # 2. Creación de usuarios por defecto
        for username, password in users_to_create:
            password_hash = ph.hash(password)
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                (username, password_hash)
            )
            print(f" - Usuario '{username}' creado. Contraseña: '{password}'")
            
        conn.commit()
        cur.close()
        print("\nBase de datos restaurada con éxito.")

    except Exception as e:
        conn.rollback()
        print(f"Error durante la restauración: {e}")
    finally:
        release_connection(conn)

if __name__ == "__main__":
    reset_database()