from concurrent.futures import ThreadPoolExecutor
from populatedb import get_connection, release_connection
from argon2 import PasswordHasher

import socket
import psycopg2

HOST = "127.0.0.1"
PORT = 5000

MAX_USERS = 50

ph = PasswordHasher()

def register_user(username, password):
    conn = get_connection()
    try:
        cur = conn.cursor()
        password_hash = ph.hash(password)
        cur.execute(
            "INSERT INTO users(username,password_hash) VALUES(%s,%s)",
            (username, password_hash)
        )
        conn.commit()
        cur.close()
        return "Usuario registrado exitosamente"

    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return "Usuario ya registrado"

    finally:
        release_connection(conn)

def login_user(username, password):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id,password_hash FROM users WHERE username=%s",
            (username,)
        )
        row = cur.fetchone()
        cur.close()

        if not row:
            return None
            
        user_id, stored_hash = row

        ph.verify(stored_hash, password)
        return user_id
    except Exception:
        return None
    finally:
        release_connection(conn)

def save_message(user_id, message):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO messages(user_id,message) VALUES(%s,%s)",
            (user_id, message)
        )
        conn.commit()
        cur.close()
    finally:
        release_connection(conn)


# #############################################################
# CONTROLADOR PARA UN SOLO CLIENTE (SIN TLS)
# #############################################################

def handle_client(conn, addr):
    """Atiende a un cliente en su propio hilo usando un socket TCP en texto plano."""
    try:
        user_id = None
        authenticated = False

        # --- FASE DE AUTENTICACIÓN ---
        while not authenticated:
            conn.send(b"Login (L) o Registro (R)?")
            option = conn.recv(1024).decode().upper()

            conn.send(b"Introduzca usuario y password")
            data = conn.recv(1024).decode()

            if "|" not in data:
                conn.send(b"Error: Formato invalido")
                continue

            username, password = data.split("|", 1)

            if option == "R":
                msg = register_user(username, password)
                if "exitosamente" in msg:
                    user_id = login_user(username, password)
                    authenticated = True
                conn.send(msg.encode())
            else:
                user_id = login_user(username, password)
                if user_id:
                    conn.send(b"Inicio de sesion exitoso")
                    authenticated = True
                else:
                    conn.send(b"Error: Credenciales invalidas")

        # --- FASE DE MENSAJERÍA ---
        while authenticated:
            conn.send(b"Escriba su mensaje (max 144 chars):")
            message = conn.recv(1024).decode()

            if not message or message.lower() == "exit":
                break

            if len(message) > 144:
                conn.send(b"ERROR: Mensaje demasiado largo")
            else:
                save_message(user_id, message)
                conn.send(b"OK: Mensaje guardado")

            conn.send(b"Desea enviar otro mensaje? (S/N)")
            cont = conn.recv(1024).decode().upper()
            if cont != "S":
                conn.send(b"Cerrando conexion. Adios.")
                break

    except Exception as e:
        print(f"[ERROR] Cliente {addr}: {e}")
    finally:
        conn.close()


# ##########################################
# ARRANQUE DEL SERVIDOR SIN TLS
# ##########################################

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(500)
        print(f"Servidor TCP (TEXTO PLANO / SIN TLS) escuchando en {HOST}:{PORT}...")

        with ThreadPoolExecutor(max_workers=MAX_USERS) as executor:
            while True:
                conn, addr = sock.accept()
                executor.submit(handle_client, conn, addr)

if __name__ == "__main__":
    start_server()