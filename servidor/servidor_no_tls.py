from concurrent.futures import ThreadPoolExecutor
from servidor.util.populatedb import get_connection, release_connection
from argon2 import PasswordHasher

import socket
import psycopg2

HOST = "127.0.0.1"
PORT = 5000

MAX_USERS = 50

ph = PasswordHasher()

def register_user(username, password):
    '''
    Función para registrar un usuario.
    '''

    # Se hashea la contraseña antes de iniciar la conexión con la BD
    password_hash = ph.hash(password)

    # Se establece conexión con la BD
    conn = get_connection()

    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users(username,password_hash) VALUES(%s,%s) RETURNING id",
            (username, password_hash)
        )
        # Se obtiene directamente el id del usuario recién registrado
        user_id = cur.fetchone()[0]

        conn.commit()
        cur.close()

        return True, user_id, "Usuario registrado exitosamente\n"

    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return False, None, "Usuario ya registrado\n"

    finally:
        release_connection(conn)


def login_user(username, password):
    '''
    Función para iniciar sesión de un usuario.
    '''

    # Se establece conexión con la BD
    conn = get_connection()

    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id,password_hash FROM users WHERE username=%s",
            (username,)
        )
        row = cur.fetchone()
        cur.close()
    finally:
        release_connection(conn)

    
    if not row:
        return False, None, "ERROR: credenciales inválidas\n"
            
    user_id, stored_hash = row

    # Se verifica la contraseña con la conexión a la BD ya cerrada para agilizar
    try:
        ph.verify(stored_hash, password)
        return True, user_id, "Inicio de sesion exitoso\n"
    
    except Exception:
        return False, None, "ERROR: credenciales inválidas\n"


def save_message(user_id, message):
    '''
    Función para guardar un mensaje en la BD.
    '''
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

            if option.strip().upper() not in ["L","R"]:
                    conn.send(b"Error: Opcion invalida\n")
                    continue

            conn.send(b"Introduzca usuario y password")
            data = conn.recv(1024).decode().strip()

            if "|" not in data:
                conn.send(b"Error: Formato invalido")
                continue

            username, password = data.split("|", 1)

            if option == "R":
                success, u_id, msg = register_user(username, password)
            else:
                success, u_id, msg = login_user(username, password)

            if success:
                user_id = u_id
                authenticated = True
                respuesta_completa = f"{msg}Escriba su mensaje (max 144 chars):\n"
                conn.send(respuesta_completa.encode())
            else:
                conn.send(msg.encode())

        # --- FASE DE MENSAJERÍA ---
        while authenticated:
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
            if cont.upper() != "S":
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
        print(f">>> Servidor TCP (TEXTO PLANO / SIN TLS) escuchando en {HOST}:{PORT}...")

        with ThreadPoolExecutor(max_workers=MAX_USERS) as executor:
            while True:
                conn, addr = sock.accept()
                executor.submit(handle_client, conn, addr)

if __name__ == "__main__":
    from servidor.util.limpiar_bd import reset_database

    try:
        reset_database()
        start_server()
    except KeyboardInterrupt:
        print("\n\n>>> Servidor detenido manualmente. Cerrando...")