from concurrent.futures import ThreadPoolExecutor
from servidor.util.populatedb import get_connection, release_connection
from argon2 import PasswordHasher

import socket
import ssl
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
# CONTRALADOR PARA UN SOLO CLIENTE (UN CLIENTE SUPONE UN HILO)
# #############################################################

def handle_client(conn, addr, context):
    """
    Atiende a un cliente en su propio hilo del pool.
    """
    try:
        with context.wrap_socket(conn, server_side=True) as secure_conn:
            # --- LÍNEA PARA VERIFICAR EL CIPHER ---
            nombre, version, bits = secure_conn.cipher()
            print(f"[*] Conexión segura con {addr}")
            print(f"[*] Protocolo: {version} | Cipher: {nombre} | Bits: {bits}")
            # ---------------------------------------

            user_id = None
            authenticated = False

            # --- FASE DE AUTENTICACIÓN ---
            while not authenticated:
                secure_conn.send(b"Login (L) o Registro (R)?\n")
                option = secure_conn.recv(1024).decode().upper()

                if option.strip().upper() not in ["L","R"]:
                    secure_conn.send(b"Error: Opcion invalida\n")
                    continue

                secure_conn.send(b"Introduzca usuario y password\n")
                data = secure_conn.recv(1024).decode().strip()

                if "|" not in data:
                    secure_conn.send(b"Error: Formato invalido\n")
                    continue

                username, password = data.split("|", 1)

                if option.strip().upper() == "R":
                    success, u_id, msg = register_user(username, password)
                else:
                    success, u_id, msg = login_user(username, password)

                if success:
                    user_id = u_id
                    authenticated = True
                    respuesta_completa = f"{msg}Escriba su mensaje (max 144 chars):\n"
                    secure_conn.send(respuesta_completa.encode())
                else:
                    secure_conn.send(msg.encode())

            # --- FASE DE MENSAJERÍA ---
            while authenticated:
                message = secure_conn.recv(1024).decode().strip()

                if not message or message.lower() == "exit":
                    break

                if len(message) > 144:
                    secure_conn.send(b"ERROR: Mensaje demasiado largo\n")
                else:
                    save_message(user_id, message)
                    secure_conn.send(b"OK: Mensaje guardado\n")

                secure_conn.send(b"Desea enviar otro mensaje? (S/N)\n")
                cont = secure_conn.recv(1024).decode().strip().upper()
                if cont.upper() != "S":
                    secure_conn.send(b"Cerrando conexion. Adios.\n")
                    break

    except Exception as e:
        print(f"[ERROR] Cliente {addr}: {e}")
    finally:
        conn.close()


# ##########################################
# ARRANQUE DEL SERVIDOR CON MÚLTIPLES HILOS
# ##########################################

def start_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    # Definimos los suites más robustos (AES-256 y ChaCha20)
    ciphers_13 = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
    
    # Intentamos aplicarlos de forma robusta
    try:
        if hasattr(context, 'set_ciphersuites'):
            context.set_ciphersuites(ciphers_13)
            print("[INFO] Cipher Suites TLS 1.3 configurados: AES-256/ChaCha20")
        else:
            # Si el sistema no soporta el método, usamos set_ciphers para versiones compatibles
            # o dejamos que TLS 1.3 use sus valores seguros por defecto.
            print("[AVISO] El sistema no permite restricción manual de suites 1.3. Usando valores seguros por defecto.")
    except Exception as e:
        print(f"[ERROR] Al configurar Ciphers: {e}")

    context.load_cert_chain(certfile="./certificados/servidor_cert.pem", keyfile="./certificados/servidor_key.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(500)
        print(f">>> Servidor TLS escuchando en {HOST}:{PORT}...")

        with ThreadPoolExecutor(max_workers=MAX_USERS) as executor:
            while True:
                conn, addr = sock.accept()
                executor.submit(handle_client, conn, addr, context)

if __name__ == "__main__":
    from servidor.util.limpiar_bd import reset_database

    try:
        reset_database()
        start_server()
    except KeyboardInterrupt:
        print("\n\n>>> Servidor detenido manualmente. Cerrando...")