import socket
import ssl
import psycopg2
from populatedb import get_connection
from argon2 import PasswordHasher

HOST = "127.0.0.1"
PORT = 5000

ph = PasswordHasher()

def register_user(username, password):
    conn = get_connection()
    cur = conn.cursor()
    try:
        password_hash = ph.hash(password)
        cur.execute(
            "INSERT INTO users(username,password_hash) VALUES(%s,%s)",
            (username, password_hash)
        )
        conn.commit()
        return "Usuario registrado exitosamente"

    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return "Usuario ya registrado"

    finally:
        cur.close()
        conn.close()

def login_user(username, password):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id,password_hash FROM users WHERE username=%s",
        (username,)
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return None
    user_id, stored_hash = row

    try:
        ph.verify(stored_hash, password)
        return user_id
    except:
        return None

def save_message(user_id, message):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO messages(user_id,message) VALUES(%s,%s)",
        (user_id, message)
    )
    conn.commit()
    cur.close()
    conn.close()

def start_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile="servidor_cert.pem", keyfile="servidor_key.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(5)
        print("Servidor TLS escuchando...")
        
        while True:
            conn, addr = sock.accept() # Nota: wrap después del accept
            with context.wrap_socket(conn, server_side=True) as secure_conn:
                user_id = None
                authenticated = False
                
                while not authenticated:
                    secure_conn.send(b"Login (L) o Registro (R)?")
                    option = secure_conn.recv(1024).decode().upper()

                    secure_conn.send(b"Introduzca usuario y password")
                    data = secure_conn.recv(1024).decode()
                    
                    if "|" not in data:
                        secure_conn.send(b"Error: Formato invalido")
                        continue
                    
                    username, password = data.split("|")

                    if option == "R":
                        msg = register_user(username, password)
                        if "exitosamente" in msg:
                            user_id = login_user(username, password)
                            authenticated = True
                        secure_conn.send(msg.encode())
                    else:
                        user_id = login_user(username, password)
                        if user_id:
                            secure_conn.send(b"Inicio de sesion exitoso")
                            authenticated = True
                        else:
                            secure_conn.send(b"Error: Credenciales invalidas")

                # Bucle de mensajes
                while authenticated:
                    secure_conn.send(b"Escriba su mensaje (max 144 chars):")
                    message = secure_conn.recv(1024).decode()
                    
                    if not message or message.lower() == 'exit': break

                    if len(message) > 144:
                        secure_conn.send(b"ERROR: Mensaje demasiado largo")
                    else:
                        save_message(user_id, message)
                        secure_conn.send(b"OK: Mensaje guardado")

                    secure_conn.send(b"Desea enviar otro mensaje? (S/N)")
                    cont = secure_conn.recv(1024).decode().upper()
                    if cont != "S":
                        secure_conn.send(b"Cerrando conexion. Adios.")
                        break

if __name__ == "__main__":
    start_server()