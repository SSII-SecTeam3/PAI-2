import socket
import time
import psycopg2
import seguridad
import logging
from populatedb import get_connection
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives import serialization

HOST = '127.0.0.1'
PORT = 5000

logger = logging.getLogger("server_logger")
logger.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(message)s')

def cambiar_fichero_log(nombre_fichero):
    global logger

    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()

    file_handler = logging.FileHandler(filename=nombre_fichero, encoding='utf-8')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

ph = PasswordHasher()
logged_users = {}
security = {}

def registerBaseUsers():
    db = None
    cur = None
    try:
        db = get_connection()
        cur = db.cursor()

        for numUsers in range(1,4):
            user = f"user{numUsers}"    
            password = f"password{numUsers}"
            password_hash = ph.hash(password)

            cur.execute(
            "SELECT id, password_hash FROM users WHERE username=%s",
            (user,)
            )
            result = cur.fetchone()

            if result is not None:
                result_id = result[0]
                mensaje = f"Usuario base '{user}' ya registrado. Nº de Cuenta: {result_id}"
                logger.info(mensaje)
                print(mensaje)
                continue

            privada_pem_bytes, publica_pem_bytes = seguridad.generar_claves_registro()
            nombre_archivo = f"clave_privada_{user}.pem"
            with open(nombre_archivo, "wb") as f:
                f.write(privada_pem_bytes)
            logger.info(f"[S] Clave privada generada y guardada localmente en {nombre_archivo}")    
            print(f"Clave privada generada y guardada localmente en {nombre_archivo}")

            cur.execute(
                "INSERT INTO users (username, password_hash, pub_rsa, balance) VALUES (%s, %s, %s, %s) RETURNING id",
                (user, password_hash, publica_pem_bytes.decode(), 1000)
            )
            new_id = cur.fetchone()[0]
            db.commit()

            mensaje = f"Usuario base registrado correctamente. Su Nº de Cuenta es: {new_id}"
            logger.info(mensaje)
            print(mensaje)

    except Exception as e:
        db.rollback()
        logger.error(f"[S] ERROR REAL EN REGISTRO DE USUARIOS BASE: {e}")
        print("ERROR REAL EN REGISTRO DE USUARIOS BASE:", e)

    finally:
        if cur: cur.close()
        if db: db.close()

def registerUser(socket, user, password, publica_pem_str):
    db = None
    cur = None
    try:
        db = get_connection()
        cur = db.cursor()
        password_hash = ph.hash(password)

        cur.execute(
            "INSERT INTO users (username, password_hash, pub_rsa, balance) VALUES (%s, %s, %s, %s) RETURNING id",
            (user, password_hash, publica_pem_str, 1000)
        )
        new_id = cur.fetchone()[0]
        db.commit()

        socket.send(f"OK|{new_id}".encode())
        
        return new_id

    except psycopg2.errors.UniqueViolation:
        db.rollback()
        socket.send("ERROR: usuario ya existe.".encode())

    except Exception as e:
        db.rollback()
        logger.error(f"[S] ERROR REAL EN REGISTRO: {e}")
        print("ERROR REAL EN REGISTRO:", e)
        socket.send("ERROR interno del servidor.".encode())

    finally:
        if cur: cur.close()
        if db: db.close()

def loginUser(socket, user, password):
    db = None
    cur = None
    try:
        db = get_connection()
        cur = db.cursor()

        cur.execute(
            "SELECT id, password_hash FROM users WHERE username=%s",
            (user,)
        )
        result = cur.fetchone()

        if not result:
            socket.send("Usuario no encontrado.".encode())
            return False
        
        user_id = result[0]
        stored_hash = result[1]

        try:
            ph.verify(stored_hash, password)
            mensaje = f"Login correcto. Su Nª de cuenta es: {user_id}"
            socket.send(mensaje.encode())
            return user_id
        except VerifyMismatchError:
            socket.send("Contraseña incorrecta.".encode())
            return None

    except Exception as e:
        logger.error(f"[S] Error login: {e}")
        print(f"Error login: {e}")
        socket.send("ERROR en login.".encode())
        return None
    
    finally:
        if cur: cur.close()
        if db: db.close()

def realizar_transferencia(origen, destino, cantidad):
    db = None
    cur = None
    try:
        db = get_connection()
        cur = db.cursor()
        db.autocommit = False
        cur.execute(
            "SELECT balance FROM users WHERE id=%s FOR UPDATE",
            (origen,)
        )
        row = cur.fetchone()

        if not row:
            return "La cuenta origen no existe."

        balance_origen = float(row[0])

        if balance_origen < cantidad:
            return "Saldo insuficiente."
        elif cantidad <= 0:
            return "La cantidad debe ser positiva."

        cur.execute(
            "SELECT balance FROM users WHERE id=%s FOR UPDATE",
            (destino,)
        )
        if not cur.fetchone():
            return "La cuenta destino no existe."

        cur.execute(
            "UPDATE users SET balance = balance - %s WHERE id=%s",
            (cantidad, origen)
        )

        cur.execute(
            "UPDATE users SET balance = balance + %s WHERE id=%s",
            (cantidad, destino)
        )
        db.commit()
        return "TRANSFERENCIA REALIZADA"

    except Exception:
        db.rollback()
        return "ERROR EN TRANSFERENCIA"

    finally:
        if cur: cur.close()
        if db: db.close()

with open("servidor_privada.pem", "rb") as f:
    priv_rsa_srv = serialization.load_pem_private_key(f.read(), password=None)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen()
    print("Servidor escuchando...")

    while True:
        try:
            conn, addr = server.accept()

            with conn:
                identidad_conexion = conn.recv(1024).decode()
                print(f"Identidad conexión: {identidad_conexion}")

                if identidad_conexion == "Cliente":
                    cambiar_fichero_log('prueba_positiva.log')
                elif identidad_conexion == "MITM":
                    cambiar_fichero_log('prueba_negativa.log')

                registerBaseUsers()

                for handler in logger.handlers:
                    print(f"Handler activo: {handler.baseFilename}")

                logger.info(f"[S] Conectado desde {addr}")
                print(f"Conectado desde {addr}")

                clave_K = seguridad.establecer_sesion_servidor(conn, priv_rsa_srv, None)

                conn.send("> ¿Quiere loguearse o registrarse? (L/R)".encode())
                regOLog = conn.recv(1024).decode()
                logger.info(f"[C->S] {regOLog}")

                if not regOLog: 
                    continue

                while regOLog.upper() not in ["L", "R"]:
                    conn.send("Opción no válida. Por favor, introduzca L para loguearse o R para registrarse.".encode())
                    regOLog = conn.recv(1024).decode()
                    logger.info(f"[C->S] {regOLog}")

                conn.send("> Introduzca a continuación su usuario y contraseña.".encode())
                datos_login_cifrados = conn.recv(4096)
                datos_login = seguridad.descifrar_credenciales(clave_K, datos_login_cifrados)
                logger.info(f"[C->S] {datos_login}")

                if "|" not in datos_login:
                    conn.close()
                    continue
                    
                clave_temporal = clave_K
                user_id = None

                if regOLog.upper() == "R":
                    partes = datos_login.split("|", 2)
                    if len(partes) == 3:
                        user, password, pub_rsa_pem = partes
                        user_id = registerUser(conn, user, password, pub_rsa_pem)
                    else:
                        conn.send("ERROR de formato en registro.".encode())
                        
                elif regOLog.upper() == "L":
                    partes = datos_login.split("|", 1)
                    if len(partes) == 2:
                        user, password = partes
                        user_id = loginUser(conn, user, password)
                
                if not user_id:
                    conn.close()
                else:
                    newTransaction = "S"
                    logged_users[conn] = user_id

                    security[conn] = {
                        "key": clave_temporal,
                        "nonces": set()
                    }

                    while newTransaction.upper() == "S":

                        time.sleep(0.2)

                        try:
                            conn.send("> Introduzca a continuación la cuenta origen, destino y cantidad de la transacción".encode())
                            data_sec = conn.recv(4096).decode()
                            logger.info(f"[C->S] {data_sec}")
                            if not data_sec:
                                break

                            contexto_sec = security[conn]
                            valido, msg, error = seguridad.verificar_integridad(
                                contexto_sec["key"], data_sec, contexto_sec["nonces"]
                            )

                            respuesta = ""

                            if not valido:
                                logger.error(f"[S] ERROR DE SEGURIDAD: {error}")
                                print("ERROR DE SEGURIDAD.", error)
                                break
                            else:
                                try:
                                    origen, destino, cantidad = msg.split("|")
                                    cantidad = float(cantidad)

                                    if conn not in logged_users:
                                        respuesta = "Debe iniciar sesión."
                                    elif str(logged_users[conn]) != str(origen):
                                        respuesta = "No puede transferir desde otra cuenta."
                                    else:
                                        resultado = realizar_transferencia(origen, destino, cantidad)
                                        respuesta = resultado
                                        logger.info(f"[S] --- DATOS RECIBIDOS ---")
                                        logger.info(f"[S] Cuenta origen: {origen}")
                                        logger.info(f"[S] Cuenta destino: {destino}")
                                        logger.info(f"[S] Cantidad: {cantidad}")
                                        logger.info(f"[S] ---------")
                                        print("\n--- DATOS RECIBIDOS ---")
                                        print("Cuenta origen:", origen)
                                        print("Cuenta destino:", destino)
                                        print("Cantidad:", cantidad)
                                        print("---------\n")

                                except ValueError:
                                    respuesta = "ERROR EN FORMATO (Use: origen|destino|cantidad)"
                                except Exception as e:
                                    respuesta = "ERROR EN PROCESAMIENTO"

                            print(respuesta)
                            respuesta_sec = seguridad.crear_mensaje_seguro(contexto_sec["key"], respuesta)
                            conn.send(respuesta_sec.encode())
                            time.sleep(0.2)
                            conn.send("> ¿Desea realizar otra transacción? (S/N)".encode())
                            newTransaction = conn.recv(1024).decode()
                            logger.info(f"[C->S] {newTransaction}")
                        
                        except ConnectionResetError:
                            logger.error(f"[S] Cliente desconectado forzosamente.")
                            print("Cliente desconectado forzosamente.")
                            break

                if conn in logged_users:
                    del logged_users[conn]
                    del security[conn]

        except KeyboardInterrupt:
            logger.error(f"[S] Servidor detenido por KeyboardInterrupt.")
            print("\nApagando servidor...")
            break
        except Exception as e:
            logger.error(f"[S] ERROR general en el servidor: {e}")
            print(f"ERROR general en el servidor: {e}")
