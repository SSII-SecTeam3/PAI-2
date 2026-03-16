import socket
import ssl
import getpass
import logging
import os

HOST = "127.0.0.1"
PORT = 5000

LOG_FOLDER = "logs"
LOG_PATH = os.path.join(LOG_FOLDER, "conexion_tls.log")

if not os.path.exists(LOG_FOLDER):
    os.makedirs(LOG_FOLDER)

logging.basicConfig(filename=LOG_PATH, encoding='utf-8', level=logging.INFO, format='%(asctime)s - %(message)s')

context = ssl.create_default_context()
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.check_hostname = False
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations("./certificados/servidor_cert.pem")
logging.info("Inicializado contexto TLS y configurado con versión TLS1.3 en el cliente.")
logging.info("Configurado certificado del servidor en el contexto TLS del cliente.")

ciphers_13 = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"

try:
    if hasattr(context, 'set_ciphersuites'):
        context.set_ciphersuites(ciphers_13)
        print("[INFO] Cliente: Proponiendo Cipher Suites robustos.")
        logging.info("Configuradas las ciphersuites personalizadas AES-256/ChaCha20 en el TLS en el lado del cliente.")
    else:
        print("[AVISO] Cliente: Usando suites por defecto de TLS 1.3.")
        logging.info("Configuradas las ciphersuites por defecto en el TLS en el lado del cliente.")
except Exception as e:
    print(f"[ERROR] Cliente al configurar Ciphers: {e}")
    logging.error("Error al configurar las ciphersuites en el lado del cliente.")

def get_input(prompt):
    return input(f"\033[94m{prompt}\033[0m").strip()

def get_password_input(prompt):
    return getpass.getpass(f"\033[94m{prompt}\033[0m").strip()

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as client:
        # --- LÍNEA PARA VERIFICAR EL CIPHER ---
        nombre, version, bits = client.cipher()
        print(f"\n[INFO] Conectado mediante {version}")
        print(f"[INFO] Cipher Suite: {nombre} ({bits} bits)\n")
        # ---------------------------------------
        logging.info("Cliente conectado con el servidor.")
        
        # Envolvemos el socket en el lector
        with client.makefile("r", encoding="utf-8") as reader:
            authenticated = False
            
            # --- FASE DE AUTENTICACIÓN ---
            while not authenticated:
                logging.info("Iniciada la fase de autenticación en el lado del cliente o repetición de esta debido a credenciales erroneas introducidas.")
                # 1. Recibir invitación (Login o Registro)
                print(f"\n>>> {reader.readline().strip()}")
                option = get_input("Opción (L/R): ")
                client.send(f"{option}\n".encode())
                logging.info(f"El cliente elige {option}.")

                # 1.2 Validar opción localmente antes de enviar
                if option.strip().upper() not in ["L","R"]:
                    print(f"\033[91m {reader.readline().strip()} \033[0m")
                    logging.info(f"La opción {option} enviada por el cliente se rechaza porque no está entre las opciones válidas (L/R).")
                    continue

                # 2. Recibir instrucción de credenciales
                print(f">>> {reader.readline().strip()}")
                username = get_input("Usuario: ")
                password = get_password_input("Password: ")
                client.send(f"{username}|{password}\n".encode())
                logging.info("El cliente envía su nombre de usuario y contraseña.")

                # 3. Recibir resultado
                response = reader.readline().strip()
                print(f"\033[92m{response}\033[0m" if "exitoso" in response else f"\033[91m{response}\033[0m")
                
                if "exitoso" in response or "exitosamente" in response:
                    authenticated = True
                    reader.readline()
                    logging.info("El cliente consigue autenticarse con éxito.")

            # --- FASE DE MENSAJERÍA ---
            print("\n--- Sesión de Mensajería Activa ---")
            while True:
                logging.info("Iniciada la fase de mensajería en el lado del cliente o repetición de esta debido a que el cliente quiere mandar otro mensaje.")
                try:
                    # 1. Pedir y enviar mensaje                
                    msg = get_input("Mensaje (o 'exit' para salir): ")
                    client.send(f"{msg}\n".encode())
                    logging.info("El cliente envía el mensaje")

                    if msg.lower() == 'exit':
                        print("\nSaliendo...")
                        logging.info("El cliente envía el mensaje 'exit' por lo que se cierra la conexión de este cliente con el servidor.")
                        break

                    # 2 Recibir confirmación de guardado
                    respuesta_servidor = reader.readline().strip()
                    print(f"\n{respuesta_servidor}")

                    # 3. Recibir pregunta de continuación
                    pregunta = reader.readline().strip()
                    print(pregunta)

                    # 4. Pedir la opción S/N
                    choice = get_input("Respuesta (S/N): ")
                    client.send(f"{choice}\n".encode())
                    logging.info(f"El cliente responde {choice} a la pregunta de sí quiere continuar.")

                    # Si es N, leer el mensaje de despedida y salir
                    if choice.upper() != 'S':
                        print(reader.readline().strip())
                        break

                except KeyboardInterrupt:
                    break