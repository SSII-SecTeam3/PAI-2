import socket
import ssl
import getpass

HOST = "127.0.0.1"
PORT = 5000

context = ssl.create_default_context()
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.check_hostname = False
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations("./certificados/servidor_cert.pem")

ciphers_13 = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"

try:
    if hasattr(context, 'set_ciphersuites'):
        context.set_ciphersuites(ciphers_13)
        print("[INFO] Cliente: Proponiendo Cipher Suites robustos.")
    else:
        print("[AVISO] Cliente: Usando suites por defecto de TLS 1.3.")
except Exception as e:
    print(f"[ERROR] Cliente al configurar Ciphers: {e}")

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
        
        # Envolvemos el socket en el lector
        with client.makefile("r", encoding="utf-8") as reader:
            authenticated = False
            
            # --- FASE DE AUTENTICACIÓN ---
            while not authenticated:
                # 1. Recibir invitación (Login o Registro)
                print(f"\n>>> {reader.readline().strip()}")
                option = get_input("Opción (L/R): ")
                client.send(f"{option}\n".encode())

                # 1.2 Validar opción localmente antes de enviar
                if option.strip().upper() not in ["L","R"]:
                    print(f"\033[91m {reader.readline().strip()} \033[0m")
                    continue

                # 2. Recibir instrucción de credenciales
                print(f">>> {reader.readline().strip()}")
                username = get_input("Usuario: ")
                password = get_password_input("Password: ")
                client.send(f"{username}|{password}\n".encode())

                # 3. Recibir resultado
                response = reader.readline().strip()
                print(f"\033[92m{response}\033[0m" if "exitoso" in response else f"\033[91m{response}\033[0m")
                
                if "exitoso" in response or "exitosamente" in response:
                    authenticated = True
                    reader.readline()

            # --- FASE DE MENSAJERÍA ---
            print("\n--- Sesión de Mensajería Activa ---")
            while True:
                try:
                    # 1. Pedir y enviar mensaje                
                    msg = get_input("Mensaje (o 'exit' para salir): ")
                    client.send(f"{msg}\n".encode())

                    if msg.lower() == 'exit':
                        print("\nSaliendo...")
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

                    # Si es N, leer el mensaje de despedida y salir
                    if choice.upper() != 'S':
                        print(reader.readline().strip())
                        break

                except KeyboardInterrupt:
                    break