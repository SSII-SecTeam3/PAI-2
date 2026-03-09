import socket
import ssl

HOST = "127.0.0.1"
PORT = 5000

context = ssl.create_default_context()
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.check_hostname = False
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations("servidor_cert.pem")

def get_input(prompt):
    return input(f"\033[94m{prompt}\033[0m").strip()

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as client:
        authenticated = False
        
        # --- FASE DE AUTENTICACIÓN ---
        while not authenticated:
            # 1. Recibir invitación (Login o Registro)
            print(f"\n>>> {client.recv(1024).decode()}")
            option = get_input("Opción (L/R): ")
            client.send(option.encode())

            # 2. Recibir instrucción de credenciales
            print(f">>> {client.recv(1024).decode()}")
            username = get_input("Usuario: ")
            password = get_input("Password: ")
            client.send(f"{username}|{password}".encode())

            # 3. Recibir resultado
            response = client.recv(1024).decode()
            print(f"\033[92m{response}\033[0m" if "exitoso" in response else f"\033[91m{response}\033[0m")
            
            if "exitoso" in response or "exitosamente" in response:
                authenticated = True

        # --- FASE DE MENSAJERÍA ---
        print("\n--- Sesión de Mensajería Activa ---")
        while True:
            try:
                # 1. Recibir invitación para enviar mensaje
                prompt_server = client.recv(1024).decode()
                if not prompt_server: break
                
                msg = get_input("Mensaje (o 'exit' para salir): ")
                client.send(msg.encode())

                # 2. Recibir confirmación de guardado
                status = client.recv(1024).decode()
                print(f"Status: {status}")

                # 3. Pregunta de continuación
                cont_prompt = client.recv(1024).decode()
                print(f"\n{cont_prompt}")
                choice = get_input("Respuesta (S/N): ")
                client.send(choice.encode())

                if choice.upper() != 'S':
                    print(client.recv(1024).decode()) # "Sesión cerrada"
                    break

            except KeyboardInterrupt:
                break