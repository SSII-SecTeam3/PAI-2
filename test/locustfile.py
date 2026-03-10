import ssl
import socket
import time
import uuid
from locust import User, task, between, events

class TLSSocketClient:
    """Cliente personalizado para interactuar con el servidor TLS."""
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def execute_flow(self, username, password, message):
        start_time = time.time()
        name = "Flujo completo: registro y mensaje"
        
        try:
            # Conexión y Handshake TLS
            sock = socket.create_connection((self.host, self.port))
            with self.context.wrap_socket(sock, server_hostname=self.host) as secure_conn:
                
                # 1. Opción Registro
                secure_conn.recv(1024)
                secure_conn.send(b"R")
                
                # 2. Enviar Credenciales
                secure_conn.recv(1024)
                secure_conn.send(f"{username}|{password}".encode())
                
                # 3. Recibir confirmación y prompt de mensaje
                data = secure_conn.recv(2048)
                if b"Escriba su mensaje" not in data:
                    secure_conn.recv(1024)

                # 4. Enviar Mensaje
                secure_conn.send(message.encode())
                
                # 5. Confirmación y Salida
                secure_conn.recv(2048)
                secure_conn.send(b"N")
                secure_conn.recv(1024)
                
            total_time = int((time.time() - start_time) * 1000)
            events.request.fire(
                request_type="TLS_SOCKET",
                name=name,
                response_time=total_time,
                response_length=0,
                exception=None,
            )

        except Exception as e:
            total_time = int((time.time() - start_time) * 1000)
            events.request.fire(
                request_type="TLS_SOCKET",
                name=name,
                response_time=total_time,
                response_length=0,
                exception=e,
            )

class MessageUser(User):
    wait_time = between(1, 5)
    
    def on_start(self):
        self.client = TLSSocketClient("127.0.0.1", 5000)

    @task
    def register_and_send(self):
        user_id = uuid.uuid4().hex[:8]
        username = f"locust_user_{user_id}"
        self.client.execute_flow(
            username=username,
            password="PasswordSegura123!",
            message="Mensaje de prueba desde Locust"
        )