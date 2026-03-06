import socket
import seguridad
import logging

from cryptography.hazmat.primitives import serialization

HOST = '127.0.0.1'
PORT = 5000

logging.basicConfig(filename='prueba_positiva.log', encoding='utf-8', level=logging.INFO, format='%(asctime)s - %(message)s')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))
    client.send("Cliente".encode())

    with open("servidor_publica.pem", "rb") as f:
        pub_rsa_srv = serialization.load_pem_public_key(f.read())

    priv_rsa_cli = None
    try:
        with open("cliente_privada.pem", "rb") as f:
            priv_rsa_cli = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        pass

    clave_K = seguridad.establecer_sesion_cliente(client, priv_rsa_cli, pub_rsa_srv)

    msgRegOLog = client.recv(1024).decode()
    logging.info(f"[S->C] {msgRegOLog}")
    print(msgRegOLog)
    regOLog = input()
    client.send(regOLog.encode())
    while regOLog.upper() not in ["L", "R"]:
        msgInvalidOption = client.recv(1024).decode()
        logging.info(f"[S->C] {msgInvalidOption}")
        print(msgInvalidOption)
        regOLog = input()
        client.send(regOLog.encode())

    mgsUserPass = client.recv(1024).decode()
    logging.info(f"[S->C] {mgsUserPass}")
    print(mgsUserPass)
    user = input(">> Usuario: ")
    logging.info(f"[C] Usuario: {user}")
    password = input(">> Password: ")
    logging.info(f"[C] Password: {password}")

    clave_sesion = clave_K
    nonces_usados = set()

    if regOLog.upper() == "R":
        privada_pem_bytes, publica_pem_bytes = seguridad.generar_claves_registro()
        nombre_archivo = f"clave_privada_{user}.pem"
        with open(nombre_archivo, "wb") as f:
            f.write(privada_pem_bytes)
        print(f"Clave privada generada y guardada localmente en {nombre_archivo}")

        datos_registro = f"{user}|{password}|{publica_pem_bytes.decode()}"
        client.send(seguridad.cifrar_credenciales(clave_K, datos_registro))

        respuesta = client.recv(1024).decode()
        logging.info(f"[S->C] {respuesta}")
        
        if respuesta.startswith("OK"):
            user_id = respuesta.split("|")[1]
            msgUserRegisteredOrLogged = "registrado correctamente" 
            logging.info(f"[C] Usuario registrado correctamente. Nº de Cuenta: {user_id}")
            print(f"Usuario registrado correctamente. Su Nº de Cuenta es: {user_id}")
        else:
            msgUserRegisteredOrLogged = respuesta
            logging.info(f"[C] Registro fallido. Razón: {respuesta}")
            print(msgUserRegisteredOrLogged)
    else:
        datos_cifrados = seguridad.cifrar_credenciales(clave_K, f"{user}|{password}")
        client.send(datos_cifrados)
        
        msgUserRegisteredOrLogged = client.recv(1024).decode()
        logging.info(f"[S->C] {msgUserRegisteredOrLogged}")
        print(msgUserRegisteredOrLogged)

    if "Login correcto" not in msgUserRegisteredOrLogged and "registrado correctamente" not in msgUserRegisteredOrLogged:
        logging.info(f"[C] Login fallido. Cerrando conexión.")
        print("Login fallido. Cerrando conexión.")
    else:
        newTransaction = "S"
        while newTransaction.upper() == "S":

            try:
                msgTrans = client.recv(1024).decode()
                logging.info(f"[S->C] {msgTrans}")
                print(msgTrans)

                origen = input(">> Cuenta origen: ")
                logging.info(f"[C] Cuenta origen: {origen}")
                destino = input(">> Cuenta destino: ")
                logging.info(f"[C] Cuenta destino: {destino}")
                cantidad = input(">> Cantidad: ")
                logging.info(f"[C] Cantidad: {cantidad}")

                mensaje_plano = f"{origen}|{destino}|{cantidad}"
                mensaje = seguridad.crear_mensaje_seguro(clave_sesion, mensaje_plano)
                client.send(mensaje.encode())

                msgResultTrans = client.recv(4096).decode()
                logging.info(f"[S->C] {msgResultTrans}")
                
                valido, msg, error = seguridad.verificar_integridad(
                    clave_sesion, msgResultTrans, nonces_usados
                )

                if valido:
                    logging.info(f"[C] Respuesta del servidor: {msg}")
                    print("Respuesta del servidor:", msg)
                else:
                    logging.error(f"[C] Error de verificación: {error}")
                    print(error)
                    break

                msgNewTransaction = client.recv(1024).decode()
                logging.info(f"[S->C] {msgNewTransaction}")
                print(msgNewTransaction)
                newTransaction = input()
                client.send(newTransaction.encode())
                
            except KeyboardInterrupt:
                logging.info(f"[C] Saliendo por KeyboardInterrupt.")
                print("\nSaliendo...")
                break