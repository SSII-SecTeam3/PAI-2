import base64
import hmac
import hashlib
import secrets

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding

ALGORITMO_HASH = hashlib.sha512
LONGITUD_CLAVE = 64 # 512 bits
LONGITUD_NONCE = 16 # 128 bits
SALT_GLOBAL = b'f4a1d8b9c2e3f0a5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9'

def generar_nonce() -> str:
    """
    Genera un número aleatorio único en formato hexadecimal.
    """
    return secrets.token_hex(LONGITUD_NONCE)

def calcular_hmac(clave: bytes, mensaje: str, nonce: str) -> str:
    """
    Genera el código de autenticación (HMAC) usando la clave derivada.
    """
    payload = f"{mensaje}|{nonce}".encode('utf-8')
    firma = hmac.new(clave, payload, ALGORITMO_HASH).hexdigest()
    return firma

def crear_mensaje_seguro(clave: bytes, mensaje: str) -> str:
    nonce = generar_nonce()
    firma = calcular_hmac(clave, mensaje, nonce)
    return f"{mensaje}|{firma}|{nonce}"

def verificar_integridad(clave: bytes, mensaje_recibido: str, nonces_usados: set) -> tuple[bool, str, str]:
    try:
        partes = mensaje_recibido.rsplit('|', 2)
        if len(partes) != 3:
            return False, "", "ERROR. Formato de mensaje incorrecto"

        mensaje_real = partes[0]
        hmac_recibido = partes[1]
        nonce_recibido = partes[2]

        # CONTROL DE REPLAY
        if nonce_recibido in nonces_usados:
            return False, "", f"ERROR DE SEGURIDAD. Nonce reutilizado."
        
        nonces_usados.add(nonce_recibido)

        # VERIFICACIÓN HMAC
        hmac_calculado = calcular_hmac(clave, mensaje_real, nonce_recibido)

        if hmac.compare_digest(hmac_calculado, hmac_recibido): # COMPARE_DIGEST PARA EVITAR LOS ATAQUES DE CANAL LATERAL
            return True, mensaje_real, ""
        else:
            return False, "", "ERROR DE SEGURIDAD. La firma no coincide."
            
    except Exception as e:
        return False, "", f"Excepción en verificación: {e}"
    

def establecer_sesion_servidor(conn, priv_rsa_srv, pub_rsa_cli) -> bytes:
    """
    Realiza el intercambio Diffie-Hellman desde el lado del servidor.
    Devuelve la clave K de 512 bits.
    """
    privada = ec.generate_private_key(ec.SECP256R1())
    publica_bytes = privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    firma_srv = firmar_rsa(priv_rsa_srv, publica_bytes)
    
    conn.send(publica_bytes + b"---FIRMA---" + firma_srv)
    
    datos_recibidos = conn.recv(4096)
    publica_cli_bytes, firma_cli = datos_recibidos.split(b"---FIRMA---")
    
    if pub_rsa_cli is not None and firma_cli != b"SIN_FIRMA":
        if not verificar_rsa(pub_rsa_cli, publica_cli_bytes, firma_cli):
            raise ValueError("ALERTA DE SEGURIDAD.")
    
    publica_cliente = serialization.load_pem_public_key(publica_cli_bytes)
    secreto_compartido = privada.exchange(ec.ECDH(), publica_cliente)
    
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=LONGITUD_CLAVE,
        salt=SALT_GLOBAL,
        info=b'handshake bancario',
    )

    return hkdf.derive(secreto_compartido)


def establecer_sesion_cliente(sock, priv_rsa_cli, pub_rsa_srv) -> bytes:
    """
    Realiza el intercambio Diffie-Hellman desde el lado del servidor.
    Devuelve la clave K de 512 bits.
    """
    privada = ec.generate_private_key(ec.SECP256R1())
    publica_bytes = privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    datos_recibidos = sock.recv(4096)
    publica_srv_bytes, firma_srv = datos_recibidos.split(b"---FIRMA---")
    
    if not verificar_rsa(pub_rsa_srv, publica_srv_bytes, firma_srv):
        raise ValueError("¡ALERTA! El servidor no es quien dice ser. MITM detectado.")

    if priv_rsa_cli:
        firma_cli = firmar_rsa(priv_rsa_cli, publica_bytes)
    else:
        firma_cli = b"SIN_FIRMA"
    sock.send(publica_bytes + b"---FIRMA---" + firma_cli)
    
    publica_servidor = serialization.load_pem_public_key(publica_srv_bytes)
    secreto_compartido = privada.exchange(ec.ECDH(), publica_servidor)
    
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=LONGITUD_CLAVE,
        salt=SALT_GLOBAL,
        info=b'handshake bancario',
    )
    return hkdf.derive(secreto_compartido)

def cifrar_credenciales(clave_dh: bytes, texto: str) -> bytes:
    f = Fernet(base64.urlsafe_b64encode(clave_dh[:32]))
    return f.encrypt(texto.encode())

def descifrar_credenciales(clave_dh: bytes, datos_cifrados: bytes) -> str:
    f = Fernet(base64.urlsafe_b64encode(clave_dh[:32]))
    return f.decrypt(datos_cifrados).decode()

def firmar_rsa(clave_privada_rsa, dato: bytes) -> bytes:
    """Firma un dato usando una clave privada RSA."""
    return clave_privada_rsa.sign(
        dato,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA512()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA512()
    )

def verificar_rsa(clave_publica_rsa, dato: bytes, firma: bytes) -> bool:
    """Verifica si la firma corresponde al dato y a la clave pública."""
    try:
        clave_publica_rsa.verify(
            firma,
            dato,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        return True
    except Exception:
        return False
    
def generar_claves_registro() -> tuple[bytes, bytes]:
    """Genera un par de claves RSA"""
    privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    privada_pem = privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    publica_pem = privada.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return privada_pem, publica_pem