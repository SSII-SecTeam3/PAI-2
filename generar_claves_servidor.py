from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def crear_pem(nombre, clave, es_privada):
    encoding = serialization.PrivateFormat.TraditionalOpenSSL if es_privada else serialization.PublicFormat.SubjectPublicKeyInfo
    format = serialization.Encoding.PEM
    
    if es_privada:
        contenido = clave.private_bytes(
            encoding=format,
            format=encoding,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        contenido = clave.public_key().public_bytes(
            encoding=format,
            format=encoding
        )
    
    with open(nombre, "wb") as f:
        f.write(contenido)

clave_srv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
crear_pem("servidor_privada.pem", clave_srv, True)
crear_pem("servidor_publica.pem", clave_srv, False)

print("✅ Archivos generados: servidor_privada.pem y servidor_publica.pem")