import asyncio
import time
import uuid

# Configuración de la prueba
HOST = '127.0.0.1'
PORT = 5000
CONCURRENCY = 300

async def cliente_no_tls(worker_id):
    try:
        await asyncio.sleep(worker_id * 0.1)
        
        # 1. Establecer conexión TCP cruda
        reader, writer = await asyncio.open_connection(HOST, PORT)
        
        # 2. Leer "Login (L) o Registro (R)?" y responder
        await reader.read(1024)
        writer.write(b"R")
        await writer.drain()
        
        # 3. Leer petición de credenciales
        await reader.read(1024)
        username = f"usr_notls_{worker_id}_{uuid.uuid4().hex[:6]}"
        credenciales = f"{username}|Password123!".encode()
        writer.write(credenciales)
        await writer.drain()
        
        # 4. Leer respuesta
        respuesta_auth = await reader.read(2048)
        if b"Escriba su mensaje" not in respuesta_auth:
            await reader.read(2048)
            
        # 5. Enviar mensaje
        msg = f"Mensaje en texto plano desde el worker {worker_id}".encode()
        writer.write(msg)
        await writer.drain()
        
        # 6. Leer confirmación
        respuesta_msg = await reader.read(2048)
        if b"Desea enviar" not in respuesta_msg:
            await reader.read(2048)
            
        # 7. Salir
        writer.write(b"N")
        await writer.drain()

        await reader.read(1024)
        
        writer.close()
        await writer.wait_closed()
        return True

    except Exception as e:
        print(f"Error en worker {worker_id}: {type(e).__name__} - {e}")
        return False

async def main():
    print(f"🚀 Iniciando Test de Carga SIN TLS para {CONCURRENCY} clientes...")
    inicio = time.time()
    
    tareas = [cliente_no_tls(i) for i in range(CONCURRENCY)]
    resultados = await asyncio.gather(*tareas)
    
    tiempo_total = time.time() - inicio
    exitos = sum(resultados)
    
    print("\n--- RESULTADOS TEST SIN TLS ---")
    print(f"Usuarios registrados y mensajes enviados: {exitos}/{CONCURRENCY}")
    print(f"Tiempo total: {tiempo_total:.2f} segundos")
    if tiempo_total > 0:
        print(f"Rendimiento: {exitos / tiempo_total:.2f} flujos completos/segundo")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass