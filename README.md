# Proyecto Cliente–Servidor Seguro con TLS1.3 y PostgreSQL (Python)

Este proyecto implementa un sistema cliente–servidor sencillo usando **sockets TCP en Python**, orientado a una asignatura de **SSII**.  
Permite:

- Registro y login de usuarios
- Almacenamiento seguro de contraseñas (Argon2)
- Envios de mensajes
- Control de sesiones (usuarios logeados)
- Base de datos PostgreSQL con control de permisos
- Interacción por terminal (sin frontend)

## 1. Requisitos previos

### Software necesario

- **Windows**
- **Python 3.10+**
- **PostgreSQL 15+**
- Acceso a terminal (PowerShell o CMD)
- Acceso a GitBash
- Editor de código (Visual Studio Code recomendado)

## 2. Instalación de PostgreSQL en Windows

### 2.1 Descargar PostgreSQL

Descargar desde la web oficial: https://www.postgresql.org/download/windows/

Usar el instalador: postgresql-18.2-1-windows-x64.exe


### 2.2 Opciones durante la instalación

Durante el instalador:

1. **Directorio de instalación**  
   - Dejar por defecto

2. **Componentes**  
   ✔ PostgreSQL Server  
   ✔ pgAdmin 4  
   ✔ Command Line Tools  

3. **Password del usuario postgres**
   - Elige una contraseña segura
   - **Guárdala**, la necesitarás

4. **Puerto**
    - 5432 (El que viene por defecto)

5. **Locale**
    - Default locale

Finaliza la instalación.


## 3. Comprobar que PostgreSQL está activo

1. Abre **Servicios de Windows**
2. Busca el servicio: postgresql-x64-18
3. Debe estar en estado **En ejecución**


## 4. Acceder a PostgreSQL (SQL Shell)

Abre **SQL Shell (psql)**. Las siguientes líneas irán apareciendo de uno en uno al pulsar ENTER:

    Server [localhost]: (Dejar en blanco)
    Database [postgres]: (Dejar en blanco)
    Port [5432]: (Dejar en blanco)
    Username [postgres]: (Dejar en blanco)
    Password: (Contraseña que introdujiste al instalar postgres en el paso 2.2)


## 5. Crear la base de datos y el usuario de la aplicación

Una vez el login ha sido correcto ejecutar los siguientes pasos:
### 5.1 Crear base de datos
```
CREATE DATABASE mensajes;
```
### 5.2 Crear usuario de la aplicación
```
CREATE USER mensajes_user WITH PASSWORD 'PasswordSegura123!';
```
### 5.3 Dar permisos al usuario
```
GRANT ALL PRIVILEGES ON DATABASE mensajes TO mensajes_user;
```
### 5.4 Conectate a la base de datos creada
```
\c mensajes
```

## 6. Crear la tabla users y mensajes
```
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);
```
```
CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 7. Dar permisos al usuario sobre las nuevas tablas
```
GRANT ALL PRIVILEGES ON TABLE users TO mensajes_user;
```
```
GRANT ALL PRIVILEGES ON TABLE messages TO mensajes_user;
```

### 7.2 Dar permisos sobre SEQUENCE
Ejecuta: 
```
\d users
```
Verás una tabla similar a esta:
```
                                    Tabla ½public.users╗
    Columna    |     Tipo      | Ordenamiento | Nulable  |            Por omisi¾n
---------------+---------------+--------------+----------+-----------------------------------
 id            | integer       |              | not null | nextval('users_id_seq'::regclass)
 username      | text          |              | not null |
 password_hash | text          |              | not null |
═ndices:
    "users_pkey" PRIMARY KEY, btree (id)
    "users_username_key" UNIQUE CONSTRAINT, btree (username)
```
Aquello que aparece en la columna 'Por omisión' dentro de nextval entre comillas es el SEQUENCE. Para conceder permisos sobre la tabla hay que ejecutar el siguiente comando sustituyendo x por el valor que veas en el SEQUENCE de la tabla anterior.
```
GRANT USAGE, SELECT ON SEQUENCE x TO mensajes_user;
```
Ahora hay que hacer lo mismo con la tabla messages.
```
\d messages
```
Busca otra vez la opción de SEQUENCE y sustituyelo en el comando donde pone una 'x'
```
GRANT USAGE, SELECT ON SEQUENCE x TO mensajes_user;
```


## 8. Preparar el entorno

Abrir la terminal de Visual e instalar las dependencias. Se puede crear un entorno vitual si se considera necesario.
```
pip install -r requirements.txt
```

## 9. Arrancar la aplicación

### 9.1 Arrancar el servidor
En una terminal ejecutar lo siguiente:
```
python servidor.py
```

### 9.2 Arrancar el cliente
En otra terminal diferente ejecutar:
```
python cliente.py
```