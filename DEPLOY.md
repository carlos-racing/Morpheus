# Despliegue de Morpheus en 192.168.7.70

## 1. Preparar el repositorio

Sube este repositorio a GitHub sin incluir `.env`, `env/`, `__pycache__/` ni ficheros de `app/uploads/`.

En el servidor:

```bash
git clone <URL_DEL_REPOSITORIO> morpheus
cd morpheus
cp .env.example .env
```

Edita `.env` y cambia, como minimo, `SECRET_KEY` y `ADMIN_PASSWORD`.

## 2. MongoDB

La aplicacion apunta por defecto al MongoDB del nuevo servidor:

```text
mongodb://APP_USER:APP_PASSWORD@MONGO_HOST:27017/Morpheus?authSource=admin
```

Si ese usuario no existe en el Mongo del servidor nuevo, crea un usuario equivalente o cambia `MONGO_URI` en `.env` por las credenciales reales del contenedor `mongodb`.

## 3. Levantar Morpheus

```bash
docker compose up -d --build
```

Por defecto queda publicada en:

```text
http://192.168.7.70:8090
```

El puerto se puede cambiar en `.env` con `MORPHEUS_PORT`.

## 4. Inicializar datos si no hay copia de la BD

Importar camas desde `listado_camas.json`:

```bash
docker compose exec morpheus python import_beds.py
```

Crear o actualizar el usuario administrador:

```bash
docker compose exec morpheus python crear_usuario.py
```

Las credenciales del admin se leen de `.env`:

```text
ADMIN_USER=admin
ADMIN_PASSWORD=replace-with-a-temporary-admin-password
ADMIN_ROLE=admin
```

## 5. Comprobaciones

```bash
docker compose ps
docker compose logs -f morpheus
```

Abre `http://192.168.7.70:8090`, inicia sesion y comprueba:

- panel principal
- consulta de camas
- asignacion desde Excel
- gestion de edificio
- desocupar cama o brigada

## 6. Integracion con nginx_proxy

Como el servidor ya tiene `nginx_proxy` usando los puertos 80 y 443, Morpheus se publica primero en el puerto 8090. Despues puedes anadir una regla en el proxy para enviar un dominio o ruta hacia:

```text
http://192.168.7.70:8090
```
