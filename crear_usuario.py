import os

from pymongo import MongoClient
from werkzeug.security import generate_password_hash


MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb://APP_USER:APP_PASSWORD@MONGO_HOST:27017/Morpheus?authSource=admin",
)
DB_NAME = os.getenv("MONGO_DB", "Morpheus")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")
ADMIN_ROLE = os.getenv("ADMIN_ROLE", "admin")
PASSWORD_FIELD = "contrase\u00f1a"


client = MongoClient(MONGO_URI)
db = client[DB_NAME]

db.usuarios.update_one(
    {"nombre": ADMIN_USER},
    {
        "$set": {
            PASSWORD_FIELD: generate_password_hash(ADMIN_PASSWORD),
            "rol": ADMIN_ROLE,
        }
    },
    upsert=True,
)

print(f"Usuario '{ADMIN_USER}' creado o actualizado con rol '{ADMIN_ROLE}'.")
