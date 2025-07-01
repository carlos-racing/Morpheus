from werkzeug.security import generate_password_hash
from pymongo import MongoClient

client = MongoClient('mongodb://APP_USER:APP_PASSWORD@MONGO_HOST:27017/Morpheus?authSource=admin')
db = client["Morpheus"]

db.usuarios.insert_one({
    "nombre": "admin",
    "contraseña": generate_password_hash("admin"),
    "rol": "admin"
})