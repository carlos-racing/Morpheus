from werkzeug.security import generate_password_hash
from pymongo import MongoClient

client = MongoClient('mongodb://e2t:Infanteria1537@192.168.7.42:27017/Morpheus?authSource=admin')
db = client["Morpheus"]

db.usuarios.insert_one({
    "nombre": "admin",
    "contraseña": generate_password_hash("admin"),
    "rol": "admin"
})