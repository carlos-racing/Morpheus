import json
from flask import Flask
from flask_pymongo import PyMongo

app = Flask(__name__)
app.config["MONGO_URI"] = 'mongodb://e2t:Infanteria1537@192.168.7.42:27017/Morpheus?authSource=admin'  # Ajusta si es necesario
mongo = PyMongo(app)

with open("listado_camas.json", "r", encoding="utf-8") as file:
    beds_data = json.load(file)

# Inserta los documentos en la colección "beds"
result = mongo.db.beds.insert_many(beds_data)
print(f"Insertados {len(result.inserted_ids)} documentos en la colección 'beds'.")
