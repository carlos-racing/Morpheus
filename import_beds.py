import json
import os

from pymongo import MongoClient, UpdateOne


MONGO_URI = os.environ["MONGO_URI"]
DB_NAME = os.getenv("MONGO_DB", "Morpheus")
BEDS_FILE = os.getenv("BEDS_FILE", "listado_camas.json")


client = MongoClient(MONGO_URI)
db = client[DB_NAME]

with open(BEDS_FILE, "r", encoding="utf-8") as file:
    beds_data = json.load(file)

operations = []
for bed in beds_data:
    bed_id = bed.get("bed_id")
    if not bed_id:
        continue
    operations.append(UpdateOne({"bed_id": bed_id}, {"$setOnInsert": bed}, upsert=True))

if operations:
    result = db.beds.bulk_write(operations)
    db.beds.create_index("bed_id", unique=True)
    print(f"Camas nuevas insertadas: {result.upserted_count}")
else:
    print("No se encontraron camas validas para importar.")
