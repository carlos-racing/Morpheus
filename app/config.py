import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Pilla de .env en producción si lo deseas
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://e2t:Infanteria1537@192.168.7.42:27017/Morpheus?authSource=admin')
    UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
    ALLOWED_EXTENSIONS = {"xls", "xlsx", "csv"}