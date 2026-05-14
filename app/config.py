import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Pilla de .env en producción si lo deseas
    SECRET_KEY = os.getenv('SECRET_KEY', 'replace-with-secret')
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://APP_USER:APP_PASSWORD@MONGO_HOST:27017/Morpheus?authSource=admin')
    UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
    ALLOWED_EXTENSIONS = {"xls", "xlsx", "csv"}
