from flask import Flask, abort, request, session
from flask_pymongo import PyMongo
from flask_cors import CORS
from markupsafe import Markup
import os
import secrets

mongo = PyMongo()

def create_app():
    # Le indicamos explícitamente dónde están estáticos y plantillas
    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
        instance_relative_config=False
    )
    app.config.from_object('app.config.Config')

    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            sent_token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
            expected_token = session.get("csrf_token")
            if not sent_token or not expected_token or not secrets.compare_digest(sent_token, expected_token):
                abort(400)

    @app.context_processor
    def inject_csrf():
        def csrf_token():
            if "csrf_token" not in session:
                session["csrf_token"] = secrets.token_urlsafe(32)
            return session["csrf_token"]

        def csrf_field():
            return Markup(f'<input type="hidden" name="csrf_token" value="{csrf_token()}">')

        return dict(csrf_token=csrf_token, csrf_field=csrf_field)

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    # Inicializar extensiones
    mongo.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Registrar blueprint
    from app.routes import bp as main_bp
    app.register_blueprint(main_bp)

    return app
