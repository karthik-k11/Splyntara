from pathlib import Path

from flask import Flask, jsonify

from config import Config
from database import init_app as init_database


def create_app(config=None):
    app = Flask(__name__)

    app.config.from_object(Config)

    if config is not None:
        app.config.from_mapping(config)

    database_path = Path(app.config["DATABASE"])
    app.config["DATABASE"] = database_path
    database_path.parent.mkdir(parents=True, exist_ok=True)

    @app.get("/health")
    def health():
        return jsonify({
            "status": "ok",
            "application": "Splyntara"
        }), 200

    init_database(app)

    return app


if __name__ == "__main__":
    application = create_app()
    application.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )