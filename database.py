import sqlite3

from flask import current_app, g


def get_db():
    if "db" not in g:
        database_path = current_app.config["DATABASE"]

        connection = sqlite3.connect(database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")

        g.db = connection

    return g.db


def close_db(error=None):
    connection = g.pop("db", None)

    if connection is not None:
        connection.close()


def init_db():
    connection = get_db()
    connection.execute("PRAGMA user_version = 1")
    connection.commit()


def init_app(app):
    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()