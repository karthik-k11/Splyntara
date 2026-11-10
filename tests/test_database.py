import sqlite3

import pytest

from database import get_db


def test_initialization_creates_database_file(app, database_path):
    assert database_path.is_file()


def test_database_connection_works(app):
    with app.app_context():
        connection = get_db()

        assert connection.execute("SELECT 1").fetchone()[0] == 1


def test_foreign_key_enforcement_is_enabled(app):
    with app.app_context():
        connection = get_db()

        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_connection_is_closed_on_app_context_teardown(app):
    with app.app_context():
        connection = get_db()

        assert connection.execute("SELECT 1").fetchone()[0] == 1

    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")
