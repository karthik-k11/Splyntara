from pathlib import Path

import pytest

from app import create_app


@pytest.fixture
def database_path(tmp_path):
    return tmp_path / "test_splyntara.db"


@pytest.fixture
def app(database_path):
    application = create_app({
        "TESTING": True,
        "DATABASE": database_path,
        "AUTH_ENABLED": False,
        "ALLOWED_PROJECT_ROOTS": [database_path.parent, Path.home()],
    })

    yield application


@pytest.fixture
def client(app):
    return app.test_client()
