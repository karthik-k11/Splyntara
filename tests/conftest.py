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
    })

    yield application


@pytest.fixture
def client(app):
    return app.test_client()
