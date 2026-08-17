import os

import pytest

os.environ["APP_PASSWORD"] = ""
os.environ["HIBP_API_KEY"] = ""

import db  # noqa: E402


@pytest.fixture(autouse=True)
def app_ctx(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
    db.init_db()

    from app import app

    app.config["TESTING"] = True
    app.config["RATELIMIT_ENABLED"] = False
    yield app


@pytest.fixture()
def client(app_ctx):
    return app_ctx.test_client()