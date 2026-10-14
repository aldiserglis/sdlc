import pytest
from fastapi.testclient import TestClient

from app import main


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "auth.db")
    return TestClient(main.app)


def register(client, email="anna@example.test", password="slepena123", confirm=None):
    return client.post(
        "/register",
        data={"email": email, "password": password, "password_confirm": confirm or password},
    )


def test_register_then_login_shows_home(client) -> None:
    assert register(client).status_code == 200

    response = client.post("/login", data={"email": "anna@example.test", "password": "slepena123"})

    assert response.status_code == 200
    assert "anna@example.test" in response.text


def test_password_is_stored_hashed(client) -> None:
    register(client)

    with main.connect() as conn:
        stored = conn.execute("SELECT password_hash FROM users").fetchone()[0]

    assert "slepena123" not in stored
    assert stored.startswith("pbkdf2_sha256$")


def test_duplicate_email_is_rejected(client) -> None:
    register(client)

    assert register(client).status_code == 409


@pytest.mark.parametrize(
    ("email", "password", "confirm"),
    [
        ("nav-epasts", "slepena123", "slepena123"),
        ("anna@example.test", "isa", "isa"),
        ("anna@example.test", "slepena123", "cita12345"),
    ],
)
def test_invalid_registration_is_rejected(client, email, password, confirm) -> None:
    assert register(client, email, password, confirm).status_code == 400


def test_wrong_password_is_rejected(client) -> None:
    register(client)

    response = client.post("/login", data={"email": "anna@example.test", "password": "nepareiza1"})

    assert response.status_code == 401


def test_home_requires_login_and_logout_ends_session(client) -> None:
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"

    register(client)
    client.post("/login", data={"email": "anna@example.test", "password": "slepena123"})
    client.post("/logout")

    assert client.get("/", follow_redirects=False).headers["location"] == "/login"
