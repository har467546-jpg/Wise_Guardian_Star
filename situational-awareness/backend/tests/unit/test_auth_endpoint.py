from collections.abc import Generator
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.api.deps import get_db_session
from app.api.v1.endpoints import auth
from app.db.models.enums import UserRole
from app.db.models.user import User
from app.main import create_app


class _FakeAuthDB:
    def __init__(self, users: list[User] | None = None) -> None:
        self.users = list(users or [])

    def scalar(self, stmt):  # type: ignore[no-untyped-def]
        sql = str(stmt)
        params = stmt.compile().params
        if "count(users.id)" in sql:
            return len(self.users)
        if "FROM users" in sql:
            identity = str(params.get("lower_1", "")).lower()
            for user in self.users:
                if user.username.lower() == identity or user.email.lower() == identity:
                    return user
            return None
        raise AssertionError(f"Unexpected query: {sql}")

    def add(self, user: User) -> None:
        if not user.id:
            user.id = f"user-{len(self.users) + 1}"
        if user.is_active is None:
            user.is_active = True
        if user.created_at is None:
            user.created_at = datetime.now(timezone.utc)
        self.users.append(user)

    def commit(self) -> None:
        return None

    def refresh(self, user: User) -> None:
        if user.id is None:
            user.id = f"user-{len(self.users)}"


def _build_client(monkeypatch, db: _FakeAuthDB) -> TestClient:  # type: ignore[no-untyped-def]
    def _noop_create_all(*args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        return None

    def _get_test_db() -> Generator[_FakeAuthDB, None, None]:
        yield db

    monkeypatch.setattr("app.main.Base.metadata.create_all", _noop_create_all)
    app = create_app()
    app.dependency_overrides[get_db_session] = _get_test_db
    return TestClient(app)


def _make_user(
    username: str = "admin",
    email: str = "admin@example.com",
    password_hash: str = "hashed::ChangeMe123!",
    role: UserRole = UserRole.ADMIN,
) -> User:
    user = User(username=username, email=email, password_hash=password_hash, role=role)
    user.id = "user-existing"
    user.is_active = True
    user.created_at = datetime.now(timezone.utc)
    return user


def _fake_token_pair(user_id: str, role: str) -> auth.TokenPair:
    return auth.TokenPair(
        access_token=f"access::{user_id}::{role}",
        refresh_token=f"refresh::{user_id}::{role}",
        expires_in=480,
        refresh_expires_in=1209600,
    )


def test_bootstrap_status_returns_not_initialized_when_no_users(monkeypatch) -> None:
    client = _build_client(monkeypatch, _FakeAuthDB())

    response = client.get("/api/v1/auth/bootstrap-status")

    assert response.status_code == 200
    assert response.json() == {
        "bootstrapped": False,
        "can_bootstrap_admin": True,
        "user_count": 0,
    }


def test_bootstrap_status_returns_initialized_when_users_exist(monkeypatch) -> None:
    client = _build_client(monkeypatch, _FakeAuthDB([_make_user()]))

    response = client.get("/api/v1/auth/bootstrap-status")

    assert response.status_code == 200
    assert response.json() == {
        "bootstrapped": True,
        "can_bootstrap_admin": False,
        "user_count": 1,
    }


def test_bootstrap_admin_creates_first_admin_and_returns_token(monkeypatch) -> None:
    db = _FakeAuthDB()
    client = _build_client(monkeypatch, db)
    monkeypatch.setattr(auth, "get_password_hash", lambda password: f"hashed::{password}")
    monkeypatch.setattr(auth, "issue_token_pair", lambda user_id, role: _fake_token_pair(user_id, role))

    response = client.post(
        "/api/v1/auth/bootstrap-admin",
        json={
            "username": "admin",
            "email": "admin@example.com",
            "password": "ChangeMe123!",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "access_token": "access::user-1::admin",
        "refresh_token": "refresh::user-1::admin",
        "token_type": "bearer",
        "expires_in": 480,
        "refresh_expires_in": 1209600,
    }
    assert len(db.users) == 1
    assert db.users[0].username == "admin"
    assert db.users[0].email == "admin@example.com"
    assert db.users[0].password_hash == "hashed::ChangeMe123!"
    assert db.users[0].role == UserRole.ADMIN
    assert db.users[0].is_active is True


def test_bootstrap_admin_rejects_when_system_is_already_initialized(monkeypatch) -> None:
    client = _build_client(monkeypatch, _FakeAuthDB([_make_user()]))

    response = client.post(
        "/api/v1/auth/bootstrap-admin",
        json={
            "username": "admin",
            "email": "admin@example.com",
            "password": "ChangeMe123!",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "系统已完成初始化，请直接登录"


def test_login_accepts_email_and_returns_token(monkeypatch) -> None:
    client = _build_client(monkeypatch, _FakeAuthDB([_make_user()]))
    monkeypatch.setattr(auth, "verify_password", lambda plain, hashed: plain == "ChangeMe123!" and hashed == "hashed::ChangeMe123!")
    monkeypatch.setattr(auth, "issue_token_pair", lambda user_id, role: _fake_token_pair(user_id, role))

    response = client.post(
        "/api/v1/auth/login",
        json={
            "username": "ADMIN@EXAMPLE.COM",
            "password": "ChangeMe123!",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "access_token": "access::user-existing::admin",
        "refresh_token": "refresh::user-existing::admin",
        "token_type": "bearer",
        "expires_in": 480,
        "refresh_expires_in": 1209600,
    }


def test_refresh_rotates_refresh_token(monkeypatch) -> None:
    client = _build_client(monkeypatch, _FakeAuthDB([_make_user()]))
    monkeypatch.setattr(auth, "rotate_refresh_token", lambda db, refresh_token: _fake_token_pair("user-existing", "admin"))

    response = client.post("/api/v1/auth/refresh", json={"refresh_token": "old-refresh"})

    assert response.status_code == 200
    assert response.json()["access_token"] == "access::user-existing::admin"
    assert response.json()["refresh_token"] == "refresh::user-existing::admin"
