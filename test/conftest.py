import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.app import app as fastapi_app
from app.core.config import settings
from app.core.mockings import UserFactory, UserMocking, ProfileFactory
from app.db.session import Base
from app.core.deps import get_db


DATABASE_URL = settings.SQLALCHEMY_DATABASE_URL
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

Base.metadata.create_all(bind=engine)


@pytest.fixture(scope="function")
def test_db_session() -> None:
    connection = engine.connect()
    transaction = connection.begin()
    session = SessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture(scope="session")
def test_app() -> TestClient:
    return TestClient(app=fastapi_app)


@pytest.fixture(scope="function", autouse=True)
def set_factory_session(test_db_session) -> None:
    factory_list = [UserFactory, ProfileFactory]
    for item in factory_list:
        item._meta.sqlalchemy_session = test_db_session


@pytest.fixture(scope="function", autouse=True)
def override_db_session(test_db_session):
    session = test_db_session
    fastapi_app.dependency_overrides[get_db] = lambda: session
    yield
    fastapi_app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def user_mocking() -> UserMocking:
    user_mocking = UserMocking()
    user_mocking.create_user()
    return user_mocking


@pytest.fixture(scope="function")
def auth_user_mocking(user_mocking) -> UserMocking:
    user_mocking.force_authenticate()
    return user_mocking
