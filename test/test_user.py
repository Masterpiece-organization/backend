from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.mockings import UserMocking


def test_user_login(test_db_session: Session, test_app: TestClient) -> None:
    user_mocking = UserMocking()
    user_mocking.create_user()
    user = user_mocking.user
    # print(user.__dict__)

    data = {"email": user.email, "password": "test"}
    response = test_app.post("/user/email/login", json=data)

    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "refresh_token" in response.json()


def test_update_user_profile(
    test_db_session: Session, test_app: TestClient, auth_user_mocking: UserMocking
) -> None:

    data = {
        "nickname": "Nickname",
        "gender": "M",
        "location": "서울",
        "age": "2000-12-06T00:00:00",
        "foot": "R",
        "level": 4,
        "positions": [1, 2, 3],
        "is_active": True,
    }
    response = test_app.patch(
        "/user/me",
        json=data,
    )
    assert response.status_code == 200


def test_get_user_profile(
    test_db_session: Session, test_app: TestClient, auth_user_mocking: UserMocking
) -> None:

    auth_user_mocking.create_user_profile()

    response = test_app.get("/user/me")
    assert response.status_code == 200


def test_get_specific_user_profile(
    test_db_session: Session, test_app: TestClient, auth_user_mocking: UserMocking
) -> None:

    auth_user_mocking.create_user_profile()
    auth_user_mocking.create_users(size=5)
    auth_user_mocking.create_profiles_for_users()

    for i in range(len(auth_user_mocking.users)):

        test_user_seq = auth_user_mocking.users[i].seq
        response = test_app.get("/user/" + str(test_user_seq))
        assert response.status_code == 200
