import factory
import random

from factory import SubFactory
from factory.alchemy import SQLAlchemyModelFactory
from factory.faker import faker

from datetime import datetime

from app.app import app as fastapi_app
from app.core.token import get_current_user
from app.model.user import User, pwd_context
from app.model.profile import Profile


class UserFactory(SQLAlchemyModelFactory):
    class Meta:
        model = User
        sqlalchemy_session_persistence = "commit"

    email = factory.Faker("ascii_free_email")
    password = pwd_context.hash("test")
    is_active = True
    profile = None


class ProfileFactory(SQLAlchemyModelFactory):
    class Meta:
        model = Profile
        sqlalchemy_session_persistence = "commit"

    nickname = factory.Faker("pystr", min_chars=1, max_chars=24, locale="ko")
    gender = random.choice(["M", "F", "U"])
    location = factory.Faker("city", locale="ko")
    age = datetime.now()
    foot = random.choice(["L", "R", "B"])
    level = factory.Faker("pyint", min_value=1, max_value=5)
    positions = random.sample(range(1, 15), 3)
    img = factory.Faker("image_url")
    user_seq = factory.SelfAttribute("user.seq")


class UserMocking:
    def __init__(self):
        self.user = None
        self.users = None

    def create_user(self):
        self.user = UserFactory.create()

    def create_user_profile(self):
        if not self.user:
            raise ValueError("User must be created before creating a profile.")
        profile = ProfileFactory.create(user_seq=self.user.seq)
        self.user.profile = profile

    def force_authenticate(self):
        async def override_get_current_user():
            return self.user

        fastapi_app.dependency_overrides[get_current_user] = override_get_current_user

    def create_users(self, size):
        self.users = UserFactory.create_batch(size)

    def create_profiles_for_users(self):
        if not self.users:
            raise ValueError("Users must be created before creating profiles.")
        for user in self.users:
            profile = ProfileFactory.create(user_seq=user.seq)
            user.profile = profile
