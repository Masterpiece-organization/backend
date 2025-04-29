from passlib.context import CryptContext
from sqlalchemy import Boolean, Column, Integer, String, select
from sqlalchemy.orm import Session, relationship

from app.core.utils import get_position_type
from app.db.session import Base
from app.helper.exception import (
    EmailConflictException,
    PasswordInvalidException,
    UserNotFoundException,
)
from app.model.chat import UserChatRoomAssociation

from .club import JoinClub
from .clubPosting import JoinClubPosting
from .firebase import Firebase
from .guest import JoinGuest
from .memberPosting import JoinMemberPosting
from .profile import Profile

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class User(Base):
    __tablename__ = "users"

    seq = Column(Integer, primary_key=True, autoincrement=True, comment="시퀀스")
    email = Column(String(128), comment="이메일")
    password = Column(String(256), comment="비밀번호")
    is_active = Column(Boolean, default=True, comment="활성화 여부")

    profile = relationship(
        Profile, back_populates="user", cascade="all, delete-orphan", uselist=False
    )

    clubs = relationship(
        "Club",
        secondary="join_club",
        primaryjoin="and_(User.seq == JoinClub.user_seq, JoinClub.accepted == True)",
        secondaryjoin="and_(Club.seq == JoinClub.clubs_seq, Club.deleted == False)",
        back_populates="members",
    )

    join_club_posting = relationship(
        JoinClubPosting, back_populates="user", cascade="all, delete-orphan"
    )

    join_guest = relationship(
        JoinGuest, back_populates="user", cascade="all, delete-orphan"
    )

    join_member_posting = relationship(
        JoinMemberPosting, back_populates="user", cascade="all, delete-orphan"
    )

    poll = relationship("Poll", back_populates="user")
    join_poll = relationship("JoinPoll", back_populates="user")

    firebase = relationship(
        Firebase, back_populates="user", cascade="all, delete-orphan"
    )

    chatting_room_associations = relationship(
        "UserChatRoomAssociation", back_populates="user"
    )
    chatting_rooms = relationship(
        "ChattingRoom", secondary="user_chatroom_association", back_populates="users"
    )
    sns = relationship("Sns", back_populates="join_user", cascade="all, delete-orphan")
    device = relationship("Device", back_populates="user", cascade="all, delete-orphan")

    @staticmethod
    def create(db: Session, email: str, password: str) -> None:
        user = db.scalar(select(User).where(User.email == email))  # ORM

        if len(password) < 6:
            raise PasswordInvalidException

        user = User(email=email, password=pwd_context.hash(password))
        db.add(user)
        db.commit()
        return user

    @staticmethod
    def resset_password(db: Session, email: str, password: str):
        user = db.scalar(select(User).where(User.email == email))

        if not user:
            raise UserNotFoundException

        db.query(User).filter(User.email == email).update(
            {"password": pwd_context.hash(password)}
        )
        db.commit()
        db.flush()
