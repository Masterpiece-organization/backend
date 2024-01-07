from sqlalchemy import Boolean, Column, Integer, String, select
from sqlalchemy.orm import Session, relationship

from app.db.session import Base


class Sns(Base):
    __tablename__ = "sns"

    seq = Column(Integer, primary_key=True, autoincrement=True, comment="시퀀스")
    refresh_token = Column(String(128), comment="리프레시 토큰")
    sub = Column(String(64), comment="구분 값")
    type = Column(String(24), comment="종류")

    # user = relationship("User", back_populates="sns")
    # join_sns = relationship("JoinSns", back_populates="sns")
