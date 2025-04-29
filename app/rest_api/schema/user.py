from pydantic import BaseModel, ConfigDict, Field

from .club.club import ClubResponseSchema
from .profile import GetProfileSchema
from app.model.device import DeviceTypeEnum


class EmailLoginSchema(BaseModel):
    email: str = Field(title="이메일", default="woorigue@gmail.com")
    password: str = Field(title="패스워드", default="123456")


class EmailRegisterSchema(BaseModel):
    email: str = Field(title="이메일")
    password: str = Field(title="패스워드")


class ResetPasswordSchema(BaseModel):
    email: str = Field(title="이메일")
    password: str = Field(title="패스워드")


class UserSchema(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    seq: int = Field(title="시퀀스")
    email: str = Field(title="이메일")
    is_active: bool = Field(title="계정 활성 여부")
    profile: GetProfileSchema
    clubs: list[ClubResponseSchema]


class UserLoginResponse(BaseModel):
    access_token: str = Field(title="access_token")
    refresh_token: str = Field(title="refresh_token")


class GoogleLoginSchema(BaseModel):
    access_token: str = Field(title="access_token")


class AppleLoginSchema(BaseModel):
    id_token: str = Field(title="token_id")


class UserSnsLoginSchema(BaseModel):
    type: str = Field(title="type")
    user: str = Field(title="user")
    email: str = Field(title="email")


class UserDeviceTokenSchema(BaseModel):
    type: DeviceTypeEnum = Field(title="type")
    token: str = Field(title="token")
