from typing import Annotated

from fastapi import APIRouter, Depends, UploadFile, Request
from sqlalchemy import delete, select, and_
from sqlalchemy.orm import Session
from fastapi.responses import HTMLResponse, Response


from starlette.config import Config
from authlib.integrations.starlette_client import OAuth

from app.core.deps import get_db
from app.core.token import (
    create_access_token,
    create_refresh_token,
    get_current_user,
    validate_refresh_token,
    verify_password,
)
from app.helper.exception import (
    ProfileRequired,
    UserNotFoundException,
    UserPasswordNotMatchException,
)
from app.model.position import JoinPosition
from app.model.profile import Profile
from app.model.user import User
from app.model.club import JoinClub
from app.rest_api.controller.email import email_controller as email_con
from app.rest_api.controller.file import file_controller as file_con
from app.rest_api.controller.user import user_controller as con
from app.rest_api.schema.base import CreateResponse
from app.rest_api.schema.email import (
    EmailAuthCodeSchema,
    EmailPasswordResetSchema,
    EmailVerifySchema,
)
from app.rest_api.schema.profile import UpdateProfileSchema
from app.rest_api.schema.token import RefreshTokenSchema
from app.rest_api.schema.user import (
    EmailLoginSchema,
    EmailRegisterSchema,
    ResetPasswordSchema,
    UserSchema,
)
from app.constants.errors import (
    EMAIL_CONFLICT_SYSTEM_CODE,
    EMAIL_VERIFY_CODE_EXPIRED_SYSTEM_CODE,
    PASSWORD_INVALID_SYSTEM_CODE,
    EMAIL_AUTH_NUMBER_INVALID_SYSTEM_CODE,
    USER_NOT_FOUND_SYSTEM_CODE,
    USER_PROFILE_REQUIRED_SYSTEM_CODE,
)

from app.model.sns import Sns


user_router = APIRouter(tags=["user"], prefix="/user")


@user_router.post(
    "/email/request/verify/code",
    description=f"""
    **[API Description]** <br><br>
    Request verify code for register user and duplicated check of email <br><br>
    **[Exception List]** <br><br> 
    {EMAIL_CONFLICT_SYSTEM_CODE}: 이메일 중복 오류(409)
    """,
)
def email_request_verify_code(
    user_data: EmailVerifySchema, db: Session = Depends(get_db)
):
    email_con.send_verify_code(db, user_data)
    return {"success": True}


@user_router.post(
    "/email/verify/auth/code",
    description=f"""
    **[API Description]** <br><br>
    Verify code(expiration time: 3min) <br><br>
    **[Exception List]** <br><br>
    {EMAIL_AUTH_NUMBER_INVALID_SYSTEM_CODE}: 인증번호 오류(400) <br><br>
    {EMAIL_VERIFY_CODE_EXPIRED_SYSTEM_CODE}: 이메일 인증 만료(400)
    """,
)
def email_verify_auth_code(
    user_data: EmailAuthCodeSchema, db: Session = Depends(get_db)
):
    email_con.verify_auth_code(db, user_data)
    return {"success": True}


@user_router.post(
    "/email/register",
    description=f"""
    **[API Description]** <br><br>
    Verify code(expiration time: 3min) <br><br>
    **[Exception List]** <br><br>
    {PASSWORD_INVALID_SYSTEM_CODE}: 비밀번호 오류(400) <br><br>
    {EMAIL_CONFLICT_SYSTEM_CODE}: 이메일 중복 오류(409)
    """,
    response_model=CreateResponse,
)
def email_register_user(user_data: EmailRegisterSchema, db: Session = Depends(get_db)):
    con.email_register_user(db, user_data)
    return {"success": True}


@user_router.post(
    "/email/login",
    description=f"""
    **[API Description]** <br><br>
    Email login <br><br>
    **[Exception List]** <br><br>
    {PASSWORD_INVALID_SYSTEM_CODE}: 비밀번호 오류(400) <br><br>
    {USER_NOT_FOUND_SYSTEM_CODE}: 사용자 정보 검색 오류(404) <br><br>
    """,
)
def email_login(user_data: EmailLoginSchema, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == user_data.email))

    if not user:
        raise UserNotFoundException

    result = verify_password(user_data.password, user.password)

    if not result:
        raise UserPasswordNotMatchException

    access_token = create_access_token(data={"sub": str(user_data.email)})
    refresh_token = create_refresh_token(data={"sub": str(user_data.email)})

    return {"access_token": access_token, "refresh_token": refresh_token}


@user_router.post(
    "/email/request/password/reset",
    description=f"""
    **[API Description]** <br><br>
    Request auth code with email<br><br>
    **[Exception List]** <br><br>
    {USER_NOT_FOUND_SYSTEM_CODE}: 사용자 정보 검색 오류(404) <br><br>
    """,
)
def email_request_password_reset(
    user_data: EmailPasswordResetSchema, db: Session = Depends(get_db)
):
    email_con.send_verify_code_for_reset_password(db, user_data)
    return {"success": True}


@user_router.post(
    "/password/reset",
    description=f"""
    **[API Description]** <br><br>
    Request auth code with email<br><br>
    **[Exception List]** <br><br>
    {USER_NOT_FOUND_SYSTEM_CODE}: 사용자 정보 검색 오류(404) <br><br>
    """,
)
def user_reset_password(user_data: ResetPasswordSchema, db: Session = Depends(get_db)):
    con.reset_password(db, user_data)
    return {"success": True}


@user_router.post("/token/refresh")
def get_access_token_using_refresh_token(
    user_data: RefreshTokenSchema,
    db: Session = Depends(get_db),
):
    username = validate_refresh_token(user_data, db)

    access_token = create_access_token(data={"sub": username})
    refresh_token = create_refresh_token(data={"sub": username})

    return {"access_token": access_token, "refresh_token": refresh_token}


@user_router.get(
    "/me",
    description=f"""
    **[API Description]** <br><br>
    Get my profile API <br><br>
    **[Exception List]** <br><br>
    {USER_PROFILE_REQUIRED_SYSTEM_CODE}: 사용자 프로필(400) <br><br>
    """,
    response_model=UserSchema,
)
def get_user_info_with_profile(token: Annotated[str, Depends(get_current_user)]):
    if not token.profile:
        raise ProfileRequired

    return token


@user_router.patch("/me")
def update_user_profile(
    user_data: UpdateProfileSchema,
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    profile = token.profile
    position = user_data.position

    token.is_active = user_data.is_active

    if not profile:
        profile = Profile(user_seq=token.seq, nickname=user_data.nickname)
        db.add(profile)
        db.commit()
        db.refresh(profile)
    else:
        profile = profile[0]

        for key, value in user_data.dict(exclude_none=True).items():
            setattr(profile, key, value)

    if position is not None:
        sql = delete(JoinPosition).where(JoinPosition.profile_seq == profile.seq)
        db.execute(sql)

        obj = [
            JoinPosition(profile_seq=profile.seq, position_seq=item)
            for item in position
        ]
        db.bulk_save_objects(obj)

    db.commit()
    db.flush()
    return {"success": True}


@user_router.delete("/me")
def delete_user(
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    user = db.query(User).filter_by(seq=token.seq).first()

    if user:
        db.delete(user)
        db.flush()
        db.commit()
        return {"success": True}


@user_router.post("/club/{club_seq}")
def join_club(
    club_seq: int,
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    join_club = JoinClub(user_seq=token.seq, clubs_seq=club_seq)
    db.add(join_club)

    db.commit()
    db.flush()

    return {"success": True}


@user_router.delete("/club/{club_seq}")
def quit_club(
    club_seq: int,
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    sql = delete(JoinClub).where(
        and_(JoinClub.user_seq == token.seq, JoinClub.clubs_seq == club_seq)
    )
    db.execute(sql)

    db.commit()
    db.flush()
    return {"success": True}


@user_router.post("/me/profile/img")
async def create_user_profile_img(
    profile_img: UploadFile,
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    file_contents = await profile_img.read()
    file_con.upload_uesr_profile_img(file_contents, token, profile_img.filename, db)
    return {"success": True}


@user_router.delete("/me/profile/img")
def delete_user_profile_img(
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    proflie = token.profile[0]
    proflie.img = ""
    db.commit()
    db.flush()
    return {"success": True}


GOOGLE_CLIENT_ID = (
    "389487021466-hvncp2oop9bma1bssqhd7huh16p3m8sn.apps.googleusercontent.com"
)
GOOGLE_CLIENT_SECRET = "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"

config_data = {
    "GOOGLE_CLIENT_ID": GOOGLE_CLIENT_ID,
    "GOOGLE_CLIENT_SECRET": GOOGLE_CLIENT_SECRET,
}
starlette_config = Config(environ=config_data)
oauth = OAuth(starlette_config)
oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
    },
)


@user_router.get("/sns/login", response_class=HTMLResponse)
def test(request: Request):
    return HTMLResponse('<a href="/user/google/login">login</a>')


@user_router.get("/google/login")
async def login(request: Request):
    redirect_uri = request.url_for("auth")
    return await oauth.google.authorize_redirect(
        request, redirect_uri, access_type="offline"
    )


@user_router.get("/auth/google")
async def auth(request: Request, db: Session = Depends(get_db)):
    access_token = await oauth.google.authorize_access_token(request)
    user_data = await oauth.google.parse_id_token(
        access_token, access_token["userinfo"]["nonce"]
    )
    request.session["user"] = dict(user_data)
    request.session.pop("user", None)

    email = user_data["email"]

    # If User does not exists then register User
    user = db.scalar(select(User).where(User.email == email))

    if user is None:
        password = user_data["sub"]
        user_login_data = EmailRegisterSchema(email=email, password=password)
        con.email_register_user(db, user_login_data)
        # TODO add & commit user_login_data

        sns = Sns(sub=user_data["sub"], refresh_token=access_token["refresh_token"])
        db.add(sns)
        db.commit()

    return Response(status_code=200)
