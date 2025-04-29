from datetime import datetime
from typing import Annotated
import requests
import secrets

import httpx
from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, Request, UploadFile, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy import delete, func, select, or_
from sqlalchemy.orm import Session
from starlette.config import Config

from app.core.config import settings
from app.core.deps import get_db
from app.core.token import (
    create_access_token,
    create_refresh_token,
    get_current_user,
    validate_refresh_token,
    verify_password,
    create_rls_refresh_token,
    create_rls_access_token,
)
from app.core.utils import error_responses
from app.helper.exception import (
    EmailAuthNumberInvalidException,
    EmailConflictException,
    EmailExpiredException,
    PasswordInvalidException,
    ProfileRequired,
    SnsRequired,
    UserNotFoundException,
    UserPasswordNotMatchException,
    UserRetrieveFailException,
    DeviceTokenRetrieveFailException,
)
from app.model.club import Club, JoinClub
from app.model.clubPosting import ClubPosting
from app.model.device import Device
from app.model.guest import Guest
from app.model.match import Match
from app.model.memberPosting import MemberPosting
from app.model.poll import JoinPoll, Poll
from app.model.position import JoinPosition
from app.model.profile import Profile
from app.model.sns import Sns
from app.model.user import User
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
    UserLoginResponse,
    UserSchema,
    GoogleLoginSchema,
    UserSnsLoginSchema,
    UserDeviceTokenSchema,
)

user_router = APIRouter(tags=["user"], prefix="/user")


@user_router.post(
    "/email/request/verify/code",
    summary="이메일 중복 여부 확인",
    responses={409: {"description": error_responses([EmailConflictException])}},
    response_model=CreateResponse,
)
def email_request_verify_code(
    user_data: EmailVerifySchema, db: Session = Depends(get_db)
):
    email_con.send_verify_code(db, user_data)
    return {"success": True}


@user_router.post(
    "/email/verify/auth/code",
    summary="이메일 인증번호 인증",
    responses={
        400: {
            "description": error_responses(
                [EmailAuthNumberInvalidException, EmailExpiredException]
            )
        }
    },
    response_model=CreateResponse,
)
def email_verify_auth_code(
    user_data: EmailAuthCodeSchema, db: Session = Depends(get_db)
):
    email_con.verify_auth_code(db, user_data)
    return {"success": True}


@user_router.post(
    "/email/register",
    summary="이메일 회원가입(등록)",
    responses={
        400: {"description": error_responses([PasswordInvalidException])},
        409: {"description": error_responses([EmailConflictException])},
    },
    response_model=CreateResponse,
)
def email_register_user(user_data: EmailRegisterSchema, db: Session = Depends(get_db)):
    con.email_register_user(db, user_data)
    return {"success": True}


@user_router.post(
    "/email/login",
    summary="로그인(이메일)",
    responses={
        404: {"description": error_responses([UserNotFoundException])},
        422: {"description": error_responses([UserPasswordNotMatchException])},
    },
    response_model=UserLoginResponse,
)
def email_login(user_data: EmailLoginSchema, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == user_data.email))

    if not user:
        raise UserNotFoundException

    result = verify_password(user_data.password, user.password)

    if not result:
        raise UserPasswordNotMatchException

    access_token = create_access_token(
        data={"sub": str(user_data.email), "type": "email"}
    )
    refresh_token = create_refresh_token(
        data={"sub": str(user_data.email), "type": "email"}
    )
    return {"access_token": access_token, "refresh_token": refresh_token}


@user_router.post(
    "/email/request/password/reset",
    summary="패스워드 초기화 인증번호 요청",
    responses={404: {"description": error_responses([UserNotFoundException])}},
    response_model=CreateResponse,
)
def email_request_password_reset(
    user_data: EmailPasswordResetSchema, db: Session = Depends(get_db)
):
    email_con.send_verify_code_for_reset_password(db, user_data)
    return {"success": True}


@user_router.post(
    "/password/reset",
    summary="패스워드 초기화",
    responses={404: {"description": error_responses([UserNotFoundException])}},
    response_model=CreateResponse,
)
def user_reset_password(user_data: ResetPasswordSchema, db: Session = Depends(get_db)):
    con.reset_password(db, user_data)
    return {"success": True}


@user_router.post(
    "/token/refresh",
    summary="토큰 재발급",
    responses={404: {"description": error_responses([UserNotFoundException])}},
    response_model=UserLoginResponse,
)
def get_access_token_using_refresh_token(
    data: RefreshTokenSchema,
    db: Session = Depends(get_db),
):
    username = validate_refresh_token(data, db)
    access_token = create_access_token(data={"sub": username})
    refresh_token = create_refresh_token(data={"sub": username})

    return {"access_token": access_token, "refresh_token": refresh_token}


@user_router.get(
    "/me",
    summary="사용자 정보 조회",
    response_model=UserSchema,
    responses={400: {"description": error_responses([ProfileRequired])}},
)
def get_user_info_with_profile(
    token: Annotated[str, Depends(get_current_user)],
):
    if not token.profile:
        raise ProfileRequired

    return token


@user_router.patch(
    "/me",
    summary="사용자 정보 업데이트",
    response_model=CreateResponse,
)
def update_user_profile(
    user_data: UpdateProfileSchema,
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    profile = token.profile
    position = user_data.positions

    token.is_active = user_data.is_active

    if not profile:
        profile = Profile(
            user_seq=token.seq,
            nickname=user_data.nickname,
            gender=user_data.gender,
            location=user_data.location,
            age=user_data.age,
            foot=user_data.foot,
            level=user_data.level,
            positions=user_data.positions,
        )
        db.add(profile)
        db.commit()
        db.refresh(profile)
    else:
        # profile = profile[0]

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


@user_router.patch(
    "/active_status",
    summary="사용자 활성 상태 업데이트",
    response_model=CreateResponse,
)
def update_user_active_status(
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    token.is_active = not token.is_active
    db.commit()
    return {"success": True}


@user_router.delete(
    "/me",
    summary="사용자 삭제",
    response_model=CreateResponse,
)
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


@user_router.post(
    "/me/profile/img",
    summary="사용자 프로필 업로드",
    response_model=CreateResponse,
)
async def create_user_profile_img(
    profile_img: UploadFile,
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    file_contents = await profile_img.read()
    file_con.upload_uesr_profile_img(file_contents, token, profile_img.filename, db)
    return {"success": True}


@user_router.delete(
    "/me/profile/img",
    summary="사용자 프로필 삭제",
    response_model=CreateResponse,
)
def delete_user_profile_img(
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    proflie = token.profile[0]
    proflie.img = ""
    db.commit()
    db.flush()
    return {"success": True}


@user_router.get(
    "/posting",
    summary="사용자 포스팅 조회",
)
def get_user_posting(
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    tables = [
        (ClubPosting, "ClubPosting"),
        (Match, "Match"),
        (Guest, "Guest"),
        (MemberPosting, "MemberPosting"),
    ]
    my_postings = []

    for table, table_name in tables:
        postings = db.query(table).filter(table.user_seq == token.seq).all()
        for posting in postings:
            if isinstance(posting, Guest):
                setattr(posting, "match", posting.match)
            my_postings.extend([(posting, table_name)])
    my_postings.sort(key=lambda x: x[0].date, reverse=True)

    return [
        {"table_name": table_name, "posting": posting}
        for posting, table_name in my_postings
    ]


@user_router.get(
    "/match_history",
    summary="사용자 매치 히스토리 조회",
)
def get_match_history(
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    club_seq_counts = (
        db.query(Poll.club_seq, func.count())
        .join(JoinPoll, Poll.seq == JoinPoll.poll_seq)
        .filter(JoinPoll.user_seq == token.seq, JoinPoll.attend == True)
        .group_by(Poll.club_seq)
        .all()
    )

    match_history = []
    for club_seq, count in club_seq_counts:
        club = db.query(Club).filter(Club.seq == club_seq).first()
        match_history.append({"club": club, "match_count": count})

    return match_history


@user_router.get(
    "/match_schedule",
    summary="사용자 예정된 매치 일정 조회",
)
def get_match_schedule(
    token: Annotated[str, Depends(get_current_user)],
    include_match_history: bool,
    db: Session = Depends(get_db),
):
    user_poll_subquery = (
        db.query(Poll.match_seq)
        .join(JoinPoll, Poll.seq == JoinPoll.poll_seq)
        .filter(JoinPoll.user_seq == token.seq, JoinPoll.attend == True)
        .subquery()
    )

    user_club_subquery = (
        db.query(JoinClub.clubs_seq)
        .filter(JoinClub.user_seq == token.seq, JoinClub.accepted == True)
        .subquery()
    )

    if include_match_history:
        match_schedule = (
            db.query(Match)
            .filter(
                Match.seq.in_(user_poll_subquery),
                Match.away_club != None,
            )
            .order_by(Match.match_date.desc())
            .all()
        )
    else:
        match_schedule = (
            db.query(Match)
            .filter(
                Match.seq.in_(user_poll_subquery),
                Match.away_club != None,
                Match.match_date >= datetime.today(),
                or_(
                    Match.home_club_seq.in_(user_club_subquery),
                    Match.away_club_seq.in_(user_club_subquery),
                ),
            )
            .order_by(Match.match_date.asc())
            .all()
        )

    return match_schedule


@user_router.get("/sns/login", response_class=HTMLResponse, deprecated=True)
def test(request: Request):
    html_content = """
    <html>
    <body>
        <a href="/user/google/login">google login</a>
        <br>
        <a href="/user/kakao/login">kako login</a>
        <br>
        <a href="/user/apple/login">apple login</a>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@user_router.post("/sns/login")
def user_sns_login(data: UserSnsLoginSchema, db: Session = Depends(get_db)):
    sns = db.query(Sns).filter(Sns.user == data.user, Sns.type == data.type).first()

    if sns is None:
        user_login_data = EmailRegisterSchema(
            email=data.email, password=secrets.token_urlsafe(13)
        )
        user = con.email_register_user(db, user_login_data)
        sns = Sns(
            sub="",
            refresh_token="",
            user_seq=user.seq,
            type=data.type,
            user=data.user,
        )
        db.add(sns)
        db.commit()

    access_token = create_access_token(
        data={"sub": str(sns.join_user.email), "type": data.type}
    )
    refresh_token = create_refresh_token(
        data={"sub": str(sns.join_user.email), "type": data.type}
    )

    return {"access_token": access_token, "refresh_token": refresh_token}


@user_router.get("/google/login", deprecated=True)
async def login(request: Request):
    redirect_uri = request.url_for("auth")
    if settings.SERVER_ENV != "LOCAL":
        redirect_uri = str(redirect_uri).replace("http", "https")
    oauth = settings.GOOGLE_OAUTH
    print(request.session)
    res = await oauth.authorize_redirect(request, redirect_uri, access_type="offline")
    print(request.session)
    return res


@user_router.get("/auth/google", deprecated=True)
async def auth(request: Request, db: Session = Depends(get_db)):
    oauth = settings.GOOGLE_OAUTH
    print(request.session)
    access_token = await oauth.authorize_access_token(request)
    user_data = await oauth.parse_id_token(
        access_token, access_token["userinfo"]["nonce"]
    )
    request.session["user"] = dict(user_data)
    request.session.pop("user", None)

    email = user_data["email"]

    user = db.scalar(select(User).where(User.email == email))

    if user is None:
        user_login_data = EmailRegisterSchema(email=email, password=user_data["sub"])
        user = con.email_register_user(db, user_login_data)
        sns = Sns(
            sub=user_data["sub"],
            refresh_token=access_token["refresh_token"],
            user_seq=user.seq,
            type="google",
        )
        db.add(sns)
        db.commit()

    access_token = create_access_token(data={"sub": str(email)})
    refresh_token = create_refresh_token(data={"sub": str(email)})

    return {"access_token": access_token, "refresh_token": refresh_token}


KAKAO_CLIENT_ID = "71cda8d5771dce9ff79f0c09292078e2"
KAKAO_CLIENT_SECRET = "7WIPuibxSxC20kWEu4DzkPKBs2EpFFH1"

config_kako = {
    "KAKAO_CLIENT_ID": KAKAO_CLIENT_ID,
    "KAKAO_CLIENT_SECRET": KAKAO_CLIENT_SECRET,
}
starlette_config_kakao = Config(environ=config_kako)
oauth_kako = OAuth(starlette_config_kakao)
oauth_kako.register(
    name="kakao",
    authorize_url="https://kauth.kakao.com/oauth/authorize",
    authorize_params=None,
    authorize_params_extra=None,
    authorize_handler=None,
    authorize_callback=None,
    token_endpoint="https://kauth.kakao.com//oauth/token",
    token_params_extra=None,
    client_kwargs={
        "scope": "profile_nickname",
        "grant_type": "authorization_code",
        "token_endpoint_auth_method": "client_secret_basic",
    },
)


@user_router.get("/kakao/login", deprecated=True)
async def login(request: Request):
    redirect_uri = request.url_for("kakao_auth")
    print(redirect_uri)
    return await oauth_kako.kakao.authorize_redirect(request, redirect_uri)


@user_router.get("/auth/kako", deprecated=True)
async def kakao_auth(request: Request, db: Session = Depends(get_db)):
    # token = await oauth_kako.kakao.authorize_access_token(request)

    token_url = "https://kauth.kakao.com/oauth/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "authorization_code",
        "client_id": KAKAO_CLIENT_ID,
        "redirect_uri": "http://127.0.0.1:8000/user/auth/kako",
        "code": request.query_params.get("code"),
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, headers=headers, data=data)

        if response.status_code == 200:
            sns_token = response.json()
            user_data = await get_kako_user_info(sns_token["access_token"])

            email = user_data["kakao_account"]["profile"]["nickname"]
            user = db.scalar(select(User).where(User.email == email))

            if user is None:
                password = "temp_password"
                user_login_data = EmailRegisterSchema(email=email, password=password)
                user = con.email_register_user(db, user_login_data)

                sns = Sns(
                    sub="temp_passowrd",
                    refresh_token=sns_token["refresh_token"],
                    user_seq=user.seq,
                    type="kako",
                )
                db.add(sns)
                db.commit()

            access_token = create_access_token(data={"sub": str(email)})
            refresh_token = create_refresh_token(data={"sub": str(email)})

            return {"access_token": access_token, "refresh_token": refresh_token}

        else:
            print("Token request failed:", response.status_code, response.text)


@user_router.get("/kako/user_info", deprecated=True)
async def get_kako_user_info(access_token):
    user_info_url = "https://kapi.kakao.com/v2/user/me"
    headers = {
        "Authorization": f"Bearer {access_token}",
    }

    async with httpx.AsyncClient() as client:
        response = await client.get(user_info_url, headers=headers)
        if response.status_code == 200:
            user_data = response.json()
            return user_data
        else:
            print("Token request failed:", response.status_code, response.text)


@user_router.get("/kako/token/refresh", deprecated=True)
async def get_kako_access_token(refresh_token):
    token_url = "https://kauth.kakao.com/oauth/token"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded;charset=utf-8",
    }
    data = {
        "grant_type": "refresh_token",
        "client_id": KAKAO_CLIENT_ID,
        "client_secret": KAKAO_CLIENT_SECRET,
        "refresh_token": refresh_token,
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, headers=headers, data=data)
        if response.status_code == 200:
            user_data = response.json()
            return user_data
        else:
            print("Token request failed:", response.status_code, response.text)


@user_router.get("/user/sns/refresh_token")
def get_sns_refresh_token(
    token: Annotated[str, Depends(get_current_user)], db: Session = Depends(get_db)
):
    sns = db.query(Sns).filter(Sns.user_seq == token.seq).first()

    if not sns:
        return SnsRequired

    return sns


@user_router.get(
    "/{user_seq}/",
    summary="사용자 정보 조회",
    responses={404: {"description": error_responses([UserRetrieveFailException])}},
    response_model=UserSchema,
)
def get_user_detail(
    user_seq: int,
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    user = db.scalar(select(User).where(User.seq == user_seq))
    if not user:
        raise UserRetrieveFailException
    return user


@user_router.post("/google/login", summary="구글 로그인", deprecated=True)
def get_user_detail(data: GoogleLoginSchema, db: Session = Depends(get_db)):
    access_token = data.access_token
    user_info = requests.get(
        "https://www.googleapis.com/oauth2/v1/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    email = user_info.json().get("email")

    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        import string

        letters_set = string.ascii_letters
        user_login_data = EmailRegisterSchema(email=email, password=letters_set)
        user = con.email_register_user(db, user_login_data)
        sns = Sns(
            sub="SUB",
            refresh_token="refresh",
            user_seq=user.seq,
            type="google",
        )
        db.add(sns)
        db.commit()

    access_token = create_access_token(data={"sub": str(email)})
    refresh_token = create_refresh_token(data={"sub": str(email)})

    return {"access_token": access_token, "refresh_token": refresh_token}


@user_router.get("/device")
def get_device(
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    device = db.scalar(select(Device.token).where(Device.user_seq == token.seq))
    if not device:
        raise DeviceTokenRetrieveFailException

    return device


@user_router.post("/device")
def add_device(
    data: UserDeviceTokenSchema,
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    device = db.scalar(
        select(Device).where(Device.user_seq == token.seq, Device.type == data.type)
    )
    if not device:
        device = Device(
            user_seq=token.seq,
            token=data.token,
            type=data.type,
        )
        db.add(device)

    else:
        device.token = data.token

    db.commit()

    return {"success": True}


@user_router.post("/rls/token")
def add_device(
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    refresh_token = create_rls_refresh_token(data={"sub": str(token.seq)})
    access_token = create_rls_access_token(data={"sub": str(token.seq)})
    return {"access_token": access_token, "refresh_token": refresh_token}
