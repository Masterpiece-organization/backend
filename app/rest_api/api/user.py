from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import get_db
from app.core.token import (
    create_access_token,
    create_refresh_token,
    get_current_user,
    validate_refresh_token,
    verify_password,
)
from app.model.user import User
from app.rest_api.controller.email import email_controller as email_con
from app.rest_api.controller.user import user_controller as con
from app.rest_api.schema.base import CreateResponse
from app.rest_api.schema.email import (
    EmailAuthCodeSchema,
    EmailPasswordResetSchema,
    EmailVerifySchema,
)
from app.rest_api.schema.profile import ProfileSchema
from app.rest_api.schema.token import RefreshTokenSchema
from app.rest_api.schema.user import (
    EmailLoginSchema,
    EmailRegisterSchema,
    ResetPasswordSchema,
    UserSchema,
)

user_router = APIRouter(tags=["user"], prefix="/user")


@user_router.post("/email/request/verify/code")
def email_request_verify_code(
    user_data: EmailVerifySchema, db: Session = Depends(get_db)
):
    email_con.send_verify_code(db, user_data)
    return {"success": True}


@user_router.post("/email/verify/auth/code")
def email_verify_auth_code(
    user_data: EmailAuthCodeSchema, db: Session = Depends(get_db)
):
    email_con.verify_auth_code(db, user_data)
    return {"success": True}


@user_router.post("/email/register", response_model=CreateResponse)
def email_register_user(user_data: EmailRegisterSchema, db: Session = Depends(get_db)):
    con.email_register_user(db, user_data)
    return {"success": True}


@user_router.post("/email/login")
def email_login(user_data: EmailLoginSchema, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == user_data.email))

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"system_code": "USER_NOT_FOUND"},
        )

    if not user.profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"system_code": "USER_PROFILE_NOT_FOUND"},
        )

    result = verify_password(user_data.password, user.password)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"system_code": "USER_PASSWORD_NOT_MATCHED"},
        )

    access_token = create_access_token(data={"sub": str(user_data.email)})
    refresh_token = create_refresh_token(data={"sub": str(user_data.email)})

    return {"access_token": access_token, "refresh_token": refresh_token}


@user_router.post("/email/request/password/reset")
def email_request_password_reset(
    user_data: EmailPasswordResetSchema, db: Session = Depends(get_db)
):
    email_con.send_verify_code_for_reset_password(db, user_data)
    return {"success": True}


@user_router.post("/password/reset")
def user_reset_password(user_data: ResetPasswordSchema, db: Session = Depends(get_db)):
    con.reset_password(db, user_data)
    return {"success": True}


@user_router.post("/token/refresh")
def get_access_token_using_refresh_token(
    user_data: RefreshTokenSchema,
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    validate_refresh_token(user_data, db)

    access_token = create_access_token(data={"sub": token.email})
    refresh_token = create_refresh_token(data={"sub": token.email})

    return {"access_token": access_token, "refresh_token": refresh_token}


@user_router.get("/me", response_model=UserSchema)
def get_user_info_with_profile(
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    return token


@user_router.patch("/me")
def update_user_profile(
    user_data: ProfileSchema,
    token: Annotated[str, Depends(get_current_user)],
    db: Session = Depends(get_db),
):
    profile = token.profile[0]
    profile.nickname = user_data.nickname

    db.commit()
    db.flush()
    return {"success": True}