from decouple import config
from fastapi import APIRouter, Depends, HTTPException
from fastapi_jwt_auth import AuthJWT
from models.enums import AccessLevel
from models.userModel import LoginModel, UserModel
from pydantic import BaseSettings
from src import redis_sessionlist as sessionlist
from src.dbMethods import user_login

router = APIRouter(
    tags=["auth"],
)


class Settings(BaseSettings):
    authjwt_secret_key: str = str(config("JWT_SECRET_KEY", cast=str))
    authjwt_access_token_expires: int = int(config("JWT_ACCESS_T_EXPIRES", cast=int))
    authjwt_refresh_token_expires: int = int(config("JWT_REFRESH_T_EXPIRES", cast=int))
    authjwt_denylist_enabled: bool = True
    authjwt_denylist_token_checks: set = {"access", "refresh"}


@AuthJWT.load_config  # type: ignore
def get_config():
    return Settings()


@AuthJWT.token_in_denylist_loader
def check_if_token_is_blacklisted(decrypted_token):
    jti = decrypted_token["jti"]
    return not sessionlist.check_if_session_token_exists(jti)


@router.post("/login")
def login(loginUser: LoginModel, authorize: AuthJWT = Depends()):
    try:
        user_model: UserModel

        login_result = user_login(username=loginUser.username, password=loginUser.password)
        if login_result:
            user_model = login_result
        else:
            raise HTTPException(
                status_code=401,
                detail="Incorrect username or password",
            )

        access_token = authorize.create_access_token(
            subject=user_model.username,
            fresh=False,
            user_claims={"claims": user_model.json()},
        )

        refresh_token = authorize.create_refresh_token(
            subject=user_model.username,
            user_claims={"claims": user_model.json()},
        )

        sessionlist.add_session_tokens(
            access_jti=authorize.get_jti(access_token),
            refresh_jti=authorize.get_jti(refresh_token),
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }
    except:
        raise HTTPException(
            status_code=500,
            detail="Something went wrong",
        )


@router.post("/freshLogin")
def fresh_login(loginUser: LoginModel, authorize: AuthJWT = Depends()):
    try:
        user_model: UserModel

        login_result = user_login(username=loginUser.username, password=loginUser.password)
        if login_result:
            user_model = login_result
        else:
            raise HTTPException(
                status_code=401,
                detail="Incorrect username or password",
            )

        access_token = authorize.create_access_token(
            subject=user_model.username,
            fresh=True,
            user_claims={"claims": user_model.json()},
        )

        sessionlist.add_session_tokens(
            access_jti=authorize.get_jti(access_token),
        )

        return {
            "access_token": access_token,
        }
    except:
        raise HTTPException(
            status_code=500,
            detail="Something went wrong",
        )

@router.post("/refresh")
def refresh(authorize: AuthJWT = Depends()):
    try:
        authorize.jwt_refresh_token_required()

        raw = authorize.get_raw_jwt()

        if not raw:
            raise HTTPException(
                status_code=401,
                detail="Invalid token, please login again",
            )
        else:
            user_model = UserModel.parse_raw(raw["claims"])  # type: ignore

            new_access_token = authorize.create_access_token(
                subject=user_model.username,
                fresh=False,
                user_claims={"claims": user_model.json()},
            )

            new_refresh_token = authorize.create_refresh_token(
                subject=user_model.username,
                user_claims={"claims": user_model.json()},
            )

            jti = _get_jti(authorize)
            if jti is not None:
                sessionlist.delete_session_tokens(jti)

            sessionlist.add_session_tokens(
                access_jti=authorize.get_jti(new_access_token),
                refresh_jti=authorize.get_jti(new_refresh_token),
            )

            return {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
            }
    except:
        raise HTTPException(
            status_code=500,
            detail="Something went wrong",
        )

@router.post("/logout")
def logout(authorize: AuthJWT = Depends()):
    try:
        authorize.jwt_required()

        jti = _get_jti(authorize)
        if jti is not None:
            sessionlist.delete_session_tokens(jti=jti)

        return {
            "detail": "User successfully logged out",
        }
    except:
        raise HTTPException(
            status_code=500,
            detail="Something went wrong",
        )


def _get_jti(authorize: AuthJWT = Depends()):
    jwt = authorize.get_raw_jwt()
    if isinstance(jwt, dict) and jwt is not None:
        try:
            return str(jwt["jti"])
        except:
            return None
    else:
        return None


### Test points
@router.get("/protected")
def protected(authorize: AuthJWT = Depends()):
    try:
        authorize.jwt_required()

        raw = authorize.get_raw_jwt()
        if raw:
            user_model = UserModel.parse_raw(raw["claims"])  # type: ignore
            return {
                "username": user_model.username,
            }
        else:
            raise HTTPException(
                status_code=401,
                detail="Invalid token, please login again",
            )
    except:
        raise HTTPException(
            status_code=500,
            detail="Something went wrong",
        )

@router.get("/protectedAdmin")
def protected_admin(authorize: AuthJWT = Depends()):
    try:
        authorize.jwt_required()
        raw = authorize.get_raw_jwt()
        if not raw:
            raise HTTPException(
                status_code=401,
                detail="Invalid token, please try again",
            )

        user_model = UserModel.parse_raw(raw["claims"])  # type: ignore

        if(user_model.access_level.value != AccessLevel.admin.value):
            raise HTTPException(
                status_code=401,
                detail="Only admins can access this API",
            )

        return {
            "username": user_model.username,
        }
    except:
        raise HTTPException(
            status_code=500,
            detail="Something went wrong",
        )


@router.get("/protectedFresh")
def protected_fresh(authorize: AuthJWT = Depends()):
    try:
        authorize.fresh_jwt_required()

        raw = authorize.get_raw_jwt()
        if raw:
            user_model = UserModel.parse_raw(raw["claims"])  # type: ignore
            return {
                "username": user_model.username,
            }
        else:
            raise HTTPException(
                status_code=401,
                detail="Invalid token, please login again",
            )
    except:
        raise HTTPException(
            status_code=500,
            detail="Something went wrong",
        )
