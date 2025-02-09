from fastapi import APIRouter, Depends, HTTPException
from fastapi_jwt_auth import AuthJWT
from models.enums import AccessLevel
from src import dbMethods, passwordMethods
from models.userModel import UserModel

router = APIRouter(
    tags=["accounts"],
)


@router.get("/addApplicationCreds")
def add_application_creds(username: str, app_name: str, password: str, authorize: AuthJWT = Depends()):
    try:
        authorize.jwt_required()
        raw = authorize.get_raw_jwt()

        if not raw:
            raise HTTPException(
                status_code=401,
                detail="Server Error - Forbidden",
            )

        user_model = UserModel.parse_raw(raw["claims"])  # type: ignore

        if (user_model.access_level.value != AccessLevel.admin.value):
            raise HTTPException(
                status_code=401,
                detail="Server Error - Forbidden",
            )

        passwords = dbMethods.add_application_password_pair(
            username, app_name, password)

        if (not passwords):
            raise HTTPException(
                status_code=500,
                detail="Server Error",
            )

        return {"message": "Application password set successfully"}
    except:
        raise HTTPException(
            status_code=500,
            detail="Server Error",
        )


@router.get("/getApplicationCreds")
def get_application_creds(authorize: AuthJWT = Depends()):
    try:
        authorize.jwt_required()
        raw = authorize.get_raw_jwt()

        if not raw:
            raise HTTPException(
                status_code=401,
                detail="Server Error - Forbidden",
            )

        user_model = UserModel.parse_raw(raw["claims"])  # type: ignore

        passwords = dbMethods.get_all_application_password_pairs(
            user_model.username)

        if (not passwords):
            raise HTTPException(
                status_code=500,
                detail="Something went wrong when fetching application passwords.",
            )

        return {"passwords": passwords}
    except:
        raise HTTPException(
            status_code=500,
            detail="Something went wrong when fetching application passwords.",
        )


@router.get("/addUser")
def add_user(username: str, password: str, access_level: AccessLevel, authorize: AuthJWT = Depends()):
    try:
        authorize.jwt_required()
        raw = authorize.get_raw_jwt()

        if not raw:
            raise HTTPException(
                status_code=401,
                detail="Server Error",
            )

        user_model = UserModel.parse_raw(raw["claims"])  # type: ignore

        if (user_model.access_level.value != AccessLevel.admin.value):
            raise HTTPException(
                status_code=401,
                detail="Server Error - Forbidden",
            )

        policy = dbMethods.get_policy()

        if not policy:
            raise HTTPException(
                status_code=500, detail="Internal Server Error")

        if (not passwordMethods.validate_password(password, policy)):
            raise HTTPException(
                status_code=401,
                detail="Server Error - Password does not meet current password requirements.",
            )

        if (passwordMethods.check_leaks_via_HIBP(password) > 0):
            raise HTTPException(
                status_code=401,
                detail="Server Error - Password is leaked previously!",
            )

        ret_code, message = dbMethods.add_user(
            username, password, access_level=access_level)

        if (ret_code != 0):
            raise HTTPException(
                status_code=401,
                detail=message,
            )

        return {"message": message}

    except:
        raise HTTPException(
            status_code=500,
            detail="Internal Server Error",
        )


@router.get("/changeUserPassword")
def change_user_password(password: str, authorize: AuthJWT = Depends()):
    try:
        authorize.fresh_jwt_required()
        raw = authorize.get_raw_jwt()

        if not raw:
            raise HTTPException(
                status_code=401,
                detail="Server Error - Forbidden",
            )

        user_model = UserModel.parse_raw(raw["claims"])  # type: ignore
        policy = dbMethods.get_policy()
        if not policy:
            raise

        if (not passwordMethods.validate_password(password, policy)):
            raise HTTPException(
                status_code=401,
                detail="Password does not meet current password requirements.",
            )

        if (passwordMethods.check_leaks_via_HIBP(password) > 0):
            raise HTTPException(
                status_code=401,
                detail="Password has appeared in leaks online, please use a different one.",
            )

        ret_code, message = dbMethods.change_user_pass(
            user_model.username, password)

        if (ret_code != 0):
            raise HTTPException(
                status_code=401,
                detail=message,
            )

        return {"message": message}

    except:
        raise HTTPException(
            status_code=500,
            detail="Something went wrong",
        )
