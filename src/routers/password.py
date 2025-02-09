import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi_jwt_auth import AuthJWT
from models.enums import AccessLevel
from models.userModel import UserModel
import services.dbMethods as dbMethods
import services.passwordMethods as passwordMethods

router = APIRouter(
    tags=["password"],
)


@router.get("/generatePasswords")
def generate_passwords(authorize: AuthJWT = Depends()):
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

        policy = dbMethods.get_policy()
        if policy:
            passwords = passwordMethods.generate_passwords(policy)

            if passwords:
                return {"passwords": passwords}
        raise
    except:
        raise HTTPException(
            status_code=500,
            detail="Something went wrong when generating the password(s)",
        )


@router.get("/checkIfPasswordLeaked")
def check_password_leak(password: str, authorize: AuthJWT = Depends()):
    try:
        authorize.jwt_required()

        leak_count = passwordMethods.check_leaks_via_HIBP(password)

        return {"leak_count": leak_count}
    except:
        raise HTTPException(
            status_code=500,
            detail="Something went wrong when checking for password leak.",
        )
