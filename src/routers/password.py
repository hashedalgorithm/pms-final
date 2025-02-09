import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi_jwt_auth import AuthJWT
from models.enums import AccessLevel
from models.userModel import UserModel
from src import dbMethods, passwordMethods

router = APIRouter(
    tags=["password"],
)


@router.get("/generatePasswords")
def generate_passwords(batch_size: int = 1, authorize: AuthJWT = Depends()):
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

        policy = dbMethods.get_policy()
        if policy:
            passwords = passwordMethods.generate_passwords(batch_size, policy)

            if passwords:
                return {"passwords": passwords}
        raise
    except:
        raise HTTPException(
            status_code=500,
            detail="Something went wrong when generating the password(s)",
        )


@router.get("/generatePasswordsCSV")
def generate_passwords_csv(batch_size: int = 1, authorize: AuthJWT = Depends()):
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

        policy = dbMethods.get_policy()
        if policy:
            passwords = passwordMethods.generate_passwords(batch_size, policy)

            if passwords:
                si = io.StringIO()
                cw = csv.writer(si)
                for password in passwords:
                    cw.writerow([password])

                response = Response(content=si.getvalue(), media_type="text/csv")
                response.headers["Content-Disposition"] = "attachment; filename=passwords.csv"

                return response

        raise HTTPException(
            status_code=500,
            detail="Something went wrong when generating the password(s)",
        )
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