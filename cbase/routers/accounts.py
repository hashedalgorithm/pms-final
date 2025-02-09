from fastapi import APIRouter, Depends, HTTPException
from fastapi_jwt_auth import AuthJWT
from models.enums import AccessLevel
from src import dbMethods, passwordMethods
from models.userModel import UserModel

router = APIRouter(
    tags=["accounts"],
)


@router.get("/addApplicationCreds")
def add_application_creds(username: str, application_name: str, password: str, authorize: AuthJWT = Depends()):
    try:
        authorize.jwt_required()
        raw = authorize.get_raw_jwt()

        if not raw:
            raise HTTPException(
                status_code=401,
                detail="Invalid token, please login again",
            )

        user_model = UserModel.parse_raw(raw["claims"])  # type: ignore

        if(user_model.access_level.value != AccessLevel.admin.value):
            raise HTTPException(
                status_code=401,
                detail="Only admins can access this API",
            )

        passwords = dbMethods.add_application_password_pair(username, application_name, password)

        if(not passwords):
            raise HTTPException(
            status_code=500,
            detail="Something went wrong when setting application password.",
        )

        return {"message": "Application password set successfully"}
    except:
        raise HTTPException(
            status_code=500,
            detail="Something went wrong when setting application password.",
        )


# TODO: App passwords are updated automatically when policy changes
# @router.get("/update-application-password")
# def update_application_password(password: str, application_name: str, authorize: AuthJWT = Depends()):
#     try:
#         authorize.jwt_required()
#         raw = authorize.get_raw_jwt()

#         if not raw:
#             raise HTTPException(
#                 status_code=401,
#                 detail="Invalid token, please login again",
#             )

#         user_model = UserModel.parse_raw(raw["claims"])  # type: ignore

#         passwords = dbMethods.update_application_password(user_model.username, application_name, password)

#         if(not passwords):
#             raise HTTPException(
#             status_code=500,
#             detail="Something went wrong when updating the application password.",
#         )

#         return {"message": "Application password updated successfully"}
#     except:
#         raise HTTPException(
#             status_code=500,
#             detail="Something went wrong when updating the application password.",
#         )

@router.get("/getApplicationCreds")
def get_application_creds(authorize: AuthJWT = Depends()):
    try:
        authorize.jwt_required()
        raw = authorize.get_raw_jwt()

        if not raw:
            raise HTTPException(
                status_code=401,
                detail="Invalid token, please login again",
            )

        user_model = UserModel.parse_raw(raw["claims"])  # type: ignore
        
        passwords = dbMethods.get_all_application_password_pairs(user_model.username)

        if(not passwords):
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
                detail="Invalid token, please login again",
            )
        
        user_model = UserModel.parse_raw(raw["claims"])  # type: ignore
        
        if(user_model.access_level.value != AccessLevel.admin.value):
            raise HTTPException(
                status_code=401,
                detail="Only admins can access this API",
            )

        policy = dbMethods.get_policy()

        if not policy:
            raise
        
        if(not passwordMethods.validate_password(password, policy)):
            raise HTTPException(
                status_code=401,
                detail="Password does not meet current password requirements.",
            )

        if(passwordMethods.check_leaks_via_HIBP(password) > 0):
            raise HTTPException(
                status_code=401,
                detail="Password has appeared in leaks online, please use a different one.",
            )

        ret_code, message = dbMethods.add_user(username, password, access_level=access_level)

        if(ret_code != 0):
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


@router.get("/changeUserPassword")
def change_user_password(password: str, authorize: AuthJWT = Depends()):
    try:
        authorize.fresh_jwt_required()
        raw = authorize.get_raw_jwt()

        if not raw:
            raise HTTPException(
                status_code=401,
                detail="Invalid token, please login again",
            )

        user_model = UserModel.parse_raw(raw["claims"])  # type: ignore
        policy = dbMethods.get_policy()
        if not policy:
            raise
        
        if(not passwordMethods.validate_password(password, policy)):
            raise HTTPException(
                status_code=401,
                detail="Password does not meet current password requirements.",
            )

        if(passwordMethods.check_leaks_via_HIBP(password) > 0):
            raise HTTPException(
                status_code=401,
                detail="Password has appeared in leaks online, please use a different one.",
            )

        ret_code, message = dbMethods.change_user_pass(user_model.username, password)

        if(ret_code != 0):
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


@router.get("/unlockAccount")
def unlock_account(username: str, password: str, authorize: AuthJWT = Depends()):
    try:
        authorize.jwt_required()
        raw = authorize.get_raw_jwt()

        if not raw:
            raise HTTPException(
                status_code=401,
                detail="Invalid token, please login again",
            )
        
        user_model = UserModel.parse_raw(raw["claims"])  # type: ignore
        
        if(user_model.access_level.value != AccessLevel.admin.value):
            raise HTTPException(
                status_code=401,
                detail="Only admins can access this API",
            )

        policy = dbMethods.get_policy()

        if not policy:
            raise
        
        if(not passwordMethods.validate_password(password, policy)):
            raise HTTPException(
                status_code=401,
                detail="Password does not meet current password requirements.",
            )

        if(passwordMethods.check_leaks_via_HIBP(password) > 0):
            raise HTTPException(
                status_code=401,
                detail="Password has appeared in leaks online, please use a different one.",
            )

        ret_code, message = dbMethods.unlock_account(username, password)

        if(ret_code != 0):
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
    