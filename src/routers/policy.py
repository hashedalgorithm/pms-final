import uuid
from datetime import datetime, timedelta
from time import time

from fastapi import APIRouter, Depends, HTTPException
from fastapi_jwt_auth import AuthJWT
from main import global_scheduler
from models.enums import AccessLevel
from models.policyModel import CreatedBy, PolicyModel, Rules
from models.userModel import UserModel
from src import dbMethods

router = APIRouter(
    tags=["policy"],
)


@router.post("/setPolicy")
def set_policy(
    min_upper_case_letters: int = 1,
    min_lower_case_letters: int = 1,
    min_digits: int = 1,
    min_symbols: int = 1,
    min_length: int = 8,
    allowed_symbols: str = "!@#$%&_+",
    authorize: AuthJWT = Depends(),
):
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

        if (
            min_upper_case_letters == None
            or min_lower_case_letters == None
            or min_digits == None
            or min_symbols == None
            or min_length == None
            or allowed_symbols == None
        ):
            return HTTPException(
                status_code=500,
                detail="Missing parameters",
            )

        # TODO: Add other potential errors and return corresponding error messages.
        # Create a PolicyModel from the API arguments
        policy_model = PolicyModel(
            id=uuid.uuid4(),
            allowed_symbols=allowed_symbols,
            created_at=datetime.utcnow().timestamp(),
            created_by=CreatedBy(admin_id=uuid.uuid4()),
            rules=Rules(
                min_upper_case_letters=min_upper_case_letters,
                min_lower_case_letters=min_lower_case_letters,
                min_digits=min_digits,
                min_symbols=min_symbols,
                min_length=min_length,
            ),
        )

        # Store the created PolicyModel via DB methods
        result = dbMethods.add_policy(policy_model)

        if result:
            _ = dbMethods.set_all_accounts_as_temp()
            global_scheduler.add_job(dbMethods.lock_all_temp_accounts, 'date', run_date=datetime.now() + timedelta(hours=24))
            global_scheduler.start()
            _ = dbMethods.update_all_application_passwords(policy_model)
            return {"message": "Policy Updated",}
        else:
            raise
    except:
        raise HTTPException(
            status_code=500,
            detail="Something went wrong when fetching the password policy",
        )


@router.get("/getPolicy")
def get_policy(
    authorize: AuthJWT = Depends(),
):
    try:
        authorize.jwt_required()

        policy = dbMethods.get_policy()

        if policy:
            return {
                "policy": policy.json(),
            }

        raise
    except:
        raise HTTPException(
            status_code=500,
            detail="Something went wrong when fetching the password policy",
        )
