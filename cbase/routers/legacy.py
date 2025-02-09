from fastapi import APIRouter, Depends, HTTPException
from src import dbMethods

router = APIRouter(
    tags=["legacy"],
)


@router.get("/legacyAuth")
def legacy_auth(username: str, password: str, application_name: str):
    try:
        response = dbMethods.legacy_auth(username, password, application_name)

        if response:
            return {"legacy_auth": True}
    except:
        raise HTTPException(
            status_code=500,
            detail="Something went wrong when logging in to the legacy application. ",
        )
