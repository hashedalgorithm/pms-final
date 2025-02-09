from uuid import UUID

from pydantic import BaseModel

from .enums import AccessLevel


class UserModel(BaseModel):
    user_uuid: UUID
    username: str
    access_level: AccessLevel


class LoginModel(BaseModel):
    username: str
    password: str
