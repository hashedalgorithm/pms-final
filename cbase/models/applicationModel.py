from uuid import UUID

from pydantic import BaseModel

class ApplicationModel(BaseModel):
    username: str
    password: str
    application_name: str
    