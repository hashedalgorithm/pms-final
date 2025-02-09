from enum import Enum


class AccountStatus(Enum):
    temp = "temp"
    normal = "normal"
    locked = "locked"
    disabled = "disabled"


class AccessLevel(Enum):
    user = "user"
    admin = "admin"
