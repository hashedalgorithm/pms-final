from typing import Union
import redis
from decouple import config

r_host = str(config("REDIS_HOSTNAME", cast=str))
r_port = int(config("REDIS_PORT", cast=int))
r_db = int(config("REDIS_DB", cast=int))
access_expiry = int(config("JWT_ACCESS_T_EXPIRES", cast=int))
refresh_expiry = int(config("JWT_REFRESH_T_EXPIRES", cast=int))

r = redis.Redis(
    host=r_host,
    port=r_port,
    db=r_db,
)


def add_session_tokens(access_jti: str, refresh_jti: Union[str, None] = None):
    if refresh_jti == None:
        return r.set(access_jti, 0, ex=access_expiry)
    else:
        seta = r.set(access_jti, refresh_jti, ex=access_expiry)
        setr = r.set(refresh_jti, access_jti, ex=refresh_expiry)
        return seta == True and setr == True


def delete_session_tokens(jti: str):
    other_jti = r.get(jti)
    token_delete_response = r.delete(jti)
    paired_token_delete_response = 1

    if other_jti:
        paired_token_delete_response = r.delete(other_jti)

    return token_delete_response != 0 and paired_token_delete_response != 0


def check_if_session_token_exists(token_jti: str):
    return r.exists(token_jti) != 0
