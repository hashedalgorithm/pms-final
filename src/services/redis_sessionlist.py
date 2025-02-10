from typing import Union
import redis
from decouple import config

redis_host = str(config("REDIS_HOSTNAME", cast=str))
redis_port = int(config("REDIS_PORT", cast=int))
redis_db = int(config("REDIS_DB", cast=int))
access_token_expiry = int(config("JWT_ACCESS_T_EXPIRES", cast=int))
refresh_token_expiry = int(config("JWT_REFRESH_T_EXPIRES", cast=int))

redis_client = redis.Redis(
    host=redis_host,
    port=redis_port,
    db=redis_db,
)

def add_session_tokens(access_jti: str, refresh_jti: Union[str, None] = None):
    if refresh_jti is None:
        return redis_client.set(access_jti, 0, ex=access_token_expiry)
    else:
        set_access = redis_client.set(access_jti, refresh_jti, ex=access_token_expiry)
        set_refresh = redis_client.set(refresh_jti, access_jti, ex=refresh_token_expiry)
        return set_access and set_refresh

def delete_session_tokens(jti: str):
    paired_jti = redis_client.get(jti)
    delete_token = redis_client.delete(jti)
    delete_paired_token = 1

    if paired_jti:
        delete_paired_token = redis_client.delete(paired_jti)

    return delete_token and delete_paired_token

def check_if_session_token_exists(token_jti: str):
    return redis_client.exists(token_jti) != 0
