import queue
import re
import uuid
from typing import Tuple, Union

import bcrypt
from decouple import config
from models.applicationModel import ApplicationModel
from models.enums import AccessLevel
from models.policyModel import PolicyModel
from models.userModel import UserModel
import services.dbConn as dbConn

conn_queue = queue.Queue()
max_connections = int(config("MAX_DB_CONNECTIONS", cast=int, default=5))
salt = bytes(str(config("SALT", cast=str)), "utf-8")


def user_login(username: str, password: str) -> Union[UserModel, None]:
    try:
        username = re.sub(r"[^a-zA-Z0-9]", "", username)
        password = re.sub(r"[^a-zA-Z0-9]", "", password)

        pwd = password.encode("utf-8")

        hashed_password = bcrypt.hashpw(pwd, salt)

        conn, cursor = dbConn.get_connection()
        cursor.execute(
            f"SELECT * FROM nextgensec_mpass WHERE username = %s", (username))
        dbConn.release_connection(conn, cursor)

        for row in cursor:
            if row[3] == hashed_password.decode():
                return UserModel(
                    user_uuid=uuid.UUID(row[1]),
                    username=str(row[2]),
                    access_level=AccessLevel(value=row[5]),
                )
        return None

    except:
        return None


def add_application_password_pair(
    username: str, application_name: str, password: str,
) -> Tuple[int, str]:
    try:
        username = re.sub(r"[^a-zA-Z0-9]", "", username)

        conn, cursor = dbConn.get_connection()

        affected = cursor.execute(
            "INSERT INTO `pms`(`username`, `password`, `application_name`) VALUES (%s,%s,%s)", (
                username, password, application_name)
        )

        conn.commit()
        dbConn.release_connection(conn, cursor)

        if affected == 1:
            return 0, "Application password set successfully."
        else:
            return 1, "An error occured when setting application password."

    except:
        return 1, "An error occured when setting application password."


def update_application_password(
    username: str, application_name: str, password: str,
) -> Tuple[int, str]:
    try:
        username = re.sub(r"[^a-zA-Z0-9]", "", username)

        conn, cursor = dbConn.get_connection()

        affected = cursor.execute(
            "UPDATE `pms` SET `password`=%s WHERE `username`=%s AND `application_name`=%s", (
                password, username, application_name)
        )

        conn.commit()
        dbConn.release_connection(conn, cursor)

        if affected == 1:
            return 0, "Application password updated successfully."
        else:
            return 1, "An error occured when updating the application password."

    except:
        return 1, "An error occured when updating the application password."


def get_all_application_password_pairs(
    username: str,
) -> Tuple[Union[list[ApplicationModel], None], str]:
    try:
        username = re.sub(r"[^a-zA-Z0-9]", "", username)

        conn, cursor = dbConn.get_connection()
        affected = cursor.execute(
            "SELECT * FROM pms WHERE username=%s",
            (username),
        )

        conn.commit()
        dbConn.release_connection(conn, cursor)

        passwords: list[ApplicationModel] = []

        for row in cursor:
            passwords.append(
                ApplicationModel(
                    username=str(row[1]),
                    password=str(row[2]),
                    application_name=str(row[3])
                ),
            )

        if affected > 0:
            return passwords, "Password fetched successfully."
        else:
            return None, "An error occured when fetching the passwords."

    except:
        return None, "An error occured when fetching the passwords."


def change_user_pass(
    username: str, password: str,
) -> Tuple[int, str]:
    try:
        username = re.sub(r"[^a-zA-Z0-9]", "", username)
        password = re.sub(r"[^a-zA-Z0-9]", "", password)

        pwd = password.encode("utf-8")

        hashed_password = bcrypt.hashpw(pwd, salt)

        conn, cursor = dbConn.get_connection()
        affected = cursor.execute(
            "UPDATE nextgensec_mpass SET password=%s WHERE username=%s",
            (hashed_password, 'normal', username),
        )

        conn.commit()
        dbConn.release_connection(conn, cursor)

        if affected == 1:
            return 0, "Password updated successfully."
        else:
            return 1, "An error occured when updating the password."

    except:
        return 1, "An error occured when updating the password."


def add_user(
    username: str, password: str, access_level: AccessLevel = AccessLevel.admin
) -> Tuple[int, str]:
    try:
        username = re.sub(r"[^a-zA-Z0-9]", "", username)
        password = re.sub(r"[^a-zA-Z0-9]", "", password)

        pwd = password.encode("utf-8")

        hashed_password = bcrypt.hashpw(pwd, salt)

        conn, cursor = dbConn.get_connection()
        affected = cursor.execute(
            "INSERT INTO nextgensec_mpass(user_uuid, username, password, access_level) VALUES(%s,%s,%s,%s)",
            (uuid.uuid4(), username, hashed_password.decode(), access_level.value),
        )

        conn.commit()
        dbConn.release_connection(conn, cursor)

        if affected == 1:
            return 0, "User added successfully."
        else:
            return 1, "An error occured when adding a new user."

    except:
        return 1, "An error occured when adding a new user."


def add_policy(policyModel: PolicyModel) -> bool:
    try:
        conn, cursor = dbConn.get_connection()
        affected = cursor.execute(
            "INSERT INTO `nextgensec_policy`(`policy_json`) VALUES (%s)", (policyModel.json(
            ))
        )

        conn.commit()
        dbConn.release_connection(conn, cursor)

        if affected == 1:
            return True
        else:
            return False

    except:
        return False


def get_policy() -> Union[PolicyModel, None]:
    try:
        conn, cursor = dbConn.get_connection()
        cursor.execute(
            "SELECT `policy_json` FROM `nextgensec_policy` ORDER BY `created_at` DESC LIMIT 1"
        )

        conn.commit()
        dbConn.release_connection(conn, cursor)
        for row in cursor:
            return PolicyModel.parse_raw(row[0])
        else:
            return None

    except:
        return None
