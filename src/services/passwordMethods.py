import hashlib
import time
from random import randint, shuffle
from typing import Union

import requests
from fastapi import HTTPException
from models.policyModel import PolicyModel


def check_leaks_via_HIBP(password: str) -> int:
    hibp_url = "https://api.pwnedpasswords.com/range/"

    hashed_password = hashlib.sha1(
        password.encode("utf-8")).hexdigest().upper()
    prefix = hashed_password[:5]
    suffix = hashed_password[5:]

    response = requests.get(
        hibp_url + prefix,
    )

    leak_count = 0

    if response.status_code == 200:
        for line in response.text.splitlines():
            hashed_password, count = line.split(":")
            if hashed_password == suffix:
                leak_count = int(count)
    else:
        raise HTTPException(
            status_code=response.status_code,
            detail="Error - password leak checker service.",
        )

    return leak_count


def validate_password(password: str, policy: PolicyModel) -> bool:
    if (len(password) < policy.rules.min_length):
        return False

    if (sum(1 for chr in password if chr.isupper()) < policy.rules.min_upper_case_letters):
        return False

    if (sum(1 for chr in password if chr.islower()) < policy.rules.min_lower_case_letters):
        return False

    if (sum(1 for chr in password if chr.isdigit()) < policy.rules.min_digits):
        return False

    min = sum(1 for chr in password if not chr.isalnum())
    if (min < policy.rules.min_symbols):
        return False

    return True


def generate_passwords(batch_size: int, policy: PolicyModel) -> Union[list[str], None]:
    password = []

    password.append(random.choice(UPPER))
    password.append(random.choice(LOWER))
    password.append(random.choice(DIGITS))
    password.append(random.choice(SPECIAL_CHARACTERS))

    remaining_chars = UPPER + LOWER 
    for _ in range(PASSWORD_LENGTH - 4):
        password.append(random.choice(remaining_chars))

    # Shuffle to avoid same patterns
    random.shuffle(password)
    return ''.join(password)
