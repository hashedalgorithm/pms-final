import hashlib
import time
from random import randint, shuffle
from typing import Union
import requests
from fastapi import HTTPException
from models.policyModel import PolicyModel

def check_leaks_via_HIBP(password: str) -> int:
    hibp_url = "https://api.pwnedpasswords.com/range/"
    hashed_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = hashed_password[:5]
    suffix = hashed_password[5:]

    response = requests.get(hibp_url + prefix)
    leak_count = 0

    if response.status_code == 200:
        for line in response.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                leak_count = int(count)
    else:
        raise HTTPException(status_code=response.status_code, detail="Error with password leak checker service")

    return leak_count

def validate_password(password: str, policy: PolicyModel) -> bool:
    if len(password) < policy.rules.min_length:
        return False

    if sum(1 for char in password if char.isupper()) < policy.rules.min_upper_case_letters:
        return False

    if sum(1 for char in password if char.islower()) < policy.rules.min_lower_case_letters:
        return False

    if sum(1 for char in password if char.isdigit()) < policy.rules.min_digits:
        return False

    if sum(1 for char in password if not char.isalnum()) < policy.rules.min_symbols:
        return False

    return True

def generate_passwords(batch_size: int, policy: PolicyModel) -> Union[list[str], None]:
    generators = [__get_upper_alpha, __get_alpha, __get_number, __get_symbol]
    passwords = []

    for _ in range(batch_size):
        generated_password = ""

        for _ in range(policy.rules.min_upper_case_letters):
            generated_password += __get_upper_alpha()

        for _ in range(policy.rules.min_lower_case_letters):
            generated_password += __get_alpha()

        for _ in range(policy.rules.min_digits):
            generated_password += __get_number()

        for _ in range(policy.rules.min_symbols):
            generated_password += __get_symbol()

        while len(generated_password) < policy.rules.min_length:
            index = randint(0, len(generators) - 1)
            generated_password += generators[index]()

        password_chars = list(generated_password)
        shuffle(password_chars)
        generated_password = "".join(password_chars)
        passwords.append(generated_password)

    return passwords

def __get_alpha() -> str:
    alpha_map = "abcdefghijklmnopqrstuvwxyz"
    return alpha_map[__get_random_index(len(alpha_map))]

def __get_upper_alpha() -> str:
    upper_alpha_map = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return upper_alpha_map[__get_random_index(len(upper_alpha_map))]

def __get_number() -> str:
    number_map = "0123456789"
    return number_map[__get_random_index(len(number_map))]

def __get_symbol() -> str:
    symbol_map = "!@#$%^&*()_+-={}[];:<>,./?ß!"
    return symbol_map[__get_random_index(len(symbol_map))]

def __get_random_index(range: int) -> int:
    now = str(time.time_ns())
    random_number = int(now[11:13])
    time.sleep(0.0000001)
    return random_number % range
