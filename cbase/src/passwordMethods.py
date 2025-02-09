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
                detail="Something went wrong with the password leak checker service, please try again later.",
            )

    return leak_count

def validate_password(password: str, policy: PolicyModel) -> bool:
    if(len(password) < policy.rules.min_length):
        return False

    if(sum(1 for chr in password if chr.isupper()) < policy.rules.min_upper_case_letters):
        return False

    if(sum(1 for chr in password if chr.islower()) < policy.rules.min_lower_case_letters):
        return False

    if(sum(1 for chr in password if chr.isdigit()) < policy.rules.min_digits):
        return False
    
    min = sum(1 for chr in password if not chr.isalnum())
    if(min < policy.rules.min_symbols):
        return False

    symbol_only_pass = "".join(filter(str.isalnum, password))

    if(sum(1 for chr in symbol_only_pass if chr not in policy.allowed_symbols) < 0):
        return False

    return True


def generate_passwords(batch_size: int, policy: PolicyModel) -> Union[list[str], None]:
    generators = [
        __getUpperAlpha,
        __getAlpha,
        __getNumber,
        __getSymbol,
    ]

    passwords: list[str] = []

    for _ in range(batch_size):
        genPsk: str = ""

        for _ in range(policy.rules.min_upper_case_letters):
            genPsk += __getUpperAlpha()

        for _ in range(policy.rules.min_lower_case_letters):
            genPsk += __getAlpha()

        for _ in range(policy.rules.min_digits):
            genPsk += __getNumber()

        for _ in range(policy.rules.min_symbols):
            genPsk += __getSymbol(policy.allowed_symbols)

        while len(genPsk) < policy.rules.min_length:
            # TODO: Use UUID as the index generator?
            i = randint(0, len(generators)-1)
            genPsk += generators[i](policy.allowed_symbols)

        passchars = list(genPsk)
        shuffle(passchars)
        genPsk = "".join(passchars)
        passwords.append(genPsk)

    return passwords


def __getAlpha(*args) -> str:
    alphaMap = "abcdefghijklmnopqrstuvwxyz"
    return alphaMap[__getRandomIndex(len(alphaMap))]


def __getUpperAlpha(*args) -> str:

    capAlphaMap = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return capAlphaMap[__getRandomIndex(len(capAlphaMap))]


def __getNumber(*args) -> str:
    numberMap = "0123456789"
    return numberMap[__getRandomIndex(len(numberMap))]


def __getSymbol(symbolMap: str) -> str:
    return symbolMap[__getRandomIndex(len(symbolMap))]


def __getRandomIndex(range: int) -> int:
    now = str(time.time_ns())
    randomNumber = int(now[11:13])
    time.sleep(0.0000001)
    return randomNumber % range
