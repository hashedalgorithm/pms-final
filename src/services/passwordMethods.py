from typing import Tuple
import re
import random
import hashlib
import time
from random import randint, shuffle
from typing import Union

import requests
from fastapi import HTTPException
from models.policyModel import PolicyModel


allowedLowerCaseCharacters = "abcdefghijklmnopqrstuvwxyz"
allowedUpperCaseCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
allowedNumbers = "1234567890"
allowedSpecialCharacters = "!@#$%^&*()_+-={}[];:<>,./?ß!"
iterations = 1000
keyLength = 64
randomSaltLength = 20


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


def generatePassword(
    length: int,
    upperCaseCharacters: int,
    numbers: int,
    specialCharacters: int
) -> str:
    firstPasswordDraft = ""
    for _ in range(length):
        randomAllowedCharacterOrNumber = generateRandomAllowedCharacterOrNumber()
        firstPasswordDraft += randomAllowedCharacterOrNumber

    patchedPassword = firstPasswordDraft
    while True:
        isLowerCaseCharactersValid, isNumbersValid, isSpecialCharactersValid, isUpperCaseCharactersValid = checkPasswordPolicy(
            patchedPassword,
            upperCaseCharacters,
            numbers,
            specialCharacters
        )

        if (
            isLowerCaseCharactersValid and
            isNumbersValid and
            isSpecialCharactersValid and
            isUpperCaseCharactersValid
        ):
            break

        if not isLowerCaseCharactersValid:
            patchedPassword = patchCharacters(
                patchedPassword,
                "lower",
                findRequiredLengthToSatisfyPasswordPolicy(
                    patchedPassword, "lower", 1)
            )
        if not isUpperCaseCharactersValid:
            patchedPassword = patchCharacters(
                patchedPassword,
                "upper",
                findRequiredLengthToSatisfyPasswordPolicy(
                    patchedPassword, "upper", upperCaseCharacters)
            )
        if not isNumbersValid:
            patchedPassword = patchCharacters(
                patchedPassword,
                "numbers",
                findRequiredLengthToSatisfyPasswordPolicy(
                    patchedPassword, "numbers", numbers)
            )
        if not isSpecialCharactersValid:
            patchedPassword = patchCharacters(
                patchedPassword,
                "special",
                findRequiredLengthToSatisfyPasswordPolicy(
                    patchedPassword, "special", specialCharacters)
            )

    return patchedPassword


def findRequiredLengthToSatisfyPasswordPolicy(
    password: str,
    characterClass: str,
    requiredLength: int
) -> int:
    if characterClass == "lower":
        matches = re.findall(r'[a-z]', password)
        return abs(len(matches) - requiredLength)
    elif characterClass == "upper":
        matches = re.findall(r'[A-Z]', password)
        return abs(len(matches) - requiredLength)
    elif characterClass == "numbers":
        matches = re.findall(r'\d', password)
        return abs(len(matches) - requiredLength)
    elif characterClass == "special":
        specialCharRegex = r'[!@#$%^&*()_+\-={}\[\];:<>,./?ß]'
        matches = re.findall(specialCharRegex, password)
        return abs(len(matches) - requiredLength)
    else:
        return 0


def patchCharacters(
    password: str,
    characterClass: str,
    requiredLength: int
) -> str:
    if requiredLength <= 0 or requiredLength > len(password):
        return password

    allowedCharacters = getAllowedCharactersBasedOnCharacterClass(
        characterClass)

    patchedPassword = password
    for _ in range(requiredLength):
        randomIndex = random.randint(0, len(password) - 1)
        randomCharacterIndex = random.randint(0, len(allowedCharacters) - 1)
        randomCharacter = allowedCharacters[randomCharacterIndex]

        patchedPassword = (
            patchedPassword[:randomIndex] +
            randomCharacter +
            patchedPassword[randomIndex + 1:]
        )

    return patchedPassword


def getAllowedCharactersBasedOnCharacterClass(characterClass: str) -> str:
    if characterClass == "lower":
        return allowedLowerCaseCharacters
    elif characterClass == "numbers":
        return allowedNumbers
    elif characterClass == "upper":
        return allowedUpperCaseCharacters
    elif characterClass == "special":
        return allowedSpecialCharacters
    else:
        return allowedLowerCaseCharacters


def generateRandomAllowedCharacterOrNumber() -> str:
    allowedCharacters = (
        allowedLowerCaseCharacters +
        allowedUpperCaseCharacters +
        allowedNumbers +
        allowedSpecialCharacters
    )

    index = random.randint(0, len(allowedCharacters) - 1)
    return allowedCharacters[index]


def checkPasswordPolicy(
    password: str,
    upperCaseCharacters: int,
    numbers: int,
    specialCharacters: int
) -> Tuple[bool, bool, bool, bool]:
    isNumbersValid = validatePasswordNumbers(password, numbers)
    isSpecialCharactersValid = validatePasswordSpecialCharacters(
        password, specialCharacters)
    isLowerCaseCharactersValid = validatePasswordLowerCaseCharacters(
        password, 1)
    isUpperCaseCharactersValid = validatePasswordUpperCaseCharacters(
        password, upperCaseCharacters)

    return (
        isNumbersValid,
        isLowerCaseCharactersValid,
        isUpperCaseCharactersValid,
        isSpecialCharactersValid
    )


def validatePasswordUpperCaseCharacters(password: str, length: int) -> bool:
    regex = re.compile(f"([A-Z].*?){{{length},}}")
    return bool(regex.search(password))


def validatePasswordNumbers(password: str, length: int) -> bool:
    regex = re.compile(f"(\\d.*?){{{length},}}")
    return bool(regex.search(password))


def validatePasswordLowerCaseCharacters(password: str, length: int) -> bool:
    regex = re.compile(f"([a-z].*?){{{length},}}")
    return bool(regex.search(password))


def validatePasswordSpecialCharacters(password: str, length: int) -> bool:
    allowedSpecialCharactersInRegixUnderstandableFormat = r"!@#\$%\^&\*\$_\+\-={}\[\];:<>,\./\?ß"
    regex = re.compile(
        f"([{allowedSpecialCharactersInRegixUnderstandableFormat}].*?){{{length},}}")
    return bool(regex.search(password))
