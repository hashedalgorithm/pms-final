import time
import unittest

import requests
from fastapi import HTTPException
from models.enums import AccessLevel
from models.policyModel import PolicyModel
from models.userModel import UserModel
from routers import password as passwordMethod
from routers import policy as policyMethod
import services.dbMethods as dbMethods

baseurl = "http://127.0.0.1:8000"

username = "abcdef"
password = "L98nji"

invusername = "vbtyygh"
invpassword = "mjilk"

validCred = {
    "username": "abcdef",
    "password": "L98nji",
}

invalidCred = {
    "username": "vbtyygh",
    "password": "mjilk",
}


class TestDB(unittest.TestCase):
    # Test an unsecure password for leaks
    def test_online_password_checker_service(self):
        checker_response = passwordMethod.check_password_leak(
            'password'
        )

        leak_count = checker_response["leak_count"]
        self.assertNotEqual(leak_count, None, "Leak count null")

        self.assertNotEqual(
            leak_count,
            0,
            "Most common password not recognised as leaked",
        )

    # Test a secure password for leaks
    def test_online_password_checker_service_with_secure_password(self):
        checker_response = passwordMethod.check_password_leak(
            'CapNoSym@021'
        )

        leak_count = checker_response["leak_count"]
        self.assertNotEqual(leak_count, None, "Leak count null")

        self.assertEqual(
            leak_count,
            0,
            "Manually verified secure password recognised as leaked",
        )

    def test_generatePasswords(self):
        batch = 5

        passwordGenResponse = passwordMethod.generate_passwords()

        self.assertIsInstance(passwordGenResponse['passwords'], list,
                              "Did not receive the passwords in a list with object key 'passwords'",)
        self.assertEqual(len(passwordGenResponse['passwords']), batch,
                         "Did not receive the exact number of passwords as the batch size.",)

    def test_online_password_checker_service_API(self):
        loginResponse = self.request_login()
        self.assertEqual(loginResponse.status_code, 200, "Valid login failed")

        access_token = loginResponse.json()["access_token"]
        self.assertNotEqual(access_token, None, "Access token null")

        refresh_token = loginResponse.json()["refresh_token"]
        self.assertNotEqual(refresh_token, None, "Refresh token null")

        checker_response = requests.get(
            baseurl + "/check-if-password-leaked",
            params={
                "password": "password",
            },
            headers={
                "Authorization": "Bearer " + access_token,
            },
        )
        self.assertEqual(
            checker_response.status_code,
            200,
            "Failed to check if password has been leaked",
        )

        leak_count = checker_response.json()["leak_count"]
        self.assertNotEqual(leak_count, None, "Leak count null")

        self.assertNotEqual(
            leak_count,
            0,
            "Most common password not recognised as leaked",
        )


if _name_ == "_main_":
    unittest.main()
