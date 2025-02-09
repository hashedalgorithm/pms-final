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

    # Test adding a valid policy to the db
    def test_adding_policy(self):
        policyAddResponse = policyMethod.set_policy(
            min_upper_case_letters=1,
            min_lower_case_letters=1,
            min_digits=1,
            min_symbols=1,
            min_length=8,
        )

        self.assertNotIsInstance(policyAddResponse, HTTPException,
                                 'Received an exception instead of a success message')
        message = policyAddResponse['message']  # type: ignore
        self.assertEqual(message, 'Policy Updated')

        # print(message)

    # Test adding a policy with invalid arguments to the db
    def test_adding_invalid_policy(self):
        policyAddResponse = policyMethod.set_policy(
            min_upper_case_letters=1,
            min_lower_case_letters=1,
            min_digits=None,  # type: ignore
            min_symbols=1,
            min_length=8,
        )

        self.assertIsInstance(policyAddResponse, HTTPException,
                              'Expected an HTTPException due to missing parameters, but did not receive it.')

    # Fetch the latest policy from the DB

    def test_getting_policy(self):
        policyAddResponse = policyMethod.get_policy()

        serialData = policyAddResponse['policy']
        self.assertNotEqual(
            serialData, None, "Did not recieve serialized policy from get_policy method")

        policy = PolicyModel.parse_raw(serialData)
        self.assertIsInstance(
            policy, PolicyModel, "Could not deserialize data into a PolicyModel object")

    def get_request(self, token: str, endpoint: str):
        return requests.get(
            baseurl + endpoint,
            headers={
                "Authorization": "Bearer " + token,
            },
        )

    def post_request(self, token: str, endpoint: str):
        return requests.post(
            baseurl + endpoint,
            headers={
                "Authorization": "Bearer " + token,
            },
        )

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


if __name__ == "__main__":
    unittest.main()
