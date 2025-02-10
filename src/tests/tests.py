import time
import unittest
import requests
from fastapi import HTTPException
from models.enums import AccessLevel
from models.policyModel import PolicyModel
from models.userModel import UserModel
from routers import password as password_router
from routers import policy as policy_router
import services.dbMethods as dbMethods

base_url = "http://127.0.0.1:8000"

class TestDatabase(unittest.TestCase):
    def test_password_leak_check(self):
        response = password_router.check_password_leak('password')
        leak_count = response["leak_count"]
        self.assertIsNotNone(leak_count, "Leak count is None")
        self.assertNotEqual(leak_count, 0, "Common password not recognized as leaked")

    def test_add_policy(self):
        response = policy_router.set_policy(
            min_upper_case_letters=1,
            min_lower_case_letters=1,
            min_digits=1,
            min_symbols=1,
            min_length=8,
        )
        self.assertNotIsInstance(response, HTTPException, 'Expected success, got exception')
        message = response['message']  # type: ignore
        self.assertEqual(message, 'Policy Updated')

    def test_add_invalid_policy(self):
        response = policy_router.set_policy(
            min_upper_case_letters=1,
            min_lower_case_letters=1,
            min_digits=None,  # type: ignore
            min_symbols=1,
            min_length=8,
        )
        self.assertIsInstance(response, HTTPException, 'Expected HTTPException due to missing parameters')

    def test_get_policy(self):
        response = policy_router.get_policy()
        serialized_data = response['policy']
        self.assertIsNotNone(serialized_data, "No serialized policy received")
        policy = PolicyModel.parse_raw(serialized_data)
        self.assertIsInstance(policy, PolicyModel, "Failed to deserialize policy")

    def test_generate_passwords(self):
        batch_size = 5
        response = password_router.generate_passwords()
        self.assertIsInstance(response['passwords'], list, "Passwords not received in a list")
        self.assertEqual(len(response['passwords']), batch_size, "Incorrect number of passwords generated")

    def get_request(self, token: str, endpoint: str):
        return requests.get(
            base_url + endpoint,
            headers={"Authorization": "Bearer " + token},
        )

    def post_request(self, token: str, endpoint: str):
        return requests.post(
            base_url + endpoint,
            headers={"Authorization": "Bearer " + token},
        )

    def test_password_leak_check_api(self):
        login_response = self.request_login()
        self.assertEqual(login_response.status_code, 200, "Login failed")

        access_token = login_response.json()["access_token"]
        self.assertIsNotNone(access_token, "Access token is None")

        refresh_token = login_response.json()["refresh_token"]
        self.assertIsNotNone(refresh_token, "Refresh token is None")

        checker_response = requests.get(
            base_url + "/check-if-password-leaked",
            params={"password": "password"},
            headers={"Authorization": "Bearer " + access_token},
        )
        self.assertEqual(checker_response.status_code, 200, "Password leak check failed")
        leak_count = checker_response.json()["leak_count"]
        self.assertIsNotNone(leak_count, "Leak count is None")
        self.assertNotEqual(leak_count, 0, "Common password not recognized as leaked")

if __name__ == "__main__":
    unittest.main()
