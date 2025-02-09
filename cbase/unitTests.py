import time
import unittest

import requests
from fastapi import HTTPException
from models.enums import AccessLevel
from models.policyModel import PolicyModel
from models.userModel import UserModel
from routers import password as passwordMethod
from routers import policy as policyMethod
from src import dbMethods

baseurl = "http://127.0.0.1:8000"

username = "rckyasd"
password = "8presG"

invusername = "rcasdakyasd"
invpassword = "asdad"

validCred = {
    "username": "rckyasd",
    "password": "8presG",
}

invalidCred = {
    "username": "rcasdakyasd",
    "password": "asdad",
}


class TestDB(unittest.TestCase):
    ### Test an unsecure password for leaks
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

    ### Test a secure password for leaks
    def test_online_password_checker_service_with_secure_password(self):
        checker_response =  passwordMethod.check_password_leak(
            'CapNoSym@021'
        )
        
        leak_count = checker_response["leak_count"]
        self.assertNotEqual(leak_count, None, "Leak count null")

        self.assertEqual(
            leak_count,
            0,
            "Manually verified secure password recognised as leaked",
        )

    ### Test to create a new user
    def test_create_user(self):
        returnCode, returnMessage = dbMethods.add_user(
            username=username, password=password,
        )

        self.assertEqual(returnCode, 0, "Expected error code 0, indicating that nothing went wrong, but did not recieve 0.")

        # print(returnMessage)

    ### Test to create a the same user again
    def test_create_user_again(self):
        returnCode, returnMessage = dbMethods.add_user(
            username=username, password=password,
        )

        self.assertNotEqual(returnCode, 0, "Did not expect error code 0, which indicats that nothing went wrong.")

        # print(returnMessage)

    ### Test to log in with correct username and password
    def test_user_login(self):
        addResult = dbMethods.user_login(username=username, password=password)

        self.assertNotEqual(addResult, None, 'Expected to receive new user\'s UserModel')
        self.assertIsInstance(addResult, UserModel, "Expected the result to be of type UserModel")

        # print(addResult)

    ### Test to log in with incorrect username and password
    def test_invalid_user_login(self):
        addResult = dbMethods.user_login(username=invusername, password=invpassword)

        self.assertEqual(addResult, None, 'Expected to receive None, but received a UserModel for a non-existent user')
        self.assertNotIsInstance(addResult, UserModel, "Did not expect the result to be of type UserModel")

        # print(addResult)

    ### Test adding a valid policy to the db
    def test_adding_policy(self):
        policyAddResponse = policyMethod.set_policy(
            min_upper_case_letters=1,
            min_lower_case_letters=1,
            min_digits=1,
            min_symbols=1,
            min_length=8,
            allowed_symbols='!@#$%&_+',
        )
        
        self.assertNotIsInstance(policyAddResponse, HTTPException, 'Received an exception instead of a success message')
        message = policyAddResponse['message'] # type: ignore
        self.assertEqual(message, 'Policy Updated')

        # print(message)


    ### Test adding a policy with invalid arguments to the db
    def test_adding_invalid_policy(self):
        policyAddResponse = policyMethod.set_policy(
            min_upper_case_letters=1,
            min_lower_case_letters=1,
            min_digits=None, # type: ignore
            min_symbols=1,
            min_length=8,
            allowed_symbols='!@#$%&_+',
        )
        
        self.assertIsInstance(policyAddResponse, HTTPException, 'Expected an HTTPException due to missing parameters, but did not receive it.')


    ### Fetch the latest policy from the DB
    def test_getting_policy(self):
        policyAddResponse = policyMethod.get_policy()

        serialData = policyAddResponse['policy']
        self.assertNotEqual(serialData, None, "Did not recieve serialized policy from get_policy method")

        policy = PolicyModel.parse_raw(serialData)
        self.assertIsInstance(policy, PolicyModel, "Could not deserialize data into a PolicyModel object")

        # print(policy)


    ### Generate passwords as per the latest policy (policy is stored in / fetched from the db)
    def test_generatePasswords(self):
        batch = 5

        passwordGenResponse = passwordMethod.generate_passwords(
            batch_size=batch, 
        )

        self.assertIsInstance(passwordGenResponse['passwords'], list, "Did not receive the passwords in a list with object key 'passwords'",)
        self.assertEqual(len(passwordGenResponse['passwords']), batch, "Did not receive the exact number of passwords as the batch size.",)

        # print(passwordGenResponse)

    # def checkIfMatchesPolicy(self) : TODO

    # def updatePassword(self) : TODO
    # temp -> normal

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

    def request_login(self, creds=validCred):
        return requests.post(baseurl + "/login", json=creds)

    def request_fresh_login(self, creds=validCred):
        return requests.post(baseurl + "/fresh-login", json=creds)

    def test_valid_login(self):
        loginResponse = self.request_login()
        self.assertEqual(loginResponse.status_code, 200, "Valid login failed")

        access_token = loginResponse.json()["access_token"]
        self.assertNotEqual(access_token, None, "Access token null")

        refresh_token = loginResponse.json()["refresh_token"]
        self.assertNotEqual(refresh_token, None, "Refresh token null")

    def test_invalid_login(self):
        loginResponse = self.request_login(invalidCred)
        self.assertNotEqual(loginResponse.status_code, 200, "Invalid login passed")

        with self.assertRaises(
            KeyError, msg="Refresh token received when not supposed to"
        ):
            loginResponse.json()["access_token"]

        with self.assertRaises(
            KeyError, msg="Refresh token received when not supposed to"
        ):
            loginResponse.json()["refresh_token"]

    def test_valid_fresh_login(self):
        loginResponse = self.request_fresh_login()
        self.assertEqual(loginResponse.status_code, 200, "Valid login failed")

        access_token = loginResponse.json()["access_token"]
        self.assertNotEqual(access_token, None, "Access token null")

        with self.assertRaises(
            KeyError, msg="Refresh token received when not supposed to"
        ):
            loginResponse.json()["refresh_token"]

    def test_invalid_fresh_login(self):
        loginResponse = self.request_fresh_login(invalidCred)
        self.assertNotEqual(loginResponse.status_code, 200, "Invalid login passed")

        with self.assertRaises(
            KeyError, msg="Refresh token received when not supposed to"
        ):
            loginResponse.json()["access_token"]

        with self.assertRaises(
            KeyError, msg="Refresh token received when not supposed to"
        ):
            loginResponse.json()["refresh_token"]

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

    def test_online_password_checker_service_with_secure_password_API(self):
        loginResponse = self.request_login()
        self.assertEqual(loginResponse.status_code, 200, "Valid login failed")

        access_token = loginResponse.json()["access_token"]
        self.assertNotEqual(access_token, None, "Access token null")

        refresh_token = loginResponse.json()["refresh_token"]
        self.assertNotEqual(refresh_token, None, "Refresh token null")

        checker_response = requests.get(
            baseurl + "/check-if-password-leaked",
            params={
                "password": "CapNoSym@021",
            },
            headers={
                "Authorization": "Bearer " + access_token,
            },
        )

        leak_count = checker_response.json()["leak_count"]
        self.assertNotEqual(leak_count, None, "Leak count null")

        self.assertEqual(
            leak_count,
            0,
            "Manually verified secure password recognised as leaked",
        )

    def test_fresh_api_with_fresh_token(self):
        loginResponse = self.request_fresh_login()
        self.assertEqual(loginResponse.status_code, 200, "Valid login failed")

        access_token = loginResponse.json()["access_token"]
        self.assertNotEqual(access_token, None, "Access token null")

        with self.assertRaises(
            KeyError, msg="Refresh token received when not supposed to"
        ):
            loginResponse.json()["refresh_token"]

        protectedFreshResponse = self.get_request(access_token, "/protected-fresh")
        self.assertEqual(
            protectedFreshResponse.status_code,
            200,
            "Failed to access protected fresh endpoint with valid fresh token",
        )

    def test_fresh_api_with_expired_fresh_token(self):
        loginResponse = self.request_fresh_login()
        self.assertEqual(loginResponse.status_code, 200, "Valid login failed")

        access_token = loginResponse.json()["access_token"]
        self.assertNotEqual(access_token, None, "Access token null")

        with self.assertRaises(
            KeyError, msg="Refresh token received when not supposed to"
        ):
            loginResponse.json()["refresh_token"]

        # For faster testing purposes, the expiry has been set to 9 seconds
        time.sleep(10)  # Expire the refresh token

        protectedFreshResponse = self.get_request(access_token, "/protected-fresh")
        self.assertNotEqual(
            protectedFreshResponse.status_code,
            200,
            "Able to access protected fresh endpoint with expired fresh token",
        )

    def test_fresh_api_with_deleted_fresh_token(self):
        loginResponse = self.request_fresh_login()
        self.assertEqual(loginResponse.status_code, 200, "Valid login failed")

        access_token = loginResponse.json()["access_token"]
        self.assertNotEqual(access_token, None, "Access token null")

        with self.assertRaises(
            KeyError, msg="Refresh token received when not supposed to"
        ):
            loginResponse.json()["refresh_token"]

        logoutResponse = self.post_request(access_token, "/logout")
        self.assertEqual(logoutResponse.status_code, 200, "Logout failed")

        protectedFreshResponse = self.get_request(access_token, "/protected-fresh")
        self.assertNotEqual(
            protectedFreshResponse.status_code,
            200,
            "Able to access protected fresh endpoint with deleted fresh token",
        )

    def test_api_with_valid_token(self):
        loginResponse = self.request_login()
        self.assertEqual(loginResponse.status_code, 200, "Valid login failed")

        access_token = loginResponse.json()["access_token"]
        self.assertNotEqual(access_token, None, "Access token null")

        refresh_token = loginResponse.json()["refresh_token"]
        self.assertNotEqual(refresh_token, None, "Refresh token null")

        protectedResponse = self.get_request(access_token, "/protected")
        self.assertEqual(
            protectedResponse.status_code,
            200,
            "Failed to access protected endpoint with valid token",
        )

    def test_api_with_expired_token(self):
        loginResponse = self.request_login()
        self.assertEqual(loginResponse.status_code, 200, "Valid login failed")

        access_token = loginResponse.json()["access_token"]
        self.assertNotEqual(access_token, None, "Access token null")

        refresh_token = loginResponse.json()["refresh_token"]
        self.assertNotEqual(refresh_token, None, "Refresh token null")

        # For faster testing purposes, the expiry has been set to 3 seconds
        time.sleep(5)  # Expire the access token

        protectedResponse = self.get_request(access_token, "/protected")
        self.assertNotEqual(
            protectedResponse.status_code,
            200,
            "Accessed protected endpoint with expired token",
        )

    def test_api_with_deleted_token(self):
        loginResponse = self.request_login()
        self.assertEqual(loginResponse.status_code, 200, "Valid login failed")

        access_token = loginResponse.json()["access_token"]
        self.assertNotEqual(access_token, None, "Access token null")

        refresh_token = loginResponse.json()["refresh_token"]
        self.assertNotEqual(refresh_token, None, "Refresh token null")

        logoutResponse = self.post_request(access_token, "/logout")
        self.assertEqual(logoutResponse.status_code, 200, "Logout failed")

        protectedResponse = self.get_request(access_token, "/protected")
        self.assertNotEqual(
            protectedResponse.status_code,
            200,
            "Accessed protected endpoint with expired token",
        )

    def test_getting_new_access_token_with_refresh_token(self):
        loginResponse = self.request_login()
        self.assertEqual(loginResponse.status_code, 200, "Valid login failed")

        access_token = loginResponse.json()["access_token"]
        self.assertNotEqual(access_token, None, "Access token null")

        refresh_token = loginResponse.json()["refresh_token"]
        self.assertNotEqual(refresh_token, None, "Refresh token null")

        # For faster testing purposes, the expiry has been set to 3 seconds
        time.sleep(5)  # Expire the access token

        protectedResponse = self.get_request(access_token, "/protected")
        self.assertNotEqual(
            protectedResponse.status_code,
            200,
            "Accessed protected endpoint with expired token",
        )

        refreshResponse = self.post_request(refresh_token, "/refresh")
        self.assertEqual(
            refreshResponse.status_code,
            200,
            "Failed to refresh token with valid refresh token",
        )

        new_access_token = refreshResponse.json()["access_token"]
        self.assertNotEqual(new_access_token, None, "Access token null")

        new_refresh_token = refreshResponse.json()["refresh_token"]
        self.assertNotEqual(new_refresh_token, None, "Refresh token null")

        protectedResponse = self.get_request(new_access_token, "/protected")
        self.assertEqual(
            protectedResponse.status_code,
            200,
            "Failed to access protected endpoint with refreshed token",
        )

    def test_getting_new_access_token_with_expired_refresh_token(self):
        loginResponse = self.request_login()
        self.assertEqual(loginResponse.status_code, 200, "Valid login failed")

        access_token = loginResponse.json()["access_token"]
        self.assertNotEqual(access_token, None, "Access token null")

        refresh_token = loginResponse.json()["refresh_token"]
        self.assertNotEqual(refresh_token, None, "Refresh token null")

        # For faster testing purposes, the expiry has been set to 3 seconds
        time.sleep(5)  # Expire the access token

        protectedResponse = self.get_request(access_token, "/protected")
        self.assertNotEqual(
            protectedResponse.status_code,
            200,
            "Accessed protected endpoint with expired token",
        )

        # For faster testing purposes, the expiry has been set to 9 seconds
        time.sleep(10)  # Expire the refresh token

        refreshResponse = self.post_request(refresh_token, "/refresh")
        self.assertNotEqual(
            refreshResponse.status_code,
            200,
            "Able to get new access token with invalid refresh token",
        )

        with self.assertRaises(
            KeyError, msg="Access token received when not supposed to"
        ):
            access_token = refreshResponse.json()["access_token"]

            protectedResponse = self.get_request(access_token, "/protected")
            self.assertEqual(
                protectedResponse.status_code,
                200,
                "Able to access protected endpoint",
            )

    def test_getting_new_access_token_with_deleted_access_and_refresh_token(self):
        loginResponse = self.request_login()
        self.assertEqual(loginResponse.status_code, 200, "Valid login failed")

        access_token = loginResponse.json()["access_token"]
        self.assertNotEqual(access_token, None, "Access token null")

        refresh_token = loginResponse.json()["refresh_token"]
        self.assertNotEqual(refresh_token, None, "Refresh token null")

        logoutResponse = self.post_request(access_token, "/logout")
        self.assertEqual(logoutResponse.status_code, 200, "Logout failed")

        protectedResponse = self.get_request(access_token, "/protected")
        self.assertNotEqual(
            protectedResponse.status_code,
            200,
            "Accessed protected endpoint with expired token",
        )

        refreshResponse = self.post_request(refresh_token, "/refresh")
        self.assertNotEqual(
            refreshResponse.status_code,
            200,
            "Failed to refresh token with valid refresh token",
        )

        with self.assertRaises(KeyError, msg="Access token found when not supposed to"):
            access_token = refreshResponse.json()["access_token"]

            protectedResponse = self.get_request(access_token, "/protected")
            self.assertEqual(
                protectedResponse.status_code,
                200,
                "Able to access protected endpoint",
            )


if __name__ == "__main__":
    unittest.main()
