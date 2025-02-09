import unittest
from app.services import generatePassword, allowedSpecialCharacters


class TestPasswordService(unittest.TestCase):

    def test_generate_password(self, expected_length: int, expected_upper_case_count: int, expected_numbers_count: int, expected_special_char_count: int):
        result = generatePassword(expected_length, expected_upper_case_count,
                                  expected_numbers_count, expected_special_char_count)

        length = len(result)
        upper_case_count = sum(1 for char in result if char.isupper())
        numbers_count = sum(1 for char in result if char.isdigit())
        special_char_count = sum(
            1 for char in result if char in allowedSpecialCharacters)

        self.assertEqual(length, expected_length,
                         "Password length does not match.")
        self.assertEqual(upper_case_count, expected_upper_case_count,
                         "Number of uppercase characters does not match.")
        self.assertEqual(numbers_count, expected_numbers_count,
                         "Number of numeric characters does not match.")
        self.assertEqual(special_char_count, expected_special_char_count,
                         "Number of special characters does not match.")

    def test_length(self):
        expected_length = 4
        expected_upper_case_count = 1
        expected_numbers_count = 1
        expected_special_char_count = 1

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    def test_length_12(self):
        expected_length = 12
        expected_upper_case_count = 1
        expected_numbers_count = 1
        expected_special_char_count = 1

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    def test_length_0(self):
        expected_length = 0
        expected_upper_case_count = 1
        expected_numbers_count = 1
        expected_special_char_count = 1

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    def test_length_1000(self):
        expected_length = 1000
        expected_upper_case_count = 1
        expected_numbers_count = 1
        expected_special_char_count = 1

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    def test_length_with_string(self):
        expected_length = "12"
        expected_upper_case_count = 1
        expected_numbers_count = 1
        expected_special_char_count = 1

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    # for number of uppercase characters

    def test_length_of_upper_case_characters(self):
        expected_length = 12
        expected_upper_case_count = 2
        expected_numbers_count = 1
        expected_special_char_count = 1

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    def test_length_of_upper_case_characters_12(self):
        expected_length = 12
        expected_upper_case_count = 12
        expected_numbers_count = 1
        expected_special_char_count = 1

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    def test_length_of_upper_case_characters_0(self):
        expected_length = 12
        expected_upper_case_count = 0
        expected_numbers_count = 1
        expected_special_char_count = 1

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    def test_length_of_upper_case_characters_1000(self):
        expected_length = 12
        expected_upper_case_count = 1000
        expected_numbers_count = 1
        expected_special_char_count = 1

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    def test_length_of_upper_case_characters_with_string(self):
        expected_length = 12
        expected_upper_case_count = "2"
        expected_numbers_count = 1
        expected_special_char_count = 1

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    # for number of numerical characters
    def test_length_of_numbers(self):
        expected_length = 12
        expected_upper_case_count = 2
        expected_numbers_count = 1
        expected_special_char_count = 1

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    def test_length_of_numbers_12(self):
        expected_length = 12
        expected_upper_case_count = 2
        expected_numbers_count = 12
        expected_special_char_count = 1

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    def test_length_of_numbers_0(self):
        expected_length = 12
        expected_upper_case_count = 2
        expected_numbers_count = 0
        expected_special_char_count = 1

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    def test_length_of_numbers_1000(self):
        expected_length = 12
        expected_upper_case_count = 2
        expected_numbers_count = 1000
        expected_special_char_count = 1

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    def test_length_of_numbers_with_string(self):
        expected_length = 12
        expected_upper_case_count = 2
        expected_numbers_count = "2"
        expected_special_char_count = 1

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    # for number of special characters
    def test_length_of_special_chars(self):
        expected_length = 12
        expected_upper_case_count = 2
        expected_numbers_count = 2
        expected_special_char_count = 2

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    def test_length_of_special_chars_12(self):
        expected_length = 12
        expected_upper_case_count = 2
        expected_numbers_count = 2
        expected_special_char_count = 12

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    def test_length_of_special_chars_0(self):
        expected_length = 12
        expected_upper_case_count = 2
        expected_numbers_count = 2
        expected_special_char_count = 0

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    def test_length_of_special_chars_1000(self):
        expected_length = 12
        expected_upper_case_count = 2
        expected_numbers_count = 2
        expected_special_char_count = 1000

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)

    def test_length_of_special_chars_with_string(self):
        expected_length = 12
        expected_upper_case_count = 2
        expected_numbers_count = 2
        expected_special_char_count = "1"

        self.test_generate_password(expected_length, expected_upper_case_count,
                                    expected_numbers_count, expected_special_char_count)


if __name__ == "__main__":
    unittest.main()
