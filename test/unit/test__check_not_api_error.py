import unittest
from masappci.masappci import mASAPP_CI


class Test(unittest.TestCase):
    def setUp(self):
        self.usr = mASAPP_CI("example_key", "example_secret")

    def test_empty_api_response(self):
        input_data = ""
        expected_message = "ERROR API Response is empty"

        with self.assertRaisesRegexp(AssertionError, expected_message):
            mASAPP_CI._check_not_api_error(self.usr, input_data)

    def test_none_api_response(self):
        input_data = None
        expected_message = "ERROR API Response is None"

        with self.assertRaisesRegexp(AssertionError, expected_message):
            mASAPP_CI._check_not_api_error(self.usr, input_data)

    def test_api_response_with_error_in_body(self):
        

        input_data = {
            "status": 200,
            "error": {
                "code": 102,
                "message": "Invalid application signature"
            }
        }

        expected_message = "ERROR API Response is None"

        with self.assertRaisesRegexp(AssertionError, expected_message):
            mASAPP_CI._check_not_api_error(self.usr, input_data)
