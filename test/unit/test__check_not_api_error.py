import json
import unittest
from masappcli.masappci import mASAPP_CI
from sdklib.http.response import HttpResponse


class Urllib3ResponseMock(object):
    def __init__(self, data):
        self.data = data

    def getheaders(self):
        return {}

    @property
    def status(self):
        return None

    @property
    def reason(self):
        return None

    @status.setter
    def status(self, value):
        self._status = value


class TestCheckNotApiError(unittest.TestCase):

    def setUp(self):
        self.usr = mASAPP_CI("example_key", "example_secret")
        self.JSON_DATA_WITHOUT_ERROR = b"""{"data": "Data for testing","scans":{"scan1":"info_scan1","scan2":"info_scan2","scan3":"info_scan3"}}"""

        self.JSON_DATA_AND_ERROR = b"""{"data": "Test with error code in body","error":{"code":209,"message":"Error"}}"""
        self.JSON_NO_DATA_AND_ERROR = b"""{}"""

    def test_empty_api_response(self):
        input_data = ""
        expected_message = "ERROR API Response is empty"

        with self.assertRaisesRegexp(ValueError, expected_message):
            mASAPP_CI._check_not_api_error(self.usr, input_data)

    def test_none_api_response(self):
        input_data = None
        expected_message = "ERROR API Response is None"

        with self.assertRaisesRegexp(TypeError, expected_message):
            mASAPP_CI._check_not_api_error(self.usr, input_data)

    def test_empty_dict_api_response(self):
        input_data = json.loads("{}")
        expected_message = "ERROR API Response dict is empty"

        with self.assertRaisesRegexp(ValueError, expected_message):
            mASAPP_CI._check_not_api_error(self.usr, input_data)

    def test__check_api_response_with_error_in_status_and_no_errors_in_body(self):
        Urllib3ResponseMock.status = 300
        input_data = HttpResponse(Urllib3ResponseMock(self.JSON_DATA_WITHOUT_ERROR))
        expected_message = "ERROR in API response: status is 300"

        with self.assertRaisesRegexp(ValueError, expected_message):
            mASAPP_CI._check_not_api_error(self.usr, input_data)

    def test__check_api_response_with_error_in_status_and_errors_in_body(self):
        Urllib3ResponseMock.status = 300
        input_data = HttpResponse(Urllib3ResponseMock(self.JSON_DATA_AND_ERROR))
        expected_message = "ERROR in API response: status is 300"

        with self.assertRaisesRegexp(ValueError, expected_message):
            mASAPP_CI._check_not_api_error(self.usr, input_data)

    def test__check_api_response_without_status_and_no_errors_in_body(self):
        Urllib3ResponseMock.status = None
        input_data = HttpResponse(Urllib3ResponseMock(self.JSON_DATA_WITHOUT_ERROR))

        self.assertTrue(mASAPP_CI._check_not_api_error(self.usr, input_data))

    def test__check_api_response_without_status_and_errors_in_body(self):
        Urllib3ResponseMock.status = None
        input_data = HttpResponse(Urllib3ResponseMock(self.JSON_DATA_AND_ERROR))
        expected_message = """ERROR in API response: body is {"data": "Test with error code in body","error":{"code":209,"message":"Error"}}"""

        with self.assertRaisesRegexp(ValueError, expected_message):
            mASAPP_CI._check_not_api_error(self.usr, input_data)

    def test__check_api_response_with_no_error_in_status_and_no_errors_in_body(self):
        Urllib3ResponseMock.status = 200
        input_data = HttpResponse(Urllib3ResponseMock(self.JSON_DATA_WITHOUT_ERROR))

        self.assertTrue(mASAPP_CI._check_not_api_error(self.usr, input_data))

    def test__check_api_response_with_no_error_in_status_errors_in_body(self):
        Urllib3ResponseMock.status = 200
        input_data = HttpResponse(Urllib3ResponseMock(self.JSON_DATA_AND_ERROR))
        expected_message = """ERROR in API response: body is {"data": "Test with error code in body","error":{"code":209,"message":"Error"}}"""

        with self.assertRaisesRegexp(ValueError, expected_message):
            mASAPP_CI._check_not_api_error(self.usr, input_data)

    
    def test__check_api_response_with_no_error_in_status_and_empty_body(self):
        Urllib3ResponseMock.status = 200
        input_data = HttpResponse(Urllib3ResponseMock(self.JSON_NO_DATA_AND_ERROR))

        self.assertTrue(mASAPP_CI._check_not_api_error(self.usr, input_data))

    def test__check_api_response_with_no_error_in_status_and_none_body(self):
        Urllib3ResponseMock.status = 200
        input_data = HttpResponse(Urllib3ResponseMock(None))

        self.assertTrue(mASAPP_CI._check_not_api_error(self.usr, input_data))



