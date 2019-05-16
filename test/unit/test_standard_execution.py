import unittest

import mock
from mock import MagicMock

from masappci.masappci import mASAPP_CI


class TestStandardExecution(unittest.TestCase):

    def setUp(self):
        self.usr = mASAPP_CI("example_key", "example_secret")

        self.usr.scan_result = {
            'riskScore': None,
            'behaviorals': {'critical': ["behav"], 'high': ["behav1", "behav2"],
                            'medium': ["behav1", "behav2", "behav3"],
                            'low': []},
            'vulnerabilities': {'critical': ["vuln1", "vuln2"], 'high': ["vuln1"], 'medium': [],
                                'low': ["vuln1", "vuln2"]}
        }

    # def mock_upload_and_analyse_app(self):
    #     return True
    #
    # @mock.patch('masappci.masappci.mASAPP_CI.upload_and_analyse_app', True)
    # def test_different_element_value_from_expected(self):
    #     """
    #     The supported elements are: "vulnerabilities", "behaviorals" or "behaviors"
    #     If it is different it would throw a ValueError exception
    #     """
    #
    #     mock = MagicMock(name='masappci.masappci.mASAPP_CI.upload_and_analyse_app',
    #                           side_effect=self.mock_upload_and_analyse_app())
    #
    #
    #     input_data = "not_supported_element"
    #     expected_message = "Element must be 'vulnerabilities', 'behaviorals' or 'behaviors'"
    #
    #     with self.assertRaisesRegexp(ValueError, expected_message):
    #         mASAPP_CI.standard_execution(self.usr, "", "", package_name_origin=None, workgroup=None,
    #                                      lang=None,
    #                                      detail=None)

    #     @mock.patch('masappci.masappci.mASAPP_CI.upload_and_analyse_app', True)
    # def test_different_element_value_from_expected(self):
    #     """
    #     The supported elements are: "vulnerabilities", "behaviorals" or "behaviors"
    #     If it is different it would throw a ValueError exception
    #     """
    #
    #     input_data = "not_supported_element"
    #     expected_message = "Element must be 'vulnerabilities', 'behaviorals' or 'behaviors'"
    #
    #     with self.assertRaisesRegexp(ValueError, expected_message):
    #         mASAPP_CI.standard_execution(self.usr, "", "", package_name_origin=None, workgroup=None,
    #                                      lang=None,
    #                                      detail=None)
    #
    #
    #
