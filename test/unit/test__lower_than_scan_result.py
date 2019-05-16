import unittest

from masappci.masappci import mASAPP_CI


class TestLowerThanScanResult(unittest.TestCase):

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

    def test_different_element_value_from_expected(self):
        """
        The supported elements are: "vulnerabilities", "behaviorals" or "behaviors"
        If it is different it would throw a ValueError exception
        """

        input_data = "not_supported_element"
        expected_message = "Element must be 'vulnerabilities', 'behaviorals' or 'behaviors'"

        with self.assertRaisesRegexp(ValueError, expected_message):
            mASAPP_CI._lower_than_scan_result(self.usr, input_data, "example_key", "example_max_expected_value")

    def test_different_key_value_from_expected(self):
        """
        The supported keys are : "critical", "high", "medium", "low"
        If it is different it would throw a ValueError exception
        """

        input_data = "not_supported_key"
        expected_message = "Element must be 'critical', 'high', 'medium', 'low'"

        with self.assertRaisesRegexp(ValueError, expected_message):
            mASAPP_CI._lower_than_scan_result(self.usr, "vulnerabilities", input_data, "example_max_expected_value")

    def test_max_expected_value_empty(self):
        """
        When the max_expected value is empty it means that the user hasn't define a max value for that field so the
        _lower_than_scan_result must not fail
        """
        input_data = ""

        test = mASAPP_CI._lower_than_scan_result(self.usr, "behaviors", "high", input_data)

        self.assertTrue(test)

    def test_greater_expected_value_vulnerability(self):
        """
        If the expected value is greater than the number of the obtained vulnerabilities for the severity sent in the
        key arg it must return True
        """
        input_data = 3

        test = mASAPP_CI._lower_than_scan_result(self.usr, "vulnerabilities", "critical", input_data)

        self.assertTrue(test)

    def test_equal_expected_value_vulnerability(self):
        """
        If the expected value is equal than the number of the obtained vulnerabilities for the severity sent in the
        key arg it must return True
        """
        input_data = 2

        test = mASAPP_CI._lower_than_scan_result(self.usr, "vulnerabilities", "critical", input_data)

        self.assertTrue(test)

    def test_lower_expected_value_vulnerability(self):
        """
        If the expected value is lower than the number of the obtained vulnerabilities for the severity sent in the
        key arg it must return False
        """
        input_data = 1

        test = mASAPP_CI._lower_than_scan_result(self.usr, "vulnerabilities", "critical", input_data)

        self.assertFalse(test)

    def test_greater_expected_value_behaviors(self):
        """
        If the expected value is greater than the number of the obtained behaviors for the severity sent in the
        key arg it must return True
        """
        input_data = 4

        test = mASAPP_CI._lower_than_scan_result(self.usr, "behaviors", "medium", input_data)

        self.assertTrue(test)

    def test_equal_expected_value_behaviors(self):
        """
        If the expected value is equal than the number of the obtained behaviors for the severity sent in the
        key arg it must return True
        """
        input_data = 3

        test = mASAPP_CI._lower_than_scan_result(self.usr, "behaviors", "medium", input_data)

        self.assertTrue(test)

    def test_lower_expected_value_behaviors(self):
        """
        If the expected value is lower than the number of the obtained behaviors for the severity sent in the
        key arg it must return False
        """
        input_data = 2

        test = mASAPP_CI._lower_than_scan_result(self.usr, "behaviors", "medium", input_data)

        self.assertFalse(test)

    def test_greater_expected_value_behaviorals(self):
        """
        If the expected value is greater than the number of the obtained behaviors for the severity sent in the
        key arg it must return True
        """
        input_data = 4

        test = mASAPP_CI._lower_than_scan_result(self.usr, "behaviorals", "medium", input_data)

        self.assertTrue(test)

    def test_equal_expected_value_behaviorals(self):
        """
        If the expected value is equal than the number of the obtained behaviors for the severity sent in the
        key arg it must return True
        """
        input_data = 3

        test = mASAPP_CI._lower_than_scan_result(self.usr, "behaviorals", "medium", input_data)

        self.assertTrue(test)

    def test_lower_expected_value_behaviorals(self):
        """
        If the expected value is lower than the number of the obtained behaviors for the severity sent in the
        key arg it must return False
        """
        input_data = 2

        test = mASAPP_CI._lower_than_scan_result(self.usr, "behaviorals", "medium", input_data)

        self.assertFalse(test)


if __name__ == '__main__':
    unittest.main()
