import unittest
from masappcli.__main__ import *


class TestCheckJSON(unittest.TestCase):
    def setUp(self):
        # Test files

        self.JSON_EMPTY_FILE = "../data/empty_json.json"
        self.NOT_JSON_FILE = "../data/txtfile.txt"
        self.JSON_NO_VULNS_AND_NOT_BEHAV_FILE = "../data/not_vuln_and_not_behaviors.json"
        self.JSON_VULNS_AND_NO_BEHAV_FILE = "../data/vuln_and_not_behaviors.json"
        self.JSON_NO_VULNS_AND_BEHAV_FILE = "../data/not_vuln_and_behaviors.json"
        self.JSON_VULNS_AND_BEHAV_FILE = "../data/vuln_and_behaviors.json"

        #Test jsons

        self.EMPTY = ""
        self.NOT_JSON = "this is a test"
        self.EMPTY_JSON = "{}"
        self.JSON_NO_VULNS_AND_NOT_BEHAV = """
        {
        "thisisnotvulnerabilities": {
            "critical": 14,
            "high": 14,
            "medium": 14,
            "low": 14
        },
        "thisisnotbehaviorals": {
            "critical": 14,
            "high": 14,
            "medium": 14,
            "low": 14
          }
        }
        """

        self.JSON_VULNS_AND_NO_BEHAV = """
        {
        "vulnerabilities": {
            "critical": 14,
            "high": 14,
            "medium": 14,
            "low": 14
        },
        "thisisnotbehaviorals": {
            "critical": 14,
            "high": 14,
            "medium": 14,
            "low": 14
          }
        }
        
        """


        self.JSON_NO_VULNS_AND_BEHAVE = """
        {
        "thisisnotvulnerabilities": {
            "critical": 14,
            "high": 14,
            "medium": 14,
            "low": 14
        },
        "behaviorals": {
            "critical": 14,
            "high": 14,
            "medium": 14,
            "low": 14
          }
        }
        """

        self.JSON_VULNS_AND_BEHAVE = """
        {
        "vulnerabilities": {
            "critical": 14,
            "high": 14,
            "medium": 14,
            "low": 14
        },
        "behaviorals": {
            "critical": 14,
            "high": 14,
            "medium": 14,
            "low": 14
          }
        }
        """


    ######### FILES  #########

    def test_empty_json_file(self):
        input_data = self.JSON_EMPTY_FILE
        self.assertFalse(check_json(input_data))

    def test_None_json(self):
        input_data = None
        self.assertFalse(check_json(input_data))

    def test_not_json_file(self):
        input_data = self.NOT_JSON_FILE
        self.assertFalse(check_json(input_data))

    def test_json_file_that_contains_no_vuln_and_no_behav(self):
        input_data = self.JSON_NO_VULNS_AND_NOT_BEHAV_FILE
        self.assertFalse(check_json(input_data))

    def test_json_file_that_contains_vuln_and_no_behav(self):
        input_data = self.JSON_VULNS_AND_NO_BEHAV_FILE
        self.assertFalse(check_json(input_data))

    def test_json_file_that_contains_no_vuln_and_behav(self):
        input_data = self.JSON_NO_VULNS_AND_BEHAV_FILE
        self.assertFalse(check_json(input_data))

    def test_json_file_that_contains_vuln_and_behav(self):
        input_data = self.JSON_VULNS_AND_BEHAV_FILE
        expected_json = json.load(open(input_data))
        self.assertEquals(expected_json, check_json(input_data))


    ######### JSON  #########

    def test_empty_json(self):
        input_data = self.EMPTY
        self.assertFalse(check_json(input_data))

    def test_not_json(self):
        input_data = self.NOT_JSON
        self.assertFalse(check_json(input_data))

    def test_json_that_contains_no_vuln_and_no_behav(self):
        input_data = self.JSON_NO_VULNS_AND_NOT_BEHAV
        self.assertFalse(check_json(input_data))

    def test_json_that_contains_vuln_and_no_behav(self):
        input_data = self.JSON_VULNS_AND_NO_BEHAV
        self.assertFalse(check_json(input_data))

    def test_json_that_contains_no_vuln_and_behav(self):
        input_data = self.JSON_NO_VULNS_AND_BEHAVE
        self.assertFalse(check_json(input_data))

    def test_json_that_contains_vuln_and_behav(self):
        input_data = self.JSON_VULNS_AND_BEHAVE
        self.assertTrue(check_json(input_data))












