import StringIO
import time
import unittest
from masappcli.__main__ import *
import sys


class TestCLI(unittest.TestCase):
    def setUp(self):

        self.NO_PARAMS_RESPONSE = """
"""

    def execute_method_capturing_cli_output(self, input_data):
        capturedOutput = StringIO.StringIO()  # Create StringIO object
        sys.stdout = capturedOutput  # and redirect stdout.
        cli(input_data)  # Call unchanged function.
        # sys.stdout = sys.__stdout__  # Reset redirect

        return capturedOutput

    def test_no_params(self):
        input_data = []

        # result = self.execute_method_capturing_cli_output(input_data).getvalue()
        # self.assertEqual(result, self.NO_PARAMS_RESPONSE)
        self.assertEqual(cli(input_data), self.NO_PARAMS_RESPONSE)

    # def test_only_key(self):
    #     input_data = ["-key"]
    #     result = self.execute_method_capturing_cli_output(input_data).getvalue()
    #     self.assertEqual(result, self.NO_PARAMS_RESPONSE)
