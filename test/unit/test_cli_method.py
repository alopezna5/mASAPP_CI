import StringIO
import time
import unittest
from masappcli.__main__ import *
import sys


class TestCLI(unittest.TestCase):
    def setUp(self):
        sys.argv = sys.argv[0:1]

    def test_no_params(self):
        input_data = []
        expected_message = "No args added"

        with self.assertRaisesRegexp(ValueError, expected_message):
            cli(input_data)

    ### Keys and secret tests ###

    def test_added_key_not_added_secret(self):
        expected_message = "-key and -secret can only be used simultaneously"

        with self.assertRaisesRegexp(ValueError, expected_message):
            sys.argv.append("-key")
            sys.argv.append("TESTING KEY")
            main()

    def test_not_added_key_added_secret(self):

        expected_message = "-key and -secret can only be used simultaneously"

        with self.assertRaisesRegexp(ValueError, expected_message):
            sys.argv.append("-secret")
            sys.argv.append("TESTING SECRET")
            main()

    ### Execution types tests ###

    def test_both_execution(self):

        expected_message = "Riskscore and standard execution can not being thrown simultaneously"

        with self.assertRaisesRegexp(ValueError, expected_message):
            sys.argv.append("-key")
            sys.argv.append("TESTING KEY")
            sys.argv.append("-secret")
            sys.argv.append("TESTING SECRET")
            sys.argv.append("-r")
            sys.argv.append("9.8")
            sys.argv.append("-s")
            sys.argv.append("fake/path.json")
            main()


