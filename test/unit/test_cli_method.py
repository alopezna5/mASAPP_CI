import unittest
from masappcli.__main__ import *
import sys
import os


class TestCLI(unittest.TestCase):
    def setUp(self):
        # Restoring of argv and environ
        sys.argv = sys.argv[0:1]
        os.environ.clear()


    def _add_fake_key_and_fake_secret(self):
        os.environ['MASAPP_KEY'] = 'FAKE_KEY'
        os.environ['MASAPP_SECRET'] = 'FAKE_SECRET'


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
            cli(sys.argv[1:])

    def test_not_added_key_added_secret(self):

        expected_message = "-key and -secret can only be used simultaneously"

        with self.assertRaisesRegexp(ValueError, expected_message):
            sys.argv.append("-secret")
            sys.argv.append("TESTING SECRET")
            cli(sys.argv[1:])

    def test_not_added_credentials_not_added_key_in_env(self):
        expected_message = "MASAPP_KEY is not stored in environment. Please, use the option --configure or add directly it with -key option"

        with self.assertRaisesRegexp(ValueError, expected_message):
            sys.argv.append("-a")
            sys.argv.append("fake/path.apk")
            cli(sys.argv[1:])

    def test_not_added_credentials_not_added_secret_in_env(self):
        expected_message = "MASAPP_SECRET is not stored in environment. Please, use the option --configure or add directly it with -secret option"

        os.environ['MASAPP_KEY'] = 'FAKE_KEY'

        with self.assertRaisesRegexp(ValueError, expected_message):
            sys.argv.append("-a")
            sys.argv.append("fake/path.apk")
            cli(sys.argv[1:])


    ### Execution types tests ###

    def test_no_execution_mode_added(self):
        expected_message = "No execution mode added"

        self._add_fake_key_and_fake_secret()

        with self.assertRaisesRegexp(ValueError, expected_message):
            sys.argv.append("-a")
            sys.argv.append("fake/path.apk")
            cli(sys.argv[1:])

    def test_both_execution(self):

        expected_message = "Riskscore and standard execution can not being thrown simultaneously"

        with self.assertRaisesRegexp(ValueError, expected_message):
            self._add_fake_key_and_fake_secret()
            sys.argv.append("-r")
            sys.argv.append("9.8")
            sys.argv.append("-s")
            sys.argv.append("fake/path.json")
            cli(sys.argv[1:])

    def test_riskscore_no_path_added(self):
        expected_message = "No path to the app added"

        with self.assertRaisesRegexp(ValueError, expected_message):
            self._add_fake_key_and_fake_secret()
            sys.argv.append("-r")
            sys.argv.append("9.8")
            cli(sys.argv[1:])


    def test_standard_no_path_added(self):
        expected_message = "No path to the app added"

        with self.assertRaisesRegexp(ValueError, expected_message):
            self._add_fake_key_and_fake_secret()
            sys.argv.append("-s")
            sys.argv.append("fake/path.json")
            cli(sys.argv[1:])


    def test_standard_wrong_json(self):
        expected_message = "Wrong json added for standard execution"

        with self.assertRaisesRegexp(ValueError, expected_message):
            self._add_fake_key_and_fake_secret()
            sys.argv.append("-s")
            sys.argv.append("../data/not_vuln_and_behaviors.json")
            sys.argv.append("-a")
            sys.argv.append("fake/path.apk")
            cli(sys.argv[1:])

