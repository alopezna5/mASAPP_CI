# -*- coding: utf-8 -*-

import unittest

from masappcli.masappcli import mASAPP_CI
import json


class TestAllEvidencesMuted(unittest.TestCase):

    def setUp(self):
        self.usr = mASAPP_CI("example_key", "example_secret")

    def test_none_element_sent(self):
        input_data = None
        expected_message = "\[X\] {} not allowed. Waiting for a vulnerability or behavior JSON".format(input_data)

        with self.assertRaisesRegex(ValueError, expected_regex=expected_message):
            mASAPP_CI._all_evidences_muted(self.usr, element=input_data)

    def test_empty_json_element_sent(self):
        input_data = {}
        expected_message = "\[X\] The mASAPP response has not the expected structure"

        with self.assertRaisesRegex(ValueError, expected_message):
            mASAPP_CI._all_evidences_muted(self.usr, element=input_data)

    def test_wrong_type_element_sent(self):
        input_data = "TestingString"
        expected_message = "\[X\] {} not allowed. Waiting for a vulnerability or behavior JSON".format(input_data)

        with self.assertRaisesRegex(ValueError, expected_message):
            mASAPP_CI._all_evidences_muted(self.usr, element=input_data)

    def test_result_field_not_sent_in_element(self):
        input_data = json.loads(open("test/data/evidence_without_result_field.json").read())
        expected_message = "\[X\] The mASAPP response has not the expected structure"

        with self.assertRaisesRegex(ValueError, expected_message):
            mASAPP_CI._all_evidences_muted(self.usr, element=input_data)

    def test_muted_field_not_sent_in_element(self):
        input_data = json.loads(open("test/data/evidence_without_muted_field.json").read())

        self.assertFalse(mASAPP_CI._all_evidences_muted(self.usr, element=input_data))

    def test_muted_fields_not_sent_in_element(self):
        input_data = json.loads(open("test/data/evidence_without_muted_fields.json").read())
        self.assertFalse(mASAPP_CI._all_evidences_muted(self.usr, element=input_data))

    def test_no_muted_evidences_in_element(self):
        input_data = json.loads(open("test/data/evidence_with_no_muted_evidences.json").read())
        self.assertFalse(mASAPP_CI._all_evidences_muted(self.usr, element=input_data))

    def test_some_muted_evidences_in_element(self):
        input_data = json.loads(open("test/data/evidence_with_some_muted_evidences.json").read())
        self.assertFalse(mASAPP_CI._all_evidences_muted(self.usr, element=input_data))

    def test_all_muted_evidences_in_element(self):
        input_data = json.loads(open("test/data/evidence_with_all_muted_evidences.json").read())
        self.assertTrue(mASAPP_CI._all_evidences_muted(self.usr, element=input_data))
