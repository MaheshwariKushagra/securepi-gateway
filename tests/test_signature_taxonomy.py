#!/usr/bin/env python3
"""
SecurePi Gateway - signature taxonomy tests (ENHANCEMENT-PLAN.md step 2.3).

Run via `make test`, or directly: python3 -m unittest tests.test_signature_taxonomy -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402 - adds app/ to sys.path

import signature_taxonomy  # noqa: E402


class ClassifyTests(unittest.TestCase):
    def test_a_curated_category_returns_its_specific_mapping(self):
        signal_type, plain_name, severity, attack = signature_taxonomy.classify(
            "A Network Trojan was detected", 1)
        self.assertEqual(signal_type, "ids_trojan")
        self.assertEqual(severity, "high")
        self.assertEqual(attack[0], "Command and Control")
        self.assertEqual(attack[3], "T1071")

    def test_an_uncurated_category_falls_back_with_severity_from_priority(self):
        signal_type, plain_name, severity, attack = signature_taxonomy.classify(
            "Misc activity", 3)
        self.assertEqual(signal_type, "ids_other")
        self.assertEqual(plain_name, "Misc activity")
        self.assertEqual(severity, "low")
        self.assertIsNone(attack)

    def test_priority_1_and_2_map_to_high_and_medium(self):
        self.assertEqual(signature_taxonomy.classify("Some rare category", 1)[2], "high")
        self.assertEqual(signature_taxonomy.classify("Some rare category", 2)[2], "medium")

    def test_missing_or_unrecognized_priority_defaults_safely(self):
        signal_type, plain_name, severity, attack = signature_taxonomy.classify(None, None)
        self.assertEqual(signal_type, "ids_other")
        self.assertEqual(severity, "medium")
        self.assertEqual(plain_name, "Unclassified IDS alert")

    def test_ids_other_has_no_playbooks_attack_mapping(self):
        # The module docstring says ids_other deliberately gets no ATT&CK
        # tag - a regression guard, the same shape as
        # PortScanNamingTests's source-text check elsewhere in this suite.
        import playbooks
        self.assertNotIn("ids_other", playbooks.ATTACK_MAPPING)
        self.assertIn("ids_other", playbooks.PLAYBOOKS, "but it must still have a playbook")

    def test_every_curated_signal_type_has_a_playbooks_entry(self):
        import playbooks
        for signal_type in signature_taxonomy.ALL_SIGNAL_TYPES:
            self.assertIn(signal_type, playbooks.PLAYBOOKS, "%s needs a playbook" % signal_type)


if __name__ == "__main__":
    unittest.main()
