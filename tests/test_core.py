import os
import tempfile
import unittest

from arca_guhya.entropy import shannon_entropy, looks_random
from arca_guhya.masking import mask
from arca_guhya.rules import RULES, rule_by_id
from arca_guhya.scanner import scan_text
from arca_guhya.ignore import IgnoreMatcher

# Sample credentials are assembled at runtime so this file never contains a
# literal token that other secret scanners (or push protection) would flag.
AWS_ID = "AKIA" + "Q3EXAMPLE7NOTREAL"[:16].upper().ljust(16, "X")
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
GH_TOKEN = "gh" + "p_" + "R4nd0mL00k1ngT0kenV4lue1234567890abc"
SLACK = "xo" + "xb-" + "123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx"
STRIPE_LIVE = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
STRIPE_TEST = "sk" + "_test_" + "4eC39HqLyjWDarjtT1zdp7dc"
JWT = "eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0." + "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"


def ids(findings):
    return sorted(f.rule_id for f in findings)


class EntropyTests(unittest.TestCase):
    def test_shannon_entropy_basics(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(shannon_entropy("ab"), 1.0)
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0)

    def test_looks_random(self):
        self.assertTrue(looks_random("q8Zr2LkP0vW9xY3nB7tM5cJ1hG4fD6sA"))
        self.assertFalse(looks_random("ThisIsAVeryLongVariableNameIndeed"))
        self.assertFalse(looks_random("aaaaaaaaaaaaaaaaaaaaaaaa1"))


class MaskTests(unittest.TestCase):
    def test_mask_keeps_only_edges(self):
        m = mask("ABCDEFGHIJKLMNOP")
        self.assertTrue(m.startswith("ABCD"))
        self.assertTrue(m.endswith("OP"))
        self.assertNotIn("GHIJ", m)
        self.assertEqual(len(m), 16)

    def test_short_values_fully_masked(self):
        self.assertEqual(mask("hunter2"), "*******")


class RuleTests(unittest.TestCase):
    def test_rule_ids_unique(self):
        names = [r.id for r in RULES]
        self.assertEqual(len(names), len(set(names)))
        self.assertIsNotNone(rule_by_id("private-key"))

    def test_detects_each_provider(self):
        cases = {
            f'aws_access_key_id = "{AWS_ID}"': "aws-access-key-id",
            f'aws_secret_access_key = "{AWS_SECRET}"': "aws-secret-access-key",
            f"token: {GH_TOKEN}": "github-token",
            f"SLACK_BOT={SLACK}": "slack-token",
            f"stripe.api_key = '{STRIPE_LIVE}'": "stripe-live-key",
            f"stripe.api_key = '{STRIPE_TEST}'": "stripe-test-key",
            f"Authorization: Bearer {JWT}": "jwt",
            PEM: "private-key",
        }
        for line, rule in cases.items():
            with self.subTest(rule=rule):
                found = scan_text(line, "x.txt")
                self.assertIn(rule, ids(found), line)

    def test_benign_text_has_no_findings(self):
        text = "def main():\n    name = 'ThisIsAVeryLongVariableNameIndeed'\n    print('hello world')\n"
        self.assertEqual(scan_text(text, "a.py"), [])

    def test_generic_entropy_in_assignment(self):
        found = scan_text('config = {"api_secret": "q8Zr2LkP0vW9xY3nB7tM5cJ1hG4fD6sA"}', "c.json")
        self.assertEqual(ids(found), ["high-entropy-string"])

    def test_specific_rule_suppresses_generic_overlap(self):
        found = scan_text(f'key = "{GH_TOKEN}"', "c.py")
        self.assertEqual(ids(found), ["github-token"])

    def test_inline_allow_comment(self):
        self.assertEqual(scan_text(f'tok = "{GH_TOKEN}"  # arca:allow', "c.py"), [])

    def test_finding_position_and_masking(self):
        f = scan_text(f"\n\nx = {GH_TOKEN}", "p.txt")[0]
        self.assertEqual((f.line, f.column), (3, 5))
        self.assertNotIn(GH_TOKEN, str(f.to_dict()))
        self.assertNotIn(GH_TOKEN, f.snippet)
        self.assertEqual(len(f.fingerprint), 16)

    def test_fingerprint_stable_across_line_moves(self):
        a = scan_text(f"x = {GH_TOKEN}", "p.txt")[0]
        b = scan_text(f"\n\n\nx = {GH_TOKEN}", "p.txt")[0]
        self.assertEqual(a.fingerprint, b.fingerprint)


class IgnoreTests(unittest.TestCase):
    def setUp(self):
        self.m = IgnoreMatcher()
        self.m.add_patterns(["*.log", "!keep.log", "/build", "tmp/", "docs/**/secret.txt", "# comment", ""], base="")

    def test_glob_and_negation(self):
        self.assertTrue(self.m.is_ignored("app.log", False))
        self.assertTrue(self.m.is_ignored("deep/dir/app.log", False))
        self.assertFalse(self.m.is_ignored("keep.log", False))

    def test_anchored_and_dir_only(self):
        self.assertTrue(self.m.is_ignored("build", True))
        self.assertFalse(self.m.is_ignored("src/build", True))
        self.assertTrue(self.m.is_ignored("src/tmp", True))
        self.assertFalse(self.m.is_ignored("src/tmp", False))

    def test_double_star(self):
        self.assertTrue(self.m.is_ignored("docs/secret.txt", False))
        self.assertTrue(self.m.is_ignored("docs/a/b/secret.txt", False))
        self.assertFalse(self.m.is_ignored("other/secret.txt", False))

    def test_nested_base(self):
        m = IgnoreMatcher()
        m.add_patterns(["*.env"], base="service")
        self.assertTrue(m.is_ignored("service/prod.env", False))
        self.assertFalse(m.is_ignored("prod.env", False))


if __name__ == "__main__":
    unittest.main()
