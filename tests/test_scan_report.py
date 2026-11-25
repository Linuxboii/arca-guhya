import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from arca_guhya import cli
from arca_guhya.filters import Allowlist, load_baseline, write_baseline, apply_filters
from arca_guhya.report import to_json, to_sarif
from arca_guhya.scanner import scan_path, scan_text

GH_TOKEN = "gh" + "p_" + "Zx81Qm2Lp0Wv7Ty3Rb6Nc5Hd4Kf9Js1Ga8Ue2"
STRIPE_TEST = "sk" + "_test_" + "51HxQk2Lm8Np3Rs7Tv9Wy4Za6"


class TreeTestCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="arca-test-")
        self.write(".gitignore", "*.log\nbuild/\n")
        self.write("app/config.py", f'GITHUB_TOKEN = "{GH_TOKEN}"\n')
        self.write("app/payments.js", f"const stripe = require('stripe')('{STRIPE_TEST}');\n")
        self.write("debug.log", f"token={GH_TOKEN}\n")
        self.write("build/out.js", f"x='{GH_TOKEN}'\n")
        self.write("img.dat", b"\x00\x01binary" + GH_TOKEN.encode())
        self.write("README.md", "Nothing to see here.\n")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def write(self, rel, content):
        path = os.path.join(self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(path, mode) as fh:
            fh.write(content)
        return path


class ScanPathTests(TreeTestCase):
    def test_respects_gitignore_and_skips_binary(self):
        findings, stats = scan_path(self.root)
        paths = sorted({f.path for f in findings})
        self.assertEqual(paths, ["app/config.py", "app/payments.js"])
        self.assertGreaterEqual(stats.files_skipped, 2)  # debug.log + img.dat

    def test_no_gitignore_scans_everything_text(self):
        findings, _ = scan_path(self.root, use_gitignore=False)
        paths = {f.path for f in findings}
        self.assertIn("debug.log", paths)
        self.assertIn("build/out.js", paths)
        self.assertNotIn("img.dat", paths)

    def test_single_file_target(self):
        findings, stats = scan_path(os.path.join(self.root, "app", "config.py"))
        self.assertEqual(stats.files_scanned, 1)
        self.assertEqual([f.rule_id for f in findings], ["github-token"])


class FilterTests(TreeTestCase):
    def test_allowlist_by_rule_path_regex_and_fingerprint(self):
        findings, _ = scan_path(self.root)
        gh = next(f for f in findings if f.rule_id == "github-token")
        for entry in ("rule:stripe-test-key", "path:app/payments.*", "regex:^sk_test_", f"fingerprint:{gh.fingerprint}"):
            with self.subTest(entry=entry):
                allow = Allowlist.parse([entry])
                kept = [f for f in findings if not allow.matches(f)]
                self.assertEqual(len(kept), len(findings) - 1)

    def test_allowlist_ignores_comments_and_rejects_bad_regex(self):
        allow = Allowlist.parse(["# comment", "", "rule:jwt"])
        self.assertEqual(len(allow.entries), 1)
        with self.assertRaises(ValueError):
            Allowlist.parse(["regex:("])

    def test_baseline_roundtrip_suppresses_known(self):
        findings, _ = scan_path(self.root)
        path = os.path.join(self.root, "baseline.json")
        write_baseline(path, findings)
        with open(path) as fh:
            raw = fh.read()
        self.assertNotIn(GH_TOKEN, raw)
        baseline = load_baseline(path)
        self.write("app/new.py", "API_KEY = 'q8Zr2LkP0vW9xY3nB7tM5cJ1hG4fD6sA'\n")
        again, _ = scan_path(self.root)
        kept, counts = apply_filters(again, Allowlist(), baseline)
        self.assertEqual([f.path for f in kept], ["app/new.py"])
        self.assertEqual(counts["baseline"], 2)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.findings = scan_text(f'token = "{GH_TOKEN}"', "src/a.py")

    def test_json_masks_secrets(self):
        data = json.loads(to_json(self.findings, {"files_scanned": 1}))
        self.assertEqual(data["summary"]["total"], 1)
        self.assertNotIn(GH_TOKEN, json.dumps(data))
        self.assertTrue(data["findings"][0]["secret"].startswith("ghp_"))

    def test_sarif_structure(self):
        sarif = json.loads(to_sarif(self.findings))
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "arca-guhya")
        result = run["results"][0]
        self.assertEqual(result["ruleId"], "github-token")
        self.assertEqual(result["level"], "error")
        loc = result["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "src/a.py")
        self.assertEqual(loc["region"]["startLine"], 1)
        rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        self.assertIn("github-token", rule_ids)
        self.assertNotIn(GH_TOKEN, json.dumps(sarif))


class CliTests(TreeTestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_exit_1_with_findings_and_masked_text(self):
        code, out, _ = self.run_cli(self.root, "--no-color")
        self.assertEqual(code, 1)
        self.assertIn("github-token", out)
        self.assertNotIn(GH_TOKEN, out)

    def test_severity_filter_and_exit_0(self):
        os.remove(os.path.join(self.root, "app", "config.py"))
        code, out, _ = self.run_cli(self.root, "--min-severity", "medium", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["summary"]["total"], 0)

    def test_write_baseline_then_clean_run(self):
        base = os.path.join(self.root, "base.json")
        code, _, _ = self.run_cli(self.root, "--write-baseline", base)
        self.assertEqual(code, 0)
        code, _, _ = self.run_cli(self.root, "--baseline", base)
        self.assertEqual(code, 0)

    def test_default_allowlist_file_is_used(self):
        self.write(".arca-allowlist", "path:app/*\n")
        code, _, _ = self.run_cli(self.root)
        self.assertEqual(code, 0)

    def test_sarif_to_file(self):
        out_path = os.path.join(self.root, "r.sarif")
        code, _, _ = self.run_cli(self.root, "--format", "sarif", "-o", out_path)
        self.assertEqual(code, 1)
        with open(out_path) as fh:
            self.assertEqual(json.load(fh)["version"], "2.1.0")

    def test_missing_path_is_error(self):
        code, _, err = self.run_cli(os.path.join(self.root, "nope"))
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
