#!/usr/bin/env python3
"""Unit and end-to-end tests for wobble (stdlib unittest only)."""

import os
import sys
import unittest

# Make wobble importable regardless of where the discovery runs from.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import wobble  # noqa: E402
from wobble import Run, mask_text  # noqa: E402

HELPERS = os.path.join(_HERE, "helpers")


def make_runs(specs):
    """specs: list of (stdout, stderr, returncode). elapsed is steady."""
    runs = []
    for i, (out, err, rc) in enumerate(specs):
        runs.append(Run(index=i, stdout=out, stderr=err, returncode=rc,
                        elapsed=0.10 + (i * 0.0001)))
    return runs


# ---------------------------------------------------------------------------
# 1. mask_text unit tests
# ---------------------------------------------------------------------------


class MaskTextTests(unittest.TestCase):
    def test_iso_timestamp(self):
        self.assertEqual(mask_text("at 2026-09-08T13:44:57.123Z ok"), "at <TS> ok")

    def test_iso_date_only(self):
        self.assertEqual(mask_text("date 2026-09-08 end"), "date <TS> end")

    def test_epoch_ms_not_epoch(self):
        # A 13-digit number must become <EPOCHMS>, not <EPOCH>.
        out = mask_text("ts=1725800000000 done")
        self.assertIn("<EPOCHMS>", out)
        self.assertNotIn("<EPOCH>", out.replace("<EPOCHMS>", ""))

    def test_epoch_seconds(self):
        self.assertEqual(mask_text("t=1725800000 x"), "t=<EPOCH> x")

    def test_uuid_not_partial_hash(self):
        u = "550e8400-e29b-41d4-a716-446655440000"
        out = mask_text("id={}".format(u))
        self.assertEqual(out, "id=<UUID>")
        self.assertNotIn("<HASH>", out)

    def test_hexptr_not_hash(self):
        out = mask_text("ptr 0xdeadbeef here")
        self.assertEqual(out, "ptr <PTR> here")
        self.assertNotIn("<HASH>", out)

    def test_sha_hash(self):
        out = mask_text("commit 1a2b3c4d5e6f7890 landed")
        self.assertEqual(out, "commit <HASH> landed")

    def test_ansi_stripped(self):
        out = mask_text("\x1b[31mred\x1b[0m text")
        self.assertEqual(out, "red text")

    def test_win_path(self):
        out = mask_text(r"open C:\Users\alex\tmp\file.log now")
        self.assertEqual(out, "open <PATH> now")

    def test_tmp_path(self):
        out = mask_text("wrote /tmp/abc123/out here")
        self.assertEqual(out, "wrote <PATH> here")

    def test_ip_port(self):
        out = mask_text("conn 10.0.0.5:8080 up")
        self.assertEqual(out, "conn <IP:PORT> up")

    def test_ipv4(self):
        out = mask_text("host 192.168.1.1 reached")
        self.assertEqual(out, "host <IP> reached")

    def test_pid(self):
        self.assertEqual(mask_text("pid=1234 running"), "pid=<PID> running")
        self.assertEqual(mask_text("PID: 42 up"), "pid=<PID> up")

    def test_localhost_port(self):
        out = mask_text("serving localhost:3000 ok")
        self.assertEqual(out, "serving <HOST:PORT> ok")


# ---------------------------------------------------------------------------
# 2. Clustering / verdict with fabricated Run lists
# ---------------------------------------------------------------------------


class VerdictTests(unittest.TestCase):
    def test_identical_stable(self):
        runs = make_runs([("same\n", "", 0)] * 6)
        a = wobble.analyze(runs, "cmd")
        self.assertEqual(a.verdict, wobble.VERDICT_STABLE)
        self.assertEqual(len(a.masked_classes), 1)
        self.assertAlmostEqual(a.flake_rate, 0.0, places=6)

    def test_volatile_but_equivalent(self):
        specs = []
        for i in range(6):
            out = "ts: 2026-09-08T00:00:0{}.000Z id: {}\n".format(
                i, "550e8400-e29b-41d4-a716-44665544000{}".format(i)
            )
            specs.append((out, "", 0))
        runs = make_runs(specs)
        a = wobble.analyze(runs, "cmd")
        self.assertEqual(a.verdict, wobble.VERDICT_VOLATILE)
        self.assertEqual(len(a.masked_classes), 1)
        self.assertGreater(len(a.raw_classes), 1)

    def test_flaky_random_word(self):
        specs = [("word: {}\n".format(w), "", 0)
                 for w in ["alpha", "beta", "alpha", "gamma"]]
        runs = make_runs(specs)
        a = wobble.analyze(runs, "cmd")
        self.assertEqual(a.verdict, wobble.VERDICT_FLAKY)
        self.assertGreater(len(a.masked_classes), 1)
        self.assertTrue(a.stdout_varied)

    def test_flaky_exit_codes(self):
        runs = make_runs([("out\n", "", 0), ("out\n", "", 1),
                          ("out\n", "", 0)])
        a = wobble.analyze(runs, "cmd")
        self.assertEqual(a.verdict, wobble.VERDICT_FLAKY)
        self.assertTrue(a.exit_varied)

    def test_timing_wobbly_note_but_stable(self):
        runs = [
            Run(index=0, stdout="x", stderr="", returncode=0, elapsed=0.10),
            Run(index=1, stdout="x", stderr="", returncode=0, elapsed=1.00),
            Run(index=2, stdout="x", stderr="", returncode=0, elapsed=0.20),
        ]
        a = wobble.analyze(runs, "cmd", timing_tolerance=50.0)
        self.assertEqual(a.verdict, wobble.VERDICT_STABLE)
        self.assertTrue(a.timing_wobbly)
        self.assertIn("timing wobbly", a.note)

    def test_no_mask_makes_volatile_flaky(self):
        specs = []
        for i in range(4):
            specs.append(("id: {}\n".format(
                "550e8400-e29b-41d4-a716-44665544000{}".format(i)), "", 0))
        runs = make_runs(specs)
        a = wobble.analyze(runs, "cmd", mask=False)
        # Without masking, distinct uuids => multiple classes => FLAKY.
        self.assertEqual(a.verdict, wobble.VERDICT_FLAKY)


# ---------------------------------------------------------------------------
# 3. End-to-end via subprocess helper scripts
# ---------------------------------------------------------------------------


def _analyze_helper(script_name, n, mask=True):
    cmd = '"{}" "{}"'.format(sys.executable, os.path.join(HELPERS, script_name))
    runs = wobble.run_many(cmd, n)
    return wobble.analyze(runs, cmd, mask=mask), runs


class EndToEndTests(unittest.TestCase):
    def test_stable_helper(self):
        a, _ = _analyze_helper("stable.py", 8)
        self.assertEqual(a.verdict, wobble.VERDICT_STABLE)

    def test_volatile_helper(self):
        a, _ = _analyze_helper("volatile.py", 8)
        self.assertEqual(a.verdict, wobble.VERDICT_VOLATILE)

    def test_flaky_helper(self):
        a, _ = _analyze_helper("flaky.py", 12)
        self.assertEqual(a.verdict, wobble.VERDICT_FLAKY)
        self.assertGreater(a.flake_rate, 0.0)


# ---------------------------------------------------------------------------
# 4. Exit code behavior
# ---------------------------------------------------------------------------


class ExitCodeTests(unittest.TestCase):
    def test_fail_on_flaky_returns_nonzero_for_flaky(self):
        self.assertEqual(
            wobble.exit_code_for(wobble.VERDICT_FLAKY, "flaky"), 1)

    def test_fail_on_flaky_zero_for_stable(self):
        self.assertEqual(
            wobble.exit_code_for(wobble.VERDICT_STABLE, "flaky"), 0)

    def test_fail_on_volatile_catches_both(self):
        self.assertEqual(
            wobble.exit_code_for(wobble.VERDICT_VOLATILE, "volatile"), 1)
        self.assertEqual(
            wobble.exit_code_for(wobble.VERDICT_FLAKY, "volatile"), 1)

    def test_fail_on_none_always_zero(self):
        for v in (wobble.VERDICT_STABLE, wobble.VERDICT_VOLATILE,
                  wobble.VERDICT_FLAKY):
            self.assertEqual(wobble.exit_code_for(v, "none"), 0)

    def test_main_exit_codes_end_to_end(self):
        flaky = '"{}" "{}"'.format(sys.executable,
                                   os.path.join(HELPERS, "flaky.py"))
        stable = '"{}" "{}"'.format(sys.executable,
                                    os.path.join(HELPERS, "stable.py"))
        rc_flaky = wobble.main(["-n", "12", "--fail-on", "flaky", "-q", flaky])
        self.assertNotEqual(rc_flaky, 0)
        rc_stable = wobble.main(["-n", "6", "--fail-on", "flaky", "-q", stable])
        self.assertEqual(rc_stable, 0)


if __name__ == "__main__":
    unittest.main()
