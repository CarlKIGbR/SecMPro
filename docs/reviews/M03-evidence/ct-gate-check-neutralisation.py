# SPDX-License-Identifier: AGPL-3.0-or-later
"""Neutralise each re-derivation check of the ct gate in turn and list the xtask tests that then fail.

M2 review F15-F17 (and the A/A' placement control of ADR-042): every check of `xtask/src/ctreport.rs` must have a
test that fails when the check is removed or loosened. For every entry of NEUTRALISATIONS this script replaces one
snippet of `ctreport.rs` (it must occur exactly once), runs `cargo test -p xtask --locked ctreport`, records the
failing tests, and restores the file (also on error). Run from the repository root:

    python3 docs/reviews/M03-evidence/ct-gate-check-neutralisation.py > docs/reviews/M03-evidence/ct-gate-check-neutralisation.txt

Python 3, standard library only; `cargo` must be on PATH.
"""
import re
import subprocess
import sys

FILE = "xtask/src/ctreport.rs"

# (what is neutralised, snippet, replacement)
NEUTRALISATIONS = [
    (
        "F15: the positive control's label is not checked",
        'if run_verdict != "CONTROL_FAIL" && !CT_CONTROL_VERDICTS.contains(&verdict) {',
        "if false {",
    ),
    (
        "F15: detection checked only when the control's label is PASS (the M2 rule)",
        'if run_verdict != "CONTROL_FAIL" && !detected {',
        'if run_verdict != "CONTROL_FAIL" && verdict == "PASS" && !detected {',
    ),
    (
        "F16: mixed crops - SUB_FLOOR_SHIFT possible next to a surely relevant crop (`!fail_sure` removed)",
        "if sub_floor_possible && !fail_sure {",
        "if sub_floor_possible {",
    ),
    (
        "F16: the target floor scaled by 1.4",
        "(expect::CT_EFFECT_FLOOR_QUANTA * q).max(expect::CT_EFFECT_FLOOR_NS / tick)\n}",
        "1.4 * (expect::CT_EFFECT_FLOOR_QUANTA * q).max(expect::CT_EFFECT_FLOOR_NS / tick)\n}",
    ),
    (
        "F16: the target floor scaled by 0.99",
        "(expect::CT_EFFECT_FLOOR_QUANTA * q).max(expect::CT_EFFECT_FLOOR_NS / tick)\n}",
        "0.99 * (expect::CT_EFFECT_FLOOR_QUANTA * q).max(expect::CT_EFFECT_FLOOR_NS / tick)\n}",
    ),
    ("F16: t-rounding margin doubled (HALF_T 1e-3)", "const HALF_T: f64 = 5e-4;", "const HALF_T: f64 = 1e-3;"),
    ("F16: t-rounding margin halved (HALF_T 2.5e-4)", "const HALF_T: f64 = 5e-4;", "const HALF_T: f64 = 2.5e-4;"),
    ("F16: t-rounding margin removed (HALF_T 0)", "const HALF_T: f64 = 5e-4;", "const HALF_T: f64 = 0.0;"),
    ("F16: Δ rounding margin doubled (HALF_4 1e-4)", "const HALF_4: f64 = 5e-5;", "const HALF_4: f64 = 1e-4;"),
    ("F16: Δ rounding margin halved (HALF_4 2.5e-5)", "const HALF_4: f64 = 5e-5;", "const HALF_4: f64 = 2.5e-5;"),
    ("F16: q_eff rounding margin doubled (HALF_Q 1e-3)", "const HALF_Q: f64 = 5e-4;", "const HALF_Q: f64 = 1e-3;"),
    ("F16: q_eff rounding margin halved (HALF_Q 2.5e-4)", "const HALF_Q: f64 = 5e-4;", "const HALF_Q: f64 = 2.5e-4;"),
    (
        "F16: control-name check removed",
        "if text(control, \"name\") != expect::CT_POSITIVE_CONTROL {",
        "if false {",
    ),
    (
        "F16: duplicate-target check removed",
        "if set.len() != names.len() || set != expected {",
        "if set != expected {",
    ),
    (
        "F17: no upper bound on a target's q_eff_ticks",
        "Some(clock.max(expect::CT_EFFECT_FLOOR_NS / tick) + 1.0)",
        "Some(f64::INFINITY.max(clock + tick))",
    ),
    (
        "F17: the bound's one-tick allowance doubled",
        "Some(clock.max(expect::CT_EFFECT_FLOOR_NS / tick) + 1.0)",
        "Some(clock.max(expect::CT_EFFECT_FLOOR_NS / tick) + 2.0)",
    ),
]

def failing_tests():
    p = subprocess.run(
        ["cargo", "test", "-p", "xtask", "--locked", "ctreport"],
        capture_output=True,
        text=True,
    )
    failed = sorted(set(re.findall(r"^test (\S+) \.\.\. FAILED$", p.stdout, re.M)))
    if p.returncode != 0 and not failed:
        return ["(build or run failure: " + (p.stderr.strip().splitlines() or ["?"])[-1] + ")"]
    return failed


def main():
    original = open(FILE, encoding="utf-8").read()
    rows = []
    try:
        base = failing_tests()
        print("baseline (all checks in place): failing tests = " + (", ".join(base) if base else "none"))
        if base:
            sys.exit("baseline is not green")
        for what, old, new in NEUTRALISATIONS:
            if original.count(old) != 1:
                sys.exit(f"{what}: snippet occurs {original.count(old)} times")
            open(FILE, "w", encoding="utf-8").write(original.replace(old, new))
            failed = failing_tests()
            rows.append((what, failed))
            print(f"{what}: failing tests = " + (", ".join(failed) if failed else "NONE"))
    finally:
        open(FILE, "w", encoding="utf-8").write(original)
    uncaught = [w for w, f in rows if not f]
    print(f"{len(rows)} neutralisations, {len(rows) - len(uncaught)} caught" + (f"; NOT caught: {uncaught}" if uncaught else ""))


if __name__ == "__main__":
    main()
