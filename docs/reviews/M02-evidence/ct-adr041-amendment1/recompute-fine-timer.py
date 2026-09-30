# SPDX-License-Identifier: AGPL-3.0-or-later
"""Recompute the ADR-041 Amendment 1 verdicts of the two fine-timer ct reports from their recorded per-crop statistics.

M2 review F13: this is the recomputation behind the table "Fine-timer case (recomputed from recorded per-crop
statistics)" of README.md in this directory. It reads the per-crop class statistics that the bench recorded in

- PR run 36651079069 (`0804f60`): ../ct-report-x86_64-linux-pr-run-36651079069-0804f60-FAIL.json
- linux-ct 36660962382 (`a2095a9`, the key-swap branch): ../ct-keyswap/linux-a2095a9-run36660962382.json

and applies the rule the bench's `decide` applies under Amendment 1: per crop (raw, p50, p75, p90, p95, p99), a shift
is reproduced if |t| > 4.5 in both measurements with the same sign, and relevant if |Δ| reaches the effect floor
max(1 q_eff, 10 ns) in both; FAIL if a reproduced crop is relevant, SUB_FLOOR_SHIFT if a crop is reproduced but none
is relevant, PASS otherwise; the deciding crop is the one with the largest min(|t1|, |t2|) (the first such crop in
report order on a tie). Δ in ns is the recorded Δ in ticks times the clock's tick length. The positive control and the
key-swap branch's two extra targets are not part of the table; the second report's sensitivity control is added as
its last row. No new measurement.

Run from the repository root (Python 3, standard library only):

    python3 docs/reviews/M02-evidence/ct-adr041-amendment1/recompute-fine-timer.py

It prints the table in the README's Markdown layout (the same output is committed as recompute-fine-timer.txt).
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPORTS = [
    ("PR 36651079069 (0804f60)", os.path.join(HERE, "..", "ct-report-x86_64-linux-pr-run-36651079069-0804f60-FAIL.json")),
    ("linux-ct 36660962382 (a2095a9)", os.path.join(HERE, "..", "ct-keyswap", "linux-a2095a9-run36660962382.json")),
]
# the non-control targets of the M2 gate, in report order
TARGETS = [
    "tag_compare",
    "msg_open_reject",
    "caead_open_reject",
    "sas",
    "caead_derive",
    "caead_aead_reject",
    "caead_com_compare",
    "caead_open_reject_samekey",
]
THRESHOLD = 4.5  # CT_THRESHOLDS (ADR-041 (1))
FLOOR_QUANTA = 1.0  # CT_EFFECT_FLOOR_QUANTA (ADR-041 (2))
FLOOR_NS = 10.0  # CT_EFFECT_FLOOR_NS (ADR-041 Amendment 1 (1))


def floor_ns(measurement, tick):
    return max(FLOOR_QUANTA * measurement["q_eff_ticks"] * tick, FLOOR_NS)


def decide(first, second, tick):
    """(verdict, crop, (Δ1 ns, Δ2 ns), (floor1 ns, floor2 ns)) under Amendment 1."""
    f1, f2 = floor_ns(first, tick), floor_ns(second, tick)
    reproduced = None
    relevant = None
    for crop, s1 in first["crops"].items():
        s2 = second["crops"][crop]
        t1, t2 = s1["t"], s2["t"]
        if abs(t1) <= THRESHOLD or abs(t2) <= THRESHOLD or (t1 < 0) != (t2 < 0):
            continue
        strength = min(abs(t1), abs(t2))
        if reproduced is None or strength > reproduced[0]:
            reproduced = (strength, crop)
        d1, d2 = s1["delta"] * tick, s2["delta"] * tick
        if abs(d1) >= f1 and abs(d2) >= f2 and (relevant is None or strength > relevant[0]):
            relevant = (strength, crop)
    if relevant is not None:
        verdict, crop = "FAIL", relevant[1]
    elif reproduced is not None:
        verdict, crop = "SUB_FLOOR_SHIFT", reproduced[1]
    else:
        return "PASS", None, None, (f1, f2)
    deltas = (first["crops"][crop]["delta"] * tick, second["crops"][crop]["delta"] * tick)
    return verdict, crop, deltas, (f1, f2)


def main():
    print("| report | target | ADR-041 verdict (recorded) | Amendment 1 verdict (recomputed) | crop | Δ1 / Δ2 (ns) | floor (ns) | Δ1 / Δ2 (floors) |")
    print("|---|---|---|---|---|---|---|---|")
    for label, path in REPORTS:
        with open(path, encoding="utf-8") as f:
            report = json.load(f)
        tick = report["clock"]["tick_ns"]
        results = {r["name"]: r for r in report["results"]}
        for name in TARGETS:
            r = results[name]
            verdict, crop, deltas, floors = decide(r["first"], r["second"], tick)
            if crop is None:
                print(f"| {label} | `{name}` | {r['verdict']} | {verdict} | — | — | — | — |")
                continue
            d1, d2 = deltas
            f1, f2 = floors
            print(
                f"| {label} | `{name}` | {r['verdict']} | {verdict} | {crop} | {d1:+.2f} / {d2:+.2f} | "
                f"{f1:.2f} / {f2:.2f} | {d1 / f1:+.3f} / {d2 / f2:+.3f} |"
            )
        control = report.get("sensitivity_control")
        if control:
            m = control["measurement"]
            raw = m["crops"]["raw"]["delta"] * tick
            fl = floor_ns(m, tick)
            state = "reached" if raw >= fl else "below the floor"
            print(f"| {label} | `min_leak_control` | (report only) | {state} | raw | {raw:+.2f} | {fl:.2f} | {raw / fl:+.2f} |")


if __name__ == "__main__":
    main()
