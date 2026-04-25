#!/usr/bin/env python3
"""Regression harness for scanner prompt versions.

Runs corpus test cases against a confirmation or verdict backend and
reports pass/fail for each expected verdict.

Usage:
    python3 regression/run_regression.py --backend openai/gemma4@http://localhost:8405
    python3 regression/run_regression.py --backend gemini/flash
    python3 regression/run_regression.py --backend ollama/gemma4:31b --stage confirmation
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import scan


def load_corpus(path: str = None) -> list:
    if path is None:
        path = str(Path(__file__).resolve().parent / "corpus.json")
    with open(path) as f:
        return json.load(f)


def run_verdict_test(case: dict, backend: scan.Backend) -> dict:
    profile = scan.load_profile("c_cpp")
    finding_data = case["finding"]

    prompt = profile.verdict_prompt_template.format(
        filename=case["file"],
        triage_findings=(
            f"FINDING:\nSEVERITY: {finding_data['severity']}\n"
            f"LOCATION: {finding_data['location']}\n"
            f"TYPE: {finding_data['type']}\n"
            f"DESCRIPTION: {finding_data['description']}\nEND_FINDING"
        ),
        reasoning_findings="(same as triage)",
        consensus_note="Both stages agree on this finding.",
        hypothesis_note="",
        code=case.get("snippet", ""),
    )

    raw = backend.query("", prompt)

    verdict_match = __import__("re").search(
        r"VERDICT:\s*(REPORT_IF_CONFIGURED|REPORT|UPSTREAM_HARDENING|"
        r"NEEDS_REPRODUCER|NOISE|CONFIRMED|FALSE_POSITIVE|NEEDS_CONTEXT)",
        raw,
    )
    compat = {
        "CONFIRMED": "REPORT",
        "FALSE_POSITIVE": "NOISE",
        "NEEDS_CONTEXT": "NEEDS_REPRODUCER",
    }
    actual = compat.get(verdict_match.group(1), verdict_match.group(1)) if verdict_match else "UNPARSED"

    return {
        "id": case["id"],
        "expected": case["expected_verdict"],
        "actual": actual,
        "pass": actual == case["expected_verdict"],
        "raw": raw[:500],
    }


def main():
    parser = argparse.ArgumentParser(description="Run regression corpus")
    parser.add_argument("--backend", required=True, help="Backend spec (e.g. gemini/flash)")
    parser.add_argument("--corpus", default=None, help="Path to corpus JSON")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    backend = scan.parse_backend_spec(args.backend)
    corpus = load_corpus(args.corpus)

    passed = 0
    failed = 0
    results = []

    for case in corpus:
        result = run_verdict_test(case, backend)
        results.append(result)
        status = "PASS" if result["pass"] else "FAIL"
        if result["pass"]:
            passed += 1
        else:
            failed += 1
        print(f"  [{status}] {result['id']}: expected={result['expected']}, "
              f"actual={result['actual']}")
        if args.verbose and not result["pass"]:
            print(f"    Raw: {result['raw'][:200]}")

    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed out of {len(corpus)}")
    if failed:
        print("\nFailed cases:")
        for r in results:
            if not r["pass"]:
                print(f"  - {r['id']}: expected {r['expected']}, got {r['actual']}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
