#!/usr/bin/env python3
"""Regression harness for scanner prompt versions.

Runs corpus test cases against a confirmation or verdict backend and
reports pass/fail for each expected verdict.

Usage:
    python3 regression/run_regression.py --backend openai/gemma3@http://localhost:8405
    python3 regression/run_regression.py --backend gemini/flash
    python3 regression/run_regression.py --backend ollama/gemma4:31b --stage confirmation
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import scan


def load_corpus(path: str = None) -> list:
    if path is None:
        path = str(Path(__file__).resolve().parent / "corpus.json")
    with open(path) as f:
        return json.load(f)


def _build_contracts_section(case: dict) -> str:
    """Load contract packs relevant to the corpus case and format them."""
    contracts_dir = Path(__file__).resolve().parent.parent / "contracts"
    if not contracts_dir.exists():
        return ""
    packs = []
    for json_file in contracts_dir.glob("*.json"):
        try:
            pack = scan.load_contract_pack(json_file.stem)
            packs.append(pack)
        except Exception:
            continue
    if not packs:
        return ""
    snippet = case.get("snippet", "")
    desc = case["finding"].get("description", "")
    code_text = f"{snippet}\n{desc}"
    entries = scan.contracts_for_code(code_text, packs)
    return scan.format_contracts_prompt(entries)


def _load_hints_from_file(toml_path: Path) -> "scan.PackageHints | None":
    """Load a hints file directly (not from source_dir convention)."""
    if not toml_path.exists():
        return None
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib
    with toml_path.open("rb") as f:
        data = tomllib.load(f)
    facts = list(data.get("facts", []))
    raw_dismissals = list(data.get("dismiss", []))
    patterns = []
    for pat in raw_dismissals:
        try:
            patterns.append(re.compile(pat, re.IGNORECASE))
        except re.error:
            pass
    return scan.PackageHints(facts=facts, dismiss_patterns=patterns,
                             raw_dismissals=raw_dismissals)


def _build_hints_section(case: dict) -> str:
    """Load hints relevant to the corpus case."""
    hints_dir = Path(__file__).resolve().parent.parent / "hints"
    if not hints_dir.exists():
        return ""
    sections = []
    for toml_file in hints_dir.glob("*.scanner-hints.toml"):
        hints = _load_hints_from_file(toml_file)
        if hints:
            sec = scan.format_hints_prompt(hints)
            if sec:
                sections.append(sec)
    return "\n".join(sections)


def _build_annotation(case: dict) -> str:
    """Build contract/hint annotations for this specific finding."""
    desc = case["finding"].get("description", "")
    loc = case["finding"].get("location", "")
    filepath = case.get("file", "")
    text = f"{filepath} {loc} {desc}".lower()

    annotations = []
    contracts_dir = Path(__file__).resolve().parent.parent / "contracts"
    if contracts_dir.exists():
        for json_file in contracts_dir.glob("*.json"):
            try:
                pack = scan.load_contract_pack(json_file.stem)
                for entry in pack.contracts:
                    if entry.symbol.lower() in text:
                        for pat in entry.dismiss_patterns:
                            if pat.search(text):
                                annotations.append(
                                    f"NOTE — a known API contract may apply: "
                                    f"{entry.symbol} ({entry.kind}): {entry.behavior}  "
                                    f"Verify whether this contract fully rules out "
                                    f"the described mechanism."
                                )
                                break
                        if annotations:
                            break
            except Exception:
                continue

    hints_dir = Path(__file__).resolve().parent.parent / "hints"
    if hints_dir.exists():
        for toml_file in hints_dir.glob("*.scanner-hints.toml"):
            hints = _load_hints_from_file(toml_file)
            if hints:
                for pat in hints.dismiss_patterns:
                    if pat.search(text):
                        annotations.append(
                            f"NOTE — a package hint suggests this may be noise "
                            f"(pattern: {pat.pattern}). Verify against the code."
                        )
                        break

    return "\n".join(annotations)


def run_verdict_test(case: dict, backend: scan.Backend) -> dict:
    profile = scan.load_profile("c_cpp")
    finding_data = case["finding"]

    contracts_section = _build_contracts_section(case)
    hints_section = _build_hints_section(case)
    annotation = _build_annotation(case)

    description = finding_data["description"]
    if annotation:
        description = f"{description}\n\n{annotation}"

    prompt = profile.verdict_prompt_template.format(
        filename=case["file"],
        triage_findings=(
            f"FINDING:\nSEVERITY: {finding_data['severity']}\n"
            f"LOCATION: {finding_data['location']}\n"
            f"TYPE: {finding_data['type']}\n"
            f"DESCRIPTION: {description}\nEND_FINDING"
        ),
        reasoning_findings="(same as triage)",
        consensus_note="Both stages agree on this finding.",
        hypothesis_note="",
        code=case.get("snippet", ""),
    )

    if contracts_section or hints_section:
        prompt = f"{contracts_section}{hints_section}\n{prompt}"

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
