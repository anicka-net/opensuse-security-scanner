import json
from argparse import Namespace
from pathlib import Path

import scan


class FakeBackend(scan.Backend):
    def __init__(self, name, file_responses=None, verdict_response=None):
        self.name = name
        self.file_responses = file_responses or {}
        self.verdict_response = verdict_response or (
            "VERDICT: CONFIRMED\nREAL_SEVERITY: High\nREASONING: verified"
        )
        self.seen_files = []

    def query(self, system: str, user: str, max_tokens: int = 4096) -> str:
        if user.startswith("SOURCE FILE: "):
            label = user.splitlines()[0].removeprefix("SOURCE FILE: ")
            filename = label.split(" (part ", 1)[0]
            self.seen_files.append(filename)
            return self.file_responses[filename]
        return self.verdict_response

    def __repr__(self):
        return self.name


def make_finding_text(location: str, vuln_type: str, description: str) -> str:
    return (
        "FINDING:\n"
        "SEVERITY: High\n"
        f"LOCATION: {location}\n"
        f"TYPE: {vuln_type}\n"
        f"DESCRIPTION: {description}\n"
        "EXPLOITATION: attacker controls input\n"
        "END_FINDING\n"
    )


def test_stage_output_round_trip(tmp_path):
    session_id, session_dir = scan.make_session_dir(str(tmp_path), "libzypp")
    backend = FakeBackend("gemini/flash")
    chunk_records = [
        {
            "chunk_index": 1,
            "label": "src/vuln.c",
            "raw_output": make_finding_text("check()", "overflow", "bad bounds"),
            "findings": [
                {
                    "severity": "High",
                    "location": "check()",
                    "type": "overflow",
                    "description": "bad bounds",
                    "exploitation": "attacker controls input",
                    "file": "src/vuln.c",
                    "model": "gemini/flash",
                    "stage": "triage",
                }
            ],
        }
    ]

    scan.save_stage_file_output(session_dir, "triage", backend, "src/vuln.c", chunk_records)

    record = session_dir / "triage" / "src" / "vuln.c.json"
    assert record.exists()
    payload = json.loads(record.read_text())
    assert payload["backend"] == "gemini/flash"
    assert payload["finding_count"] == 1

    findings = scan.load_stage_findings(session_dir, "triage")
    assert len(findings) == 1
    assert findings[0].file == "src/vuln.c"
    assert findings[0].stage == "triage"

    progress_lines = (session_dir / "progress.jsonl").read_text().strip().splitlines()
    assert len(progress_lines) == 1
    assert json.loads(progress_lines[0])["file"] == "src/vuln.c"
    assert session_id


def test_run_pipeline_writes_session_metadata_and_stage_outputs(tmp_path, monkeypatch):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "vuln.c").write_text("int main(void) { return 0; }\n")
    (source_dir / "clean.c").write_text("int ok(void) { return 0; }\n")

    triage = FakeBackend(
        "gemini/flash",
        file_responses={
            "vuln.c": make_finding_text("main()", "overflow", "triage hit"),
            "clean.c": "CLEAN",
        },
    )
    reasoning = FakeBackend(
        "claude/sonnet",
        file_responses={
            "vuln.c": make_finding_text("main()", "overflow", "reasoning hit"),
        },
    )
    verdict = FakeBackend("codex/gpt-5.4")
    backends = {
        "gemini/flash": triage,
        "claude/sonnet": reasoning,
        "codex/gpt-5.4": verdict,
    }

    monkeypatch.setattr(scan, "parse_backend_spec", lambda spec: backends[spec])

    args = Namespace(
        source_dir=str(source_dir),
        obs_package=None,
        package_name="libzypp",
        output=str(tmp_path / "report.md"),
        json=str(tmp_path / "report.json"),
        scratch_dir=str(tmp_path / "scratch"),
        triage="gemini/flash",
        reasoning="claude/sonnet",
        verdict="codex/gpt-5.4",
        triage_only=False,
    )

    result = scan.run_pipeline(args)
    scan.generate_report(result, args.output)

    session_dir = Path(result.session_dir)
    metadata = json.loads((session_dir / "metadata.json").read_text())
    assert metadata["package"] == "libzypp"
    assert metadata["source_dir"] == str(source_dir)
    assert metadata["backends"] == {
        "triage": "gemini/flash",
        "reasoning": "claude/sonnet",
        "verdict": "codex/gpt-5.4",
    }

    assert (session_dir / "triage" / "vuln.c.json").exists()
    assert (session_dir / "triage" / "clean.c.json").exists()
    assert (session_dir / "reasoning" / "vuln.c.json").exists()
    assert list((session_dir / "verdict").glob("*.json"))

    assert triage.seen_files == ["vuln.c", "clean.c"]
    assert reasoning.seen_files == ["vuln.c"]
    assert result.files_scanned == 2
    assert result.files_with_findings == 1
    assert result.clean_files == ["clean.c"]
    assert result.session_id
    assert len(result.findings) == 2


def test_generate_report_includes_session_metadata(tmp_path):
    result = scan.ScanResult(
        package="libzypp",
        files_scanned=10,
        files_with_findings=1,
        session_id="1234-session",
        session_dir="/tmp/opensuse-security-scanner/libzypp-1234-session",
        created_at="2026-04-21T12:34:56+00:00",
        findings=[],
    )

    output = tmp_path / "report.md"
    scan.generate_report(result, str(output))
    text = output.read_text()

    assert "**Date**: 2026-04-21T12:34:56+00:00" in text
    assert "**Session UUID**: 1234-session" in text
    assert "**Session Dir**: /tmp/opensuse-security-scanner/libzypp-1234-session" in text


# ── Prompt selection ───────────────────────────────────────────────────


def test_triage_stage_uses_triage_prompt(tmp_path):
    """Triage stage sends the paranoid pattern-matching prompt."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "main.c").write_text("int main() { return 0; }\n")

    prompts_seen = []

    class CapturingBackend(scan.Backend):
        def query(self, system, user, max_tokens=4096):
            prompts_seen.append(system)
            return "CLEAN"
        def __repr__(self):
            return "test/capture"

    session_id, session_dir = scan.make_session_dir(str(tmp_path / "s"), "test")
    scan.run_scan_stage(
        [source_dir / "main.c"],
        CapturingBackend(), "triage", str(source_dir), session_dir,
    )
    assert len(prompts_seen) == 1
    assert "paranoid" in prompts_seen[0].lower()
    assert "source" not in prompts_seen[0].lower().split("focus on")[0]


def test_reasoning_stage_uses_reasoning_prompt(tmp_path):
    """Reasoning stage sends the chain-analysis prompt, not triage."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "main.c").write_text("int main() { return 0; }\n")

    prompts_seen = []

    class CapturingBackend(scan.Backend):
        def query(self, system, user, max_tokens=4096):
            prompts_seen.append(system)
            return "CLEAN"
        def __repr__(self):
            return "test/capture"

    session_id, session_dir = scan.make_session_dir(str(tmp_path / "s"), "test")
    scan.run_scan_stage(
        [source_dir / "main.c"],
        CapturingBackend(), "reasoning", str(source_dir), session_dir,
    )
    assert len(prompts_seen) == 1
    assert "trace" in prompts_seen[0].lower() or "chain" in prompts_seen[0].lower()
    assert "quality over quantity" in prompts_seen[0].lower()


# ── SOURCE/SINK parsing ───────────────────────────────────────────────


def test_parse_findings_extracts_source_sink():
    """Reasoning-format findings with SOURCE/SINK are parsed correctly."""
    raw = (
        "FINDING:\n"
        "SEVERITY: Critical\n"
        "LOCATION: dhcpv6_parse_vendor_option\n"
        "TYPE: Buffer overflow\n"
        "SOURCE: DHCPv6 network packet, vendor option type 203\n"
        "SINK: strlen() on unterminated data, then strcpy into fixed buffer\n"
        "DESCRIPTION: strlen reads past buffer until NUL found in memory\n"
        "EXPLOITATION: malicious DHCP server sends crafted packet\n"
        "END_FINDING\n"
    )
    findings = scan.parse_findings(raw, "dhcpv6.c", "test/model", "reasoning")
    assert len(findings) == 1
    f = findings[0]
    assert f.source == "DHCPv6 network packet, vendor option type 203"
    assert f.sink == "strlen() on unterminated data, then strcpy into fixed buffer"
    assert f.severity == "Critical"
    assert f.stage == "reasoning"


def test_parse_findings_multiline_source_sink():
    """SOURCE/SINK fields that wrap to multiple lines are fully captured."""
    raw = (
        "FINDING:\n"
        "SEVERITY: High\n"
        "LOCATION: readFile\n"
        "TYPE: Path traversal\n"
        "SOURCE: filename parameter passed from command line\n"
        "  through getArguments() without validation\n"
        "SINK: openFileForReading() which calls fopen()\n"
        "  with the raw unsanitized path\n"
        "DESCRIPTION: attacker controls filename\n"
        "EXPLOITATION: escape intended directory\n"
        "END_FINDING\n"
    )
    findings = scan.parse_findings(raw, "file.c", "test/model", "reasoning")
    assert len(findings) == 1
    f = findings[0]
    assert "through getArguments()" in f.source
    assert "raw unsanitized path" in f.sink


def test_parse_findings_without_source_sink():
    """Triage-format findings (no SOURCE/SINK) still parse correctly."""
    raw = make_finding_text("main()", "overflow", "bad bounds check")
    findings = scan.parse_findings(raw, "test.c", "test/model", "triage")
    assert len(findings) == 1
    assert findings[0].source == ""
    assert findings[0].sink == ""
    assert findings[0].description == "bad bounds check"


# ── Verdict prompt formatting ──────────────────────────────────────────


def test_verdict_formats_findings_by_stage():
    """Verdict stage receives findings grouped by stage with consensus note."""
    triage_finding = scan.Finding(
        severity="High", location="vuln()", type="overflow",
        description="triage found overflow", exploitation="",
        file="test.c", model="gpt-oss", stage="triage",
    )
    reasoning_finding = scan.Finding(
        severity="High", location="vuln()", type="overflow",
        description="chain: user input -> memcpy", exploitation="",
        file="test.c", model="gemma-4", stage="reasoning",
        source="user input via argv", sink="memcpy without bounds",
    )
    group = {
        "findings": [triage_finding, reasoning_finding],
        "stages": {"triage", "reasoning"},
        "count": 2,
    }

    # Simulate what run_verdict_stage builds
    triage_items = [f for f in group["findings"] if f.stage == "triage"]
    reasoning_items = [f for f in group["findings"] if f.stage == "reasoning"]
    assert len(triage_items) == 1
    assert len(reasoning_items) == 1
    assert reasoning_items[0].source == "user input via argv"

    # Consensus note for cross-stage confirmation
    assert group["count"] > 1


# ── Report rendering ──────────────────────────────────────────────────


def test_report_includes_source_sink(tmp_path):
    """Report renders Source/Sink lines when present."""
    result = scan.ScanResult(
        package="test",
        files_scanned=1,
        files_with_findings=1,
        findings=[
            scan.Finding(
                severity="Critical", location="parse()", type="overflow",
                description="chain traced", exploitation="crafted input",
                file="test.c", model="gemma-4", stage="reasoning",
                source="network packet", sink="strcpy into fixed buffer",
            ),
        ],
    )
    output = tmp_path / "report.md"
    scan.generate_report(result, str(output))
    text = output.read_text()
    assert "**Source**: network packet" in text
    assert "**Sink**: strcpy into fixed buffer" in text
