import json
import re
import subprocess
import sys
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

    def query(self, system: str, user: str, max_tokens: int = 16384) -> str:
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


def test_load_profiles_supports_multiple_names():
    profiles = scan.load_profiles("c_cpp,python,bash")
    assert [p.name for p in profiles] == ["c_cpp", "python", "bash"]
    assert ".c" in profiles[0].extensions
    assert ".py" in profiles[1].extensions
    assert ".sh" in profiles[2].extensions


def test_load_profiles_auto_expands_to_available_profiles():
    profiles = scan.load_profiles("auto")
    names = {p.name for p in profiles}
    assert "c_cpp" in names
    assert "python" in names
    assert "bash" in names


def test_find_source_files_dispatches_by_extension(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.c").write_text("int main(void) { return 0; }\n")
    (src / "tool.py").write_text("print('hi')\n")
    (src / "script.sh").write_text("#!/bin/sh\necho hi\n")
    (src / "README.txt").write_text("ignore me\n")

    files = scan.find_source_files(str(src), scan.load_profiles("c_cpp,python,bash"))
    dispatch = {f.path.name: f.profile.name for f in files}
    assert dispatch["main.c"] == "c_cpp"
    assert dispatch["tool.py"] == "python"
    assert dispatch["script.sh"] == "bash"
    assert "README.txt" not in dispatch


def test_run_pipeline_writes_session_metadata_and_stage_outputs(tmp_path, monkeypatch):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "vuln.c").write_text("int main(void) { return 0; }\n")
    (source_dir / "clean.py").write_text("print('ok')\n")

    triage = FakeBackend(
        "gemini/flash",
        file_responses={
            "vuln.c": make_finding_text("main()", "overflow", "triage hit"),
            "clean.py": "CLEAN",
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
        profile="c_cpp,python",
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
    assert metadata["profiles"] == "c_cpp,python"
    assert metadata["source_dir"] == str(source_dir)
    assert metadata["backends"] == {
        "triage": "gemini/flash",
        "reasoning": "claude/sonnet",
        "verdict": "codex/gpt-5.4",
    }

    assert (session_dir / "triage" / "vuln.c.json").exists()
    assert (session_dir / "triage" / "clean.py.json").exists()
    assert (session_dir / "reasoning" / "vuln.c.json").exists()
    assert list((session_dir / "verdict").glob("*.json"))

    assert triage.seen_files == ["vuln.c", "clean.py"]
    assert reasoning.seen_files == ["vuln.c"]
    assert result.files_scanned == 2
    assert result.files_with_findings == 1
    assert result.clean_files == ["clean.py"]
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
    assert "**Session**: 1234-session" in text


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
    c_profile = scan.load_profile("c_cpp")
    scan.run_scan_stage(
        [scan.SourceFile(source_dir / "main.c", c_profile)],
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
    c_profile = scan.load_profile("c_cpp")
    scan.run_scan_stage(
        [scan.SourceFile(source_dir / "main.c", c_profile)],
        CapturingBackend(), "reasoning", str(source_dir), session_dir,
    )
    assert len(prompts_seen) == 1
    assert "trace" in prompts_seen[0].lower() or "chain" in prompts_seen[0].lower()
    assert "quality over quantity" in prompts_seen[0].lower()


def test_mixed_profiles_use_different_prompts(tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "main.c").write_text("int main() { return 0; }\n")
    (source_dir / "tool.py").write_text("print('hi')\n")
    (source_dir / "script.sh").write_text("#!/bin/sh\necho hi\n")

    prompts_seen = {}

    class CapturingBackend(scan.Backend):
        def query(self, system, user, max_tokens=4096):
            label = user.splitlines()[0].removeprefix("SOURCE FILE: ")
            prompts_seen[label] = system
            return "CLEAN"
        def __repr__(self):
            return "test/capture"

    session_id, session_dir = scan.make_session_dir(str(tmp_path / "s"), "test")
    files = scan.find_source_files(str(source_dir), scan.load_profiles("c_cpp,python,bash"))
    scan.run_scan_stage(files, CapturingBackend(), "triage", str(source_dir), session_dir)

    assert "c/c++ code" in prompts_seen["main.c"].lower()
    assert "python application code" in prompts_seen["tool.py"].lower()
    assert "shell scripts" in prompts_seen["script.sh"].lower()


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
    """Verdict stage receives numbered findings grouped by stage."""
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
    triage_text = scan.format_findings_for_verdict(triage_items)
    reasoning_text = scan.format_findings_for_verdict(reasoning_items)
    consensus_note, hypothesis_note = scan.build_verdict_group_notes(group)

    assert "1. [High] vuln(): triage found overflow" in triage_text
    assert "1. [High] vuln(): chain: user input -> memcpy" in reasoning_text
    assert "Source: user input via argv" in reasoning_text
    assert "Sink: memcpy without bounds" in reasoning_text
    assert "Both stages independently flagged this location" in consensus_note
    assert "Multiple findings were merged into this grouped location" in hypothesis_note


def test_verdict_notes_multiple_reasoning_hypotheses():
    """Verdict gets an explicit note when reasoning produced multiple chains."""
    group = {
        "findings": [
            scan.Finding(
                severity="High", location="vuln()", type="overflow",
                description="path one", exploitation="",
                file="test.c", model="triage-model", stage="triage",
            ),
            scan.Finding(
                severity="High", location="vuln()", type="overflow",
                description="argv reaches memcpy", exploitation="",
                file="test.c", model="reason-model", stage="reasoning",
                source="argv", sink="memcpy",
            ),
            scan.Finding(
                severity="High", location="vuln()", type="overflow",
                description="env reaches strcpy", exploitation="",
                file="test.c", model="reason-model", stage="reasoning",
                source="ENV_VAR", sink="strcpy",
            ),
        ],
        "stages": {"triage", "reasoning"},
        "count": 2,
    }

    _, hypothesis_note = scan.build_verdict_group_notes(group)
    reasoning_text = scan.format_findings_for_verdict(
        [f for f in group["findings"] if f.stage == "reasoning"]
    )

    assert "2 distinct source/sink hypotheses" in hypothesis_note
    assert "1. [High] vuln(): argv reaches memcpy" in reasoning_text
    assert "2. [High] vuln(): env reaches strcpy" in reasoning_text


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


def test_stage_stats_are_computed_from_progress(tmp_path):
    session_id, session_dir = scan.make_session_dir(str(tmp_path), "pkg")
    scan.append_jsonl(session_dir / "progress.jsonl", {
        "created_at": "2026-01-01T00:00:00+00:00",
        "stage": "triage",
        "file": "a.c",
        "backend": "triage-model",
        "chunk_count": 1,
        "finding_count": 0,
    })
    scan.append_jsonl(session_dir / "progress.jsonl", {
        "created_at": "2026-01-01T00:00:01+00:00",
        "stage": "triage",
        "file": "b.c",
        "backend": "triage-model",
        "chunk_count": 1,
        "finding_count": 2,
    })
    scan.append_jsonl(session_dir / "progress.jsonl", {
        "created_at": "2026-01-01T00:00:02+00:00",
        "stage": "reasoning",
        "file": "b.c",
        "backend": "reason-model",
        "chunk_count": 1,
        "finding_count": 1,
    })

    stats = scan.compute_stage_stats(session_dir)
    assert stats["triage"]["completed_files"] == 2
    assert stats["triage"]["files_with_findings"] == 1
    assert stats["triage"]["total_findings"] == 2
    assert stats["reasoning"]["completed_files"] == 1
    assert stats["verdict"]["completed_files"] == 0
    assert session_id


def test_resume_session_reuses_cached_stage_outputs(tmp_path, monkeypatch):
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
        file_responses={"vuln.c": make_finding_text("main()", "overflow", "reasoning hit")},
    )
    backends = {
        "gemini/flash": triage,
        "claude/sonnet": reasoning,
    }
    monkeypatch.setattr(scan, "parse_backend_spec", lambda spec: backends[spec])

    initial_args = Namespace(
        source_dir=str(source_dir),
        obs_package=None,
        resume_session=None,
        package_name="pkg",
        output=str(tmp_path / "report.md"),
        json=None,
        scratch_dir=str(tmp_path / "scratch"),
        profile="c_cpp",
        triage="gemini/flash",
        reasoning="claude/sonnet",
        verdict=None,
        triage_only=True,
    )
    initial = scan.run_pipeline(initial_args)
    assert triage.seen_files == ["vuln.c", "clean.c"]

    triage.seen_files.clear()
    resumed_args = Namespace(
        source_dir=None,
        obs_package=None,
        resume_session=initial.session_dir,
        package_name=None,
        output=str(tmp_path / "report2.md"),
        json=None,
        scratch_dir=str(tmp_path / "scratch"),
        profile="c_cpp",
        triage="gemini/flash",
        reasoning="claude/sonnet",
        verdict=None,
        triage_only=True,
    )
    resumed = scan.run_pipeline(resumed_args)
    assert triage.seen_files == []
    assert resumed.session_id == initial.session_id
    assert resumed.stage_stats["triage"]["completed_files"] == 2


def test_report_includes_stage_summary(tmp_path):
    result = scan.ScanResult(
        package="pkg",
        files_scanned=2,
        files_with_findings=1,
        session_id="session",
        session_dir="/tmp/session",
        created_at="2026-04-21T12:34:56+00:00",
        stage_stats={
            "triage": {"completed_files": 2, "files_with_findings": 1, "total_findings": 2},
            "reasoning": {"completed_files": 1, "files_with_findings": 1, "total_findings": 1},
            "verdict": {"completed_files": 0, "files_with_findings": 0, "total_findings": 0},
        },
    )
    output = tmp_path / "report.md"
    scan.generate_report(result, str(output))
    text = output.read_text()
    assert "## Scan funnel" in text
    assert "**Triage**: 2 files, 1 with findings, 2 total findings" in text


def test_find_cross_references_uses_invocation_shaped_matches(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "vuln.cpp").write_text("void exec() {}\n")
    (tmp_path / "src" / "caller.cpp").write_text("int main() { exec(); }\n")
    (tmp_path / "src" / "noise.cpp").write_text(
        "void execute() {}\n"
        "// exec() in a comment should not count\n"
        "const char *s = \"exec() in a string\";\n"
    )

    finding = scan.Finding(
        severity="High",
        location="exec",
        type="command injection",
        description="desc",
        exploitation="exploit",
        file="src/vuln.cpp",
        model="claude/sonnet",
        stage="reasoning",
    )

    result = scan.find_cross_references(finding, str(tmp_path), "src/vuln.cpp")
    assert "caller.cpp:1:int main() { exec(); }" in result
    assert "noise.cpp" not in result
    assert "heuristic reference lines" in result


def test_find_cross_references_covers_supported_extensions(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "vuln.rb").write_text("def run_task; end\n")
    (tmp_path / "pkg" / "task.rake").write_text("run_task()\n")

    finding = scan.Finding(
        severity="Medium",
        location="run_task",
        type="logic bug",
        description="desc",
        exploitation="exploit",
        file="pkg/vuln.rb",
        model="claude/sonnet",
        stage="reasoning",
    )

    result = scan.find_cross_references(finding, str(tmp_path), "pkg/vuln.rb")
    assert "pkg/task.rake:1:run_task()" in result


def test_generate_report_uses_final_verdict_severity(tmp_path):
    session_dir = tmp_path / "session"
    (session_dir / "verdict").mkdir(parents=True)
    scan.write_json(
        session_dir / "verdict" / "finding.json",
        {
            "file": "src/vuln.c",
            "key": "src/vuln.c:main:overflow",
            "created_at": "2026-04-21T12:34:56+00:00",
            "verdict": "CONFIRMED",
            "real_severity": "Low",
            "verdict_raw": "VERDICT: CONFIRMED\nREAL_SEVERITY: Low\nREASONING: reachable but limited",
            "findings": [{
                "severity": "High",
                "location": "main()",
                "type": "overflow",
                "description": "bad bounds",
                "exploitation": "attacker controls input",
                "file": "src/vuln.c",
                "model": "gemini/flash",
                "stage": "triage",
                "source": "",
                "sink": "",
            }],
            "confirmation_count": 2,
            "stages": ["reasoning", "triage"],
        },
    )
    result = scan.ScanResult(
        package="pkg",
        files_scanned=1,
        files_with_findings=1,
        session_id="session",
        session_dir=str(session_dir),
        created_at="2026-04-21T12:34:56+00:00",
        stage_stats={"triage": {"completed_files": 1, "files_with_findings": 1, "total_findings": 1}},
    )

    output = tmp_path / "report.md"
    scan.generate_report(result, str(output))
    text = output.read_text()
    assert "### [Low] main()" in text
    assert "**Final severity**: Low" in text
    assert "reachable but limited" in text


def test_save_verdict_output_persists_real_severity(tmp_path):
    session_id, session_dir = scan.make_session_dir(str(tmp_path), "pkg")
    finding = scan.Finding(
        severity="High",
        location="main()",
        type="overflow",
        description="desc",
        exploitation="exploit",
        file="src/vuln.c",
        model="gemini/flash",
        stage="triage",
    )
    group = {
        "findings": [finding],
        "count": 1,
        "stages": {"triage"},
        "verdict": "CONFIRMED",
        "real_severity": "Medium",
        "verdict_raw": "VERDICT: CONFIRMED\nREAL_SEVERITY: Medium\nREASONING: tested",
    }

    scan.save_verdict_output(session_dir, group)
    payload = json.loads(next((session_dir / "verdict").rglob("*.json")).read_text())
    assert payload["real_severity"] == "Medium"


def test_main_loads_config_file(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "tool.py").write_text("print('hi')\n")
    (tmp_path / "config.toml").write_text(
        'source_dir = "src"\n'
        'triage_only = true\n'
        'profile = "python"\n'
    )

    result = subprocess.run(
        [sys.executable, str(Path(scan.__file__).resolve())],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0
    assert "Found 1 source files in src" in result.stdout
    assert "[python]" in result.stdout


def test_cli_overrides_config_file(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.c").write_text("int main(void) { return 0; }\n")
    (tmp_path / "config.toml").write_text(
        'source_dir = "src"\n'
        'triage_only = true\n'
        'profile = "python"\n'
    )

    result = subprocess.run(
        [sys.executable, str(Path(scan.__file__).resolve()), "--profile", "c_cpp"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0
    assert "Found 1 source files in src" in result.stdout
    assert "[c_cpp]" in result.stdout


def test_main_rejects_unknown_config_keys(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "tool.py").write_text("print('hi')\n")
    (tmp_path / "config.toml").write_text(
        'source_dir = "src"\n'
        'totally_wrong = true\n'
    )

    result = subprocess.run(
        [sys.executable, str(Path(scan.__file__).resolve())],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode != 0
    assert "Unknown config key(s): totally_wrong" in result.stderr


def test_main_rejects_conflicting_config_sources(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "tool.py").write_text("print('hi')\n")
    (tmp_path / "config.toml").write_text(
        'source_dir = "src"\n'
        'obs_package = "openSUSE:Factory/zypper"\n'
    )

    result = subprocess.run(
        [sys.executable, str(Path(scan.__file__).resolve())],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode != 0
    assert "mutually exclusive" in result.stderr


def test_main_rejects_wrong_config_value_types(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "tool.py").write_text("print('hi')\n")
    (tmp_path / "config.toml").write_text(
        'source_dir = "src"\n'
        'profile = 123\n'
    )

    result = subprocess.run(
        [sys.executable, str(Path(scan.__file__).resolve())],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode != 0
    assert "Config key 'profile' must be a string." in result.stderr


# ── Include / import resolution tests ──────────────────────────────────


def test_resolve_c_includes(tmp_path):
    """C include resolver finds local headers and extracts declarations."""
    # Create a mini C project
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "Util.hpp").write_text(
        '#pragma once\n'
        '#include <string>\n'
        'class Util {\n'
        '    static std::string exec(const std::string cmd);\n'
        '    static int run(char* argv[]);\n'
        '};\n'
    )
    (tmp_path / "lib" / "main.cpp").write_text(
        '#include "Util.hpp"\n'
        '#include <stdio.h>\n'
        'int main() { Util::exec("ls"); }\n'
    )

    code = (tmp_path / "lib" / "main.cpp").read_text()
    result = scan.resolve_includes(
        code, str(tmp_path), tmp_path / "lib" / "main.cpp", "c_cpp"
    )
    assert "exec" in result
    assert "Util.hpp" in result
    # System headers should NOT be resolved
    assert "stdio.h" not in result


def test_resolve_c_includes_empty_for_system_only(tmp_path):
    """No context returned when only system includes present."""
    (tmp_path / "test.c").write_text('#include <stdlib.h>\nint main() {}\n')
    result = scan.resolve_includes(
        (tmp_path / "test.c").read_text(), str(tmp_path),
        tmp_path / "test.c", "c_cpp"
    )
    assert result == ""


def test_resolve_c_includes_preserves_nested_include_paths(tmp_path):
    """Nested quoted includes should resolve the matching project path."""
    (tmp_path / "include" / "foo").mkdir(parents=True)
    (tmp_path / "src").mkdir()
    (tmp_path / "include" / "foo" / "bar.h").write_text(
        "int nested_target(void);\n"
    )
    (tmp_path / "src" / "main.cpp").write_text(
        '#include "foo/bar.h"\n'
        "int main() { return nested_target(); }\n"
    )

    code = (tmp_path / "src" / "main.cpp").read_text()
    result = scan.resolve_includes(
        code, str(tmp_path), tmp_path / "src" / "main.cpp", "c_cpp"
    )
    assert "nested_target" in result
    assert "include/foo/bar.h" in result


def test_resolve_c_includes_avoids_wrong_duplicate_basename(tmp_path):
    """Path-qualified includes should not degrade to basename-only matches."""
    (tmp_path / "include" / "foo").mkdir(parents=True)
    (tmp_path / "vendor" / "other").mkdir(parents=True)
    (tmp_path / "src").mkdir()
    (tmp_path / "include" / "foo" / "bar.h").write_text(
        "int expected_target(void);\n"
    )
    (tmp_path / "vendor" / "other" / "bar.h").write_text(
        "int wrong_target(void);\n"
    )
    (tmp_path / "src" / "main.cpp").write_text(
        '#include "foo/bar.h"\n'
        "int main() { return expected_target(); }\n"
    )

    code = (tmp_path / "src" / "main.cpp").read_text()
    result = scan.resolve_includes(
        code, str(tmp_path), tmp_path / "src" / "main.cpp", "c_cpp"
    )
    assert "expected_target" in result
    assert "wrong_target" not in result


def test_resolve_python_imports(tmp_path):
    """Python import resolver finds local modules."""
    (tmp_path / "utils.py").write_text(
        'def run_command(cmd):\n'
        '    pass\n\n'
        'class Executor:\n'
        '    def execute(self):\n'
        '        pass\n'
    )
    (tmp_path / "main.py").write_text(
        'import os\n'
        'from utils import run_command\n'
        'run_command("ls")\n'
    )

    code = (tmp_path / "main.py").read_text()
    result = scan.resolve_includes(
        code, str(tmp_path), tmp_path / "main.py", "python"
    )
    assert "run_command" in result
    assert "Executor" in result
    # stdlib should not be resolved
    assert "os" not in result or "utils" in result


def test_resolve_bash_sources(tmp_path):
    """Bash source resolver finds sourced scripts and extracts functions."""
    (tmp_path / "helpers.sh").write_text(
        '#!/bin/bash\n'
        'do_backup() {\n'
        '    tar cf /tmp/backup.tar /data\n'
        '}\n'
        'cleanup() {\n'
        '    rm -rf /tmp/work\n'
        '}\n'
    )
    (tmp_path / "main.sh").write_text(
        '#!/bin/bash\n'
        'source helpers.sh\n'
        'do_backup\n'
    )

    code = (tmp_path / "main.sh").read_text()
    result = scan.resolve_includes(
        code, str(tmp_path), tmp_path / "main.sh", "bash"
    )
    assert "do_backup" in result
    assert "cleanup" in result


def test_resolve_node_imports(tmp_path):
    """Node resolver finds local relative modules."""
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "helpers.ts").write_text(
        "export function runCommand(cmd: string) {\n"
        "  return cmd;\n"
        "}\n"
        "export class Executor {}\n"
    )
    (tmp_path / "main.ts").write_text(
        'import { runCommand } from "./lib/helpers";\n'
        "runCommand(process.argv[2]);\n"
    )

    result = scan.resolve_includes(
        (tmp_path / "main.ts").read_text(), str(tmp_path), tmp_path / "main.ts", "node"
    )
    assert "runCommand" in result
    assert "Executor" in result
    assert "lib/helpers.ts" in result


def test_resolve_ruby_requires(tmp_path):
    """Ruby resolver finds local require_relative files."""
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "helpers.rb").write_text(
        "module Helpers\n"
        "  class Runner\n"
        "  end\n"
        "end\n"
        "def perform_check\n"
        "end\n"
    )
    (tmp_path / "main.rb").write_text(
        'require_relative "lib/helpers"\n'
        "perform_check\n"
    )

    result = scan.resolve_includes(
        (tmp_path / "main.rb").read_text(), str(tmp_path), tmp_path / "main.rb", "ruby"
    )
    assert "module Helpers" in result
    assert "class Runner" in result
    assert "def perform_check" in result


def test_resolve_perl_imports(tmp_path):
    """Perl resolver finds local modules under use lib paths."""
    (tmp_path / "lib" / "App").mkdir(parents=True)
    (tmp_path / "lib" / "App" / "Util.pm").write_text(
        "package App::Util;\n"
        "sub run_command {\n"
        "    return 1;\n"
        "}\n"
        "1;\n"
    )
    (tmp_path / "main.pl").write_text(
        "use lib 'lib';\n"
        "use App::Util;\n"
    )

    result = scan.resolve_includes(
        (tmp_path / "main.pl").read_text(), str(tmp_path), tmp_path / "main.pl", "perl"
    )
    assert "package App::Util;" in result
    assert "sub run_command" in result
    assert "lib/App/Util.pm" in result


def test_resolve_rust_modules(tmp_path):
    """Rust resolver finds sibling modules referenced by mod declarations."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "helpers.rs").write_text(
        "pub fn run_command() {}\n"
        "pub struct Executor;\n"
    )
    (tmp_path / "src" / "main.rs").write_text(
        "mod helpers;\n"
        "use crate::helpers::run_command;\n"
        "fn main() { run_command(); }\n"
    )

    result = scan.resolve_includes(
        (tmp_path / "src" / "main.rs").read_text(), str(tmp_path), tmp_path / "src" / "main.rs", "rust"
    )
    assert "pub fn run_command" in result
    assert "pub struct Executor" in result
    assert "src/helpers.rs" in result


def test_resolve_unknown_profile(tmp_path):
    """Unknown profiles return empty string."""
    (tmp_path / "test.go").write_text('package main\nfunc main() {}\n')
    result = scan.resolve_includes(
        "package main\nfunc main() {}\n", str(tmp_path), tmp_path / "test.go", "go"
    )
    assert result == ""


def test_resolve_header_budget_cap(tmp_path):
    """Resolved context respects the HEADER_BUDGET limit."""
    (tmp_path / "lib").mkdir()
    # Create a large header that would exceed budget
    big_header = "class Big {\n" + "    void method_%d();\n" * 2000 + "};\n"
    big_header = big_header % tuple(range(2000))
    (tmp_path / "lib" / "big.h").write_text(big_header)
    (tmp_path / "lib" / "main.cpp").write_text('#include "big.h"\nint main() {}\n')

    code = (tmp_path / "lib" / "main.cpp").read_text()
    result = scan.resolve_includes(
        code, str(tmp_path), tmp_path / "lib" / "main.cpp", "c_cpp"
    )
    # Result should be within budget + wrapper text
    assert len(result) <= scan.HEADER_BUDGET + 200


# ── Context-exceeded recovery tests ─────────────────────────────────


def test_find_failed_files_detects_errored_triage(tmp_path):
    """Files where all chunks returned errors are detected as failed."""
    session_id, session_dir = scan.make_session_dir(str(tmp_path), "pkg")

    # File that failed: all chunks errored
    scan.save_stage_file_output(session_dir, "triage", FakeBackend("test"), "big.c", [
        {
            "chunk_index": 1,
            "label": "big.c",
            "raw_output": "[ERROR: context exceeded]",
            "findings": [],
        }
    ])

    # File that succeeded: clean output
    scan.save_stage_file_output(session_dir, "triage", FakeBackend("test"), "ok.c", [
        {
            "chunk_index": 1,
            "label": "ok.c",
            "raw_output": "CLEAN",
            "findings": [],
        }
    ])

    # File that partially failed: one chunk errored, one succeeded
    scan.save_stage_file_output(session_dir, "triage", FakeBackend("test"), "partial.c", [
        {
            "chunk_index": 1,
            "label": "partial.c (part 1/2)",
            "raw_output": "[ERROR: context exceeded]",
            "findings": [],
        },
        {
            "chunk_index": 2,
            "label": "partial.c (part 2/2)",
            "raw_output": make_finding_text("foo()", "overflow", "found it"),
            "findings": [{"severity": "High", "location": "foo()", "type": "overflow",
                         "description": "found it", "exploitation": "",
                         "file": "partial.c", "model": "test", "stage": "triage"}],
        },
    ])

    failed = scan.find_failed_files(session_dir, "triage")
    assert failed == ["big.c"]


def test_context_exceeded_rechunks_and_retries(tmp_path):
    """When a chunk hits context exceeded, it is split and retried."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    # File big enough that halving produces 2 sub-chunks
    (source_dir / "big.c").write_text("int x;\n" * 500)

    call_count = {"n": 0}

    class ContextLimitedBackend(scan.Backend):
        def query(self, system, user, max_tokens=16384):
            call_count["n"] += 1
            # First call: simulate context exceeded
            if call_count["n"] == 1:
                return "[ERROR: context exceeded]"
            # Sub-chunks succeed
            return make_finding_text("x", "overflow", "found in sub-chunk")

        def __repr__(self):
            return "test/limited"

    session_id, session_dir = scan.make_session_dir(str(tmp_path / "s"), "pkg")
    c_profile = scan.load_profile("c_cpp")
    scan.run_scan_stage(
        [scan.SourceFile(source_dir / "big.c", c_profile)],
        ContextLimitedBackend(), "triage", str(source_dir), session_dir,
    )

    # Should have re-chunked and found things
    findings = scan.load_stage_findings(session_dir, "triage")
    assert len(findings) >= 1
    assert call_count["n"] >= 3  # 1 failed + at least 2 sub-chunks

    # Should NOT be detected as failed
    failed = scan.find_failed_files(session_dir, "triage")
    assert failed == []


def test_pipeline_forwards_failed_triage_to_reasoning(tmp_path, monkeypatch):
    """Files that fail triage entirely are forwarded to reasoning."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "big.c").write_text("int main() { return 0; }\n")
    (source_dir / "small.c").write_text("int ok() { return 0; }\n")

    class FailingTriageBackend(scan.Backend):
        def __init__(self):
            self.seen_files = []

        def query(self, system, user, max_tokens=16384):
            label = user.splitlines()[0].removeprefix("SOURCE FILE: ")
            filename = label.split(" (part ", 1)[0]
            self.seen_files.append(filename)
            if "big.c" in filename:
                return "[ERROR: context exceeded]"
            return "CLEAN"

        def __repr__(self):
            return "test/failing-triage"

    class ReasoningBackend(scan.Backend):
        def __init__(self):
            self.seen_files = []

        def query(self, system, user, max_tokens=16384):
            label = user.splitlines()[0].removeprefix("SOURCE FILE: ")
            filename = label.split(" (part ", 1)[0]
            self.seen_files.append(filename)
            return make_finding_text("main()", "overflow", "reasoning found it")

        def __repr__(self):
            return "test/reasoning"

    triage_be = FailingTriageBackend()
    reasoning_be = ReasoningBackend()

    backends = {
        "test/failing-triage": triage_be,
        "test/reasoning": reasoning_be,
    }
    monkeypatch.setattr(scan, "parse_backend_spec", lambda spec: backends[spec])

    args = Namespace(
        source_dir=str(source_dir),
        obs_package=None,
        package_name="pkg",
        output=str(tmp_path / "report.md"),
        json=None,
        scratch_dir=str(tmp_path / "scratch"),
        profile="c_cpp",
        triage="test/failing-triage",
        reasoning="test/reasoning",
        verdict=None,
        triage_only=False,
    )

    result = scan.run_pipeline(args)

    # big.c failed triage but should have been forwarded to reasoning
    assert "big.c" in reasoning_be.seen_files
    # small.c was clean, should NOT go to reasoning
    assert "small.c" not in reasoning_be.seen_files
    # The reasoning finding should be in results
    assert any(f.file == "big.c" for f in result.findings)


def test_find_chunked_files(tmp_path):
    """Files that needed chunking are detected."""
    session_id, session_dir = scan.make_session_dir(str(tmp_path), "pkg")

    # Single-chunk file
    scan.save_stage_file_output(session_dir, "triage", FakeBackend("test"), "small.c", [
        {"chunk_index": 1, "label": "small.c", "raw_output": "CLEAN", "findings": []},
    ])

    # Multi-chunk file — clean but was chunked
    scan.save_stage_file_output(session_dir, "triage", FakeBackend("test"), "big.c", [
        {"chunk_index": 1, "label": "big.c (part 1/2)", "raw_output": "CLEAN", "findings": []},
        {"chunk_index": 2, "label": "big.c (part 2/2)", "raw_output": "CLEAN", "findings": []},
    ])

    chunked = scan.find_chunked_files(session_dir, "triage")
    assert chunked == ["big.c"]


def test_catchup_runs_paranoid_prompt_on_failed_files(tmp_path, monkeypatch):
    """Failed triage files get a paranoid pass via the reasoning backend."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "big.c").write_text("int main() { return 0; }\n")
    (source_dir / "small.c").write_text("int ok() { return 0; }\n")

    prompts_by_stage = {}

    class FailingTriageBackend(scan.Backend):
        def query(self, system, user, max_tokens=16384):
            label = user.splitlines()[0].removeprefix("SOURCE FILE: ")
            filename = label.split(" (part ", 1)[0]
            if "big.c" in filename:
                return "[ERROR: context exceeded]"
            return "CLEAN"

        def __repr__(self):
            return "test/failing-triage"

    class ReasoningBackend(scan.Backend):
        def __init__(self):
            self.calls = []  # (filename, is_paranoid)

        def query(self, system, user, max_tokens=16384):
            label = user.splitlines()[0].removeprefix("SOURCE FILE: ")
            # Strip chunk suffix " (part N/M)" and function suffix "::name"
            filename = label.split(" (part ", 1)[0].split("::", 1)[0]
            self.calls.append((filename, "paranoid" in system.lower()))
            return make_finding_text("main()", "overflow", "caught by catchup")

        def __repr__(self):
            return "test/reasoning"

    reasoning_be = ReasoningBackend()
    backends = {
        "test/failing-triage": FailingTriageBackend(),
        "test/reasoning": reasoning_be,
    }
    monkeypatch.setattr(scan, "parse_backend_spec", lambda spec: backends[spec])

    args = Namespace(
        source_dir=str(source_dir),
        obs_package=None,
        package_name="pkg",
        output=str(tmp_path / "report.md"),
        json=None,
        scratch_dir=str(tmp_path / "scratch"),
        profile="c_cpp",
        triage="test/failing-triage",
        reasoning="test/reasoning",
        verdict=None,
        triage_only=False,
    )

    result = scan.run_pipeline(args)

    # big.c should have been called twice: catch-up (paranoid) then reasoning (not)
    big_calls = [(f, paranoid) for f, paranoid in reasoning_be.calls if f == "big.c"]
    assert len(big_calls) == 2
    # First call was catch-up with paranoid prompt
    assert big_calls[0] == ("big.c", True)
    # Second call was reasoning with chain-tracing prompt
    assert big_calls[1] == ("big.c", False)


def test_pipeline_forwards_chunked_clean_files_to_reasoning(tmp_path, monkeypatch):
    """Clean files that were chunked in triage get forwarded to reasoning."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    # Write a file large enough to be chunked at 200 chars
    (source_dir / "big.c").write_text("int x;\n" * 100)
    (source_dir / "small.c").write_text("int ok() { return 0; }\n")

    call_log = {"triage": [], "reasoning": []}

    class SmallContextTriage(scan.Backend):
        def query(self, system, user, max_tokens=16384):
            label = user.splitlines()[0].removeprefix("SOURCE FILE: ")
            filename = label.split(" (part ", 1)[0]
            call_log["triage"].append(filename)
            return "CLEAN"

        def __repr__(self):
            return "test/triage"

    class ReasoningBE(scan.Backend):
        def query(self, system, user, max_tokens=16384):
            label = user.splitlines()[0].removeprefix("SOURCE FILE: ")
            filename = label.split(" (part ", 1)[0]
            call_log["reasoning"].append(filename)
            return make_finding_text("x", "overflow", "found by reasoning")

        def __repr__(self):
            return "test/reasoning"

    backends = {
        "test/triage": SmallContextTriage(),
        "test/reasoning": ReasoningBE(),
    }
    monkeypatch.setattr(scan, "parse_backend_spec", lambda spec: backends[spec])
    # Force chunking at 200 chars so big.c gets chunked
    monkeypatch.setattr(scan, "chunk_file", lambda code, max_chars=40000: (
        scan.chunk_file.__wrapped__(code, max_chars=200)
        if hasattr(scan.chunk_file, '__wrapped__')
        else [code[i:i+200] for i in range(0, len(code), 200)] if len(code) > 200 else [code]
    ))

    args = Namespace(
        source_dir=str(source_dir),
        obs_package=None,
        package_name="pkg",
        output=str(tmp_path / "report.md"),
        json=None,
        scratch_dir=str(tmp_path / "scratch"),
        profile="c_cpp",
        triage="test/triage",
        reasoning="test/reasoning",
        verdict=None,
        triage_only=False,
    )

    result = scan.run_pipeline(args)

    # big.c was clean in triage but chunked — should be forwarded to reasoning
    assert "big.c" in call_log["reasoning"]
    # small.c was clean and not chunked — should NOT go to reasoning
    assert "small.c" not in call_log["reasoning"]


# ── Function extractor tests ──────────────────────────────────────────


def test_extract_c_functions_finds_named_functions():
    """Extractor pulls out C functions with their signatures."""
    code = '''
#include <stdio.h>

typedef struct { int x; } Point;

static int
compute(int a, int b)
{
    return a + b;
}

void
print_point(Point *p)
{
    printf("%d\\n", p->x);
}
'''
    funcs = scan.extract_c_functions(code)
    names = [n for n, _ in funcs]
    assert "compute" in names
    assert "print_point" in names
    # Preamble should contain the typedef
    compute_body = [body for n, body in funcs if n == "compute"][0]
    assert "typedef" in compute_body
    # Function body should include signature
    assert "static int" in compute_body
    assert "return a + b" in compute_body


def test_extract_c_functions_ignores_control_flow():
    """Extractor does not confuse `if (fopen(...)) {` for a function definition."""
    code = '''
static int
process(const char *path)
{
    if (fopen(path, "r") == NULL) {
        return 1;
    }
    while (realloc(buf, 100)) {
        break;
    }
    return 0;
}
'''
    funcs = scan.extract_c_functions(code)
    names = [n for n, _ in funcs]
    assert names == ["process"]
    assert "fopen" not in names
    assert "realloc" not in names


def test_extract_c_functions_handles_kr_signature():
    """K&R-style signature split across lines is captured with its type."""
    code = '''
static int
_strbuf_reserve(struct strbuf *buffer, int add)
{
    return 0;
}
'''
    funcs = scan.extract_c_functions(code)
    assert len(funcs) == 1
    name, body = funcs[0]
    assert name == "_strbuf_reserve"
    # The full signature must be in the body
    assert "_strbuf_reserve(struct strbuf *buffer, int add)" in body
    assert "static int" in body


def test_extract_python_functions_finds_defs_and_methods():
    code = '''
import os

def top_level(x):
    return x + 1

class Widget:
    def __init__(self, name):
        self.name = name

    def greet(self):
        print(f"hello {self.name}")

async def async_func():
    await something()
'''
    funcs = scan.extract_python_functions(code)
    names = [n for n, _ in funcs]
    assert "top_level" in names
    assert "Widget.__init__" in names
    assert "Widget.greet" in names
    assert "async_func" in names


def test_extract_python_functions_includes_decorators():
    code = '''
def outer():
    pass

@decorator
@another_decorator
def decorated():
    return 1
'''
    funcs = scan.extract_python_functions(code)
    decorated_body = [body for n, body in funcs if n == "decorated"][0]
    assert "@decorator" in decorated_body
    assert "@another_decorator" in decorated_body


def test_extract_bash_functions_both_forms():
    code = '''#!/bin/bash
set -e
LOG=/tmp/log

do_backup() {
    tar cf /tmp/backup.tar /data
}

function cleanup {
    rm -rf /tmp/work
}

main() {
    do_backup
    cleanup
}
'''
    funcs = scan.extract_bash_functions(code)
    names = [n for n, _ in funcs]
    assert "do_backup" in names
    assert "cleanup" in names
    assert "main" in names


def test_extract_rust_functions_includes_impl_methods():
    code = '''
use std::io;

struct Parser;

impl Parser {
    pub fn new() -> Self {
        Parser
    }

    pub fn parse(&self, input: &str) -> Result<(), io::Error> {
        Ok(())
    }
}

pub fn standalone() -> i32 {
    42
}
'''
    funcs = scan.extract_rust_functions(code)
    names = [n for n, _ in funcs]
    assert "standalone" in names
    assert "Parser::new" in names
    assert "Parser::parse" in names


def test_extract_ruby_functions_inside_class():
    code = '''
require "json"

class Service
  def initialize(config)
    @config = config
  end

  def call(request)
    process(request)
  end

  def self.factory
    new({})
  end
end

def top_level_method(x)
  x * 2
end
'''
    funcs = scan.extract_ruby_functions(code)
    names = [n for n, _ in funcs]
    assert "top_level_method" in names
    # Class methods should be qualified
    assert any("Service#initialize" in n or "initialize" in n for n in names)
    assert any("Service#call" in n or "call" in n for n in names)


def test_extract_perl_functions():
    code = '''
use strict;
use warnings;

package MyModule;

sub new {
    my $class = shift;
    return bless {}, $class;
}

sub process ($$) {
    my ($self, $arg) = @_;
    return $arg;
}
'''
    funcs = scan.extract_perl_functions(code)
    names = [n for n, _ in funcs]
    assert "new" in names
    assert "process" in names


def test_extract_node_functions_includes_methods():
    code = '''
import fs from "fs";

function topLevel(x) {
    return x + 1;
}

export async function handler(req, res) {
    res.send("ok");
}

class Controller {
    async show(req) {
        return req.id;
    }

    static create() {
        return new Controller();
    }
}
'''
    funcs = scan.extract_node_functions(code)
    names = [n for n, _ in funcs]
    assert "topLevel" in names
    assert "handler" in names
    assert "Controller.show" in names
    assert "Controller.create" in names


def test_extract_functions_dispatch_returns_empty_for_unknown():
    """Unknown profiles return [] so caller falls back to whole-file scan."""
    assert scan.extract_functions("int main() {}", "golang") == []
    assert scan.extract_functions("int main() {}", "unknown_lang") == []


def test_extract_functions_dispatch_dispatches_by_profile():
    """Dispatch routes to the right extractor."""
    c_funcs = scan.extract_functions(
        "int foo(int x) { return x + 1; }\n", "c_cpp",
    )
    assert [n for n, _ in c_funcs] == ["foo"]

    py_funcs = scan.extract_functions(
        "def bar(x):\n    return x + 1\n", "python",
    )
    assert [n for n, _ in py_funcs] == ["bar"]


def test_extract_functions_survives_crash_in_extractor(monkeypatch):
    """Extractor exceptions don't kill the scan."""
    def boom(code):
        raise RuntimeError("parser exploded")

    monkeypatch.setitem(scan.FUNCTION_EXTRACTORS, "c_cpp", boom)
    # Should not raise — returns empty for caller to fall back
    assert scan.extract_functions("anything", "c_cpp") == []


# ── Confirmation pass tests ──────────────────────────────────────────


def test_parse_confirmation_outcome_confirmed():
    raw = (
        "OUTCOME: CONFIRMED\n"
        "REASONING: attacker controls len via config file; overflow reachable"
    )
    result = scan._parse_confirmation_outcome(raw)
    assert result["outcome"] == "CONFIRMED"
    assert "attacker controls len" in result["reasoning"]
    assert result["callers_of"] == ""


def test_parse_confirmation_outcome_false_positive():
    raw = (
        "OUTCOME: FALSE_POSITIVE\n"
        "REASONING: the caller always passes a literal constant — not reachable"
    )
    result = scan._parse_confirmation_outcome(raw)
    assert result["outcome"] == "FALSE_POSITIVE"
    assert "literal constant" in result["reasoning"]


def test_parse_confirmation_outcome_need_callers():
    raw = (
        "OUTCOME: NEED_CALLERS\n"
        "REASONING: the function is not called anywhere in this file\n"
        "CALLERS_OF: verify_password, check_auth"
    )
    result = scan._parse_confirmation_outcome(raw)
    assert result["outcome"] == "NEED_CALLERS"
    assert result["callers_of"] == "verify_password, check_auth"


def test_parse_confirmation_outcome_unparsed():
    raw = "I think this looks suspicious."
    result = scan._parse_confirmation_outcome(raw)
    assert result["outcome"] == "UNPARSED"


def test_parse_confirmation_outcome_additional_finding():
    """Confirmation may surface a side-observation as ADDITIONAL_FINDING."""
    raw = (
        "OUTCOME: FALSE_POSITIVE\n"
        "REASONING: The described off-by-one is impossible because of the "
        "strict inequality.\n"
        "ADDITIONAL_FINDING: High / check_account / Use-After-Free / "
        "read_field frees the buffer on EOF without clearing the pointer."
    )
    result = scan._parse_confirmation_outcome(raw)
    assert result["outcome"] == "FALSE_POSITIVE"
    assert "Use-After-Free" in result["additional_finding"]
    assert "read_field frees" in result["additional_finding"]
    # REASONING must stop at ADDITIONAL_FINDING, not bleed into it.
    assert "Use-After-Free" not in result["reasoning"]


def test_parse_confirmation_outcome_no_additional_finding():
    """Absence of ADDITIONAL_FINDING leaves the field empty."""
    raw = (
        "OUTCOME: CONFIRMED\n"
        "REASONING: real bug via attacker-controlled .pam_environment"
    )
    result = scan._parse_confirmation_outcome(raw)
    assert result["additional_finding"] == ""


def test_run_confirmation_pass_saves_results(tmp_path):
    """Confirmation pass writes JSON per file and returns parsed outcomes."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "foo.c").write_text("int main() { return 0; }\n")

    session_id, session_dir = scan.make_session_dir(str(tmp_path / "s"), "pkg")

    finding = scan.Finding(
        severity="High", location="main()", type="overflow",
        description="catch-up flagged this",
        exploitation="", file="foo.c",
        model="test", stage="triage",
    )

    class ConfirmBackend(scan.Backend):
        def query(self, system, user, max_tokens=16384):
            return (
                "OUTCOME: CONFIRMED\n"
                "REASONING: verified against whole file"
            )
        def __repr__(self):
            return "test/confirm"

    source_file = scan.SourceFile(source_dir / "foo.c", scan.load_profile("c_cpp"))
    results = scan.run_confirmation_pass(
        [finding], [source_file], ConfirmBackend(),
        str(source_dir), session_dir,
    )

    assert finding.key() in results
    assert results[finding.key()]["outcome"] == "CONFIRMED"
    # Per-file JSON exists
    assert (session_dir / "triage_confirm" / "foo.c.json").exists()


def test_run_confirmation_pass_triggers_caller_pass(tmp_path):
    """When confirmation says NEED_CALLERS, caller pass runs with xrefs."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "lib.c").write_text("void target(char *p) { }\n")
    (source_dir / "caller.c").write_text('int main() { target("hello"); }\n')

    session_id, session_dir = scan.make_session_dir(str(tmp_path / "s"), "pkg")

    finding = scan.Finding(
        severity="High", location="target", type="overflow",
        description="catch-up finding",
        exploitation="", file="lib.c",
        model="test", stage="triage",
    )

    class SwitchBackend(scan.Backend):
        def __init__(self):
            self.call_count = 0
        def query(self, system, user, max_tokens=16384):
            self.call_count += 1
            if self.call_count == 1:
                # First call = confirmation pass — ask for callers
                return (
                    "OUTCOME: NEED_CALLERS\n"
                    "REASONING: not called in this file\n"
                    "CALLERS_OF: target"
                )
            # Second call = caller pass — confirm
            return (
                "OUTCOME: CONFIRMED\n"
                "REASONING: caller passes attacker input"
            )
        def __repr__(self):
            return "test/switch"

    backend = SwitchBackend()
    source_files = [
        scan.SourceFile(source_dir / "lib.c", scan.load_profile("c_cpp")),
        scan.SourceFile(source_dir / "caller.c", scan.load_profile("c_cpp")),
    ]

    confirm = scan.run_confirmation_pass(
        [finding], source_files, backend, str(source_dir), session_dir,
    )
    assert confirm[finding.key()]["outcome"] == "NEED_CALLERS"

    caller_res = scan.run_caller_pass(
        [finding], confirm, backend, str(source_dir), session_dir,
    )
    assert caller_res[finding.key()]["outcome"] == "CONFIRMED"
    assert (session_dir / "triage_confirm_callers" / "lib.c.json").exists()


def test_run_caller_pass_skips_findings_without_need_callers(tmp_path):
    """Findings whose confirmation was CONFIRMED/FP are not re-asked."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "foo.c").write_text("void x() {}\n")
    session_id, session_dir = scan.make_session_dir(str(tmp_path / "s"), "pkg")

    finding = scan.Finding(
        severity="High", location="x", type="overflow", description="",
        exploitation="", file="foo.c", model="test", stage="triage",
    )
    confirmation = {finding.key(): {"outcome": "CONFIRMED", "reasoning": "ok"}}

    class ShouldNotCallBackend(scan.Backend):
        def query(self, system, user, max_tokens=16384):
            raise RuntimeError("caller pass should not run")
        def __repr__(self):
            return "test/nope"

    result = scan.run_caller_pass(
        [finding], confirmation, ShouldNotCallBackend(),
        str(source_dir), session_dir,
    )
    assert result == {}


def test_verdict_prompt_includes_confirmation_notes(tmp_path, monkeypatch):
    """Verdict prompt sees confirmation-pass reasoning when present."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "foo.c").write_text("int main() { return 0; }\n")
    session_id, session_dir = scan.make_session_dir(str(tmp_path / "s"), "pkg")

    # Seed a confirmation output
    (session_dir / "triage_confirm").mkdir(parents=True, exist_ok=True)
    scan.write_json(
        session_dir / "triage_confirm" / "foo.c.json",
        {
            "file": "foo.c",
            "stage": "triage_confirm",
            "backend": "test",
            "created_at": "2026-04-23T00:00:00+00:00",
            "evaluations": [
                {
                    "finding_key": "foo.c:main():overflow",
                    "outcome": "CONFIRMED",
                    "reasoning": "confirmation REASONING MARKER",
                    "callers_of": "",
                }
            ],
        },
    )

    prompts_sent = []

    class CapturingBackend(scan.Backend):
        def query(self, system, user, max_tokens=16384):
            prompts_sent.append(user)
            return "VERDICT: CONFIRMED\nREAL_SEVERITY: High\nREASONING: ok"
        def __repr__(self):
            return "test/verdict"

    finding = scan.Finding(
        severity="High", location="main()", type="overflow",
        description="x", exploitation="", file="foo.c",
        model="test", stage="triage",
    )
    consensus = [{"findings": [finding], "stages": {"triage"}, "count": 1}]
    profile_by_file = {"foo.c": scan.load_profile("c_cpp")}

    scan.run_verdict_stage(
        consensus, CapturingBackend(), str(source_dir),
        session_dir, profile_by_file,
    )
    assert prompts_sent
    joined = "\n".join(prompts_sent)
    assert "confirmation REASONING MARKER" in joined
    assert "Prior confirmation pass notes" in joined


# ── Regression tests for GPT review fixes ────────────────────────────


def test_fp_catchup_findings_dropped_before_reasoning(tmp_path, monkeypatch):
    """Fix #1: catch-up findings marked FALSE_POSITIVE must not reach reasoning."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "big.c").write_text("int main() { return 0; }\n")

    reasoning_calls = []

    class FailingTriage(scan.Backend):
        def query(self, system, user, max_tokens=16384):
            return "[ERROR: context exceeded]"
        def __repr__(self):
            return "test/fail-triage"

    class Reasoning(scan.Backend):
        def __init__(self):
            self.state = "catchup"
            self.calls = []

        def query(self, system, user, max_tokens=16384):
            self.calls.append(user[:120])
            if "OUTCOME:" in user or "A previous function-level scan" in user:
                # Confirmation prompt — reject the finding
                return "OUTCOME: FALSE_POSITIVE\nREASONING: unreachable in context"
            if "triage_hints" in user.lower() or "NOTE:" in user:
                reasoning_calls.append("reasoning_with_hints")
                return "CLEAN"
            if "paranoid" in system.lower():
                # Catch-up paranoid scan — flag it
                return make_finding_text("main()", "overflow", "pattern smells")
            reasoning_calls.append("reasoning_plain")
            return "CLEAN"

    reasoning = Reasoning()
    backends = {
        "test/fail-triage": FailingTriage(),
        "test/reason": reasoning,
    }
    monkeypatch.setattr(scan, "parse_backend_spec", lambda spec: backends[spec])

    args = Namespace(
        source_dir=str(source_dir),
        obs_package=None,
        package_name="pkg",
        output=str(tmp_path / "report.md"),
        json=None,
        scratch_dir=str(tmp_path / "scratch"),
        profile="c_cpp",
        triage="test/fail-triage",
        reasoning="test/reason",
        verdict=None,
        triage_only=False,
    )
    result = scan.run_pipeline(args)

    # The FP catch-up finding must not end up in result.findings
    assert not any(
        f.file == "big.c" and f.stage == "triage"
        for f in result.findings
    ), f"FP finding leaked into result: {result.findings}"


def test_caller_pass_honors_callers_of(tmp_path):
    """Fix #2: caller pass passes CALLERS_OF symbols to cross-ref search."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "lib.c").write_text("void vuln(char *p) { }\n")
    # two distinct possible callers — lib calls only one of them
    (source_dir / "a.c").write_text("int main() { wrapper_one(buf); }\n")
    (source_dir / "b.c").write_text("int main() { wrapper_two(buf); }\n")

    session_id, session_dir = scan.make_session_dir(str(tmp_path / "s"), "pkg")

    finding = scan.Finding(
        severity="High", location="vuln", type="overflow", description="",
        exploitation="", file="lib.c", model="test", stage="triage",
    )
    # Confirmation asks for callers of wrapper_one specifically
    confirmation = {
        finding.key(): {
            "outcome": "NEED_CALLERS",
            "reasoning": "vuln isn't called here directly",
            "callers_of": "wrapper_one",
        }
    }

    queries_seen = []

    class CaptureBackend(scan.Backend):
        def query(self, system, user, max_tokens=16384):
            queries_seen.append(user)
            return "OUTCOME: CONFIRMED\nREASONING: ok"
        def __repr__(self):
            return "test/capture"

    scan.run_caller_pass(
        [finding], confirmation, CaptureBackend(),
        str(source_dir), session_dir,
    )

    assert queries_seen, "caller pass didn't call the backend"
    text = queries_seen[0]
    # Caller pass should have included a.c (wrapper_one's file), not b.c
    assert "a.c" in text
    assert "b.c" not in text


def test_find_cross_references_uses_explicit_symbols(tmp_path):
    """find_cross_references honors an explicit symbols list."""
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "a.cpp").write_text("void caller() { target_fn(); }\n")
    (tmp_path / "pkg" / "b.cpp").write_text("void caller() { other_fn(); }\n")

    finding = scan.Finding(
        severity="High", location="vulnerable", type="x", description="",
        exploitation="", file="pkg/src.cpp", model="m", stage="triage",
    )
    result = scan.find_cross_references(
        finding, str(tmp_path), "pkg/src.cpp",
        symbols=["target_fn"],
    )
    assert "a.cpp" in result
    assert "target_fn" in result
    # Without symbols it would use finding.location = "vulnerable" — nothing found
    assert "b.cpp" not in result


def test_clean_files_recomputed_after_fp_drops(tmp_path, monkeypatch):
    """Fix #3: file forwarded but all findings dropped ends up in clean_files."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "forwarded.c").write_text("int main() { return 0; }\n")
    (source_dir / "always_clean.c").write_text("int ok() { return 0; }\n")

    class FailOnlyBigTriage(scan.Backend):
        def query(self, system, user, max_tokens=16384):
            label = user.splitlines()[0].removeprefix("SOURCE FILE: ")
            filename = label.split(" (part ", 1)[0].split("::", 1)[0]
            if "forwarded.c" in filename:
                return "[ERROR: context exceeded]"
            return "CLEAN"
        def __repr__(self):
            return "test/fail-triage"

    class Reasoning(scan.Backend):
        def query(self, system, user, max_tokens=16384):
            # Every second-stage answer is either CLEAN or OUTCOME: FP
            if "A previous function-level scan" in user:
                return "OUTCOME: FALSE_POSITIVE\nREASONING: not reachable"
            if "paranoid" in system.lower():
                return make_finding_text("main()", "overflow", "catch-up flagged")
            return "CLEAN"
        def __repr__(self):
            return "test/reason"

    backends = {
        "test/fail-triage": FailOnlyBigTriage(),
        "test/reason": Reasoning(),
    }
    monkeypatch.setattr(scan, "parse_backend_spec", lambda spec: backends[spec])

    args = Namespace(
        source_dir=str(source_dir),
        obs_package=None,
        package_name="pkg",
        output=str(tmp_path / "report.md"),
        json=None,
        scratch_dir=str(tmp_path / "scratch"),
        profile="c_cpp",
        triage="test/fail-triage",
        reasoning="test/reason",
        verdict=None,
        triage_only=False,
    )
    result = scan.run_pipeline(args)

    # forwarded.c got flagged by catch-up, then confirmed as FP.
    # It should land in clean_files (alongside always_clean.c).
    assert "forwarded.c" in result.clean_files, (
        f"forwarded-but-cleared file missing from clean_files: {result.clean_files}"
    )
    assert "always_clean.c" in result.clean_files


def test_triage_only_keeps_forwarded_out_of_clean(tmp_path, monkeypatch):
    """--triage-only must NOT mark forwarded (unanalyzed) files as clean.

    Regression: after recompute_clean_files() was added for later pipeline
    returns, the triage-only path erroneously called it with triage_findings
    alone, which ignored triage_forwarded and put unanalyzed files in the
    clean list.
    """
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "forwarded.c").write_text("int main() { return 0; }\n")
    (source_dir / "really_clean.c").write_text("int ok() { return 0; }\n")

    class FailOnlyBigTriage(scan.Backend):
        def query(self, system, user, max_tokens=16384):
            label = user.splitlines()[0].removeprefix("SOURCE FILE: ")
            filename = label.split(" (part ", 1)[0].split("::", 1)[0]
            if "forwarded.c" in filename:
                return "[ERROR: context exceeded]"
            return "CLEAN"
        def __repr__(self):
            return "test/fail-triage-only"

    monkeypatch.setattr(
        scan, "parse_backend_spec",
        lambda spec: FailOnlyBigTriage(),
    )

    args = Namespace(
        source_dir=str(source_dir),
        obs_package=None,
        package_name="pkg",
        output=str(tmp_path / "report.md"),
        json=None,
        scratch_dir=str(tmp_path / "scratch"),
        profile="c_cpp",
        triage="test/fail-triage-only",
        reasoning=None,
        verdict=None,
        triage_only=True,
    )
    result = scan.run_pipeline(args)

    # forwarded.c was not analyzed past triage — it must NOT be in clean_files.
    assert "forwarded.c" not in result.clean_files, (
        f"unanalyzed forwarded file wrongly in clean_files: {result.clean_files}"
    )
    # really_clean.c got a CLEAN verdict from triage, so it IS clean.
    assert "really_clean.c" in result.clean_files


# ── Contract DB tests ────────────────────────────────────────────────


def test_load_contract_pack():
    pack = scan.load_contract_pack("pam")
    assert pack.name == "pam"
    assert len(pack.contracts) >= 6
    symbols = {c.symbol for c in pack.contracts}
    assert "_pam_drop" in symbols
    assert "pam_set_item" in symbols
    assert "D(" in symbols


def test_available_contract_packs():
    names = scan.available_contract_packs()
    assert "pam" in names


def test_detect_contract_packs_matches_pam_includes(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "mod.c").write_text(
        '#include <security/pam_modules.h>\nint main() {}\n'
    )
    profile = scan.load_profile("c_cpp")
    files = [scan.SourceFile(src / "mod.c", profile)]
    packs = scan.detect_contract_packs(files)
    assert any(p.name == "pam" for p in packs)


def test_detect_contract_packs_no_match(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.c").write_text('#include <stdio.h>\nint main() {}\n')
    profile = scan.load_profile("c_cpp")
    files = [scan.SourceFile(src / "main.c", profile)]
    packs = scan.detect_contract_packs(files)
    assert packs == []


def test_contracts_for_code_filters_by_symbol():
    pack = scan.load_contract_pack("pam")
    code_with_drop = "void cleanup() { _pam_drop(ptr); }"
    relevant = scan.contracts_for_code(code_with_drop, [pack])
    symbols = {c.symbol for c in relevant}
    assert "_pam_drop" in symbols
    assert "pam_set_item" not in symbols


def test_format_contracts_prompt_nonempty():
    pack = scan.load_contract_pack("pam")
    entries = [c for c in pack.contracts if c.symbol == "_pam_drop"]
    text = scan.format_contracts_prompt(entries)
    assert "TRUSTED API CONTRACTS" in text
    assert "_pam_drop" in text
    assert "NULL" in text


def test_format_contracts_prompt_empty():
    assert scan.format_contracts_prompt([]) == ""


def test_apply_contract_prefilter_dismisses_matching():
    pack = scan.load_contract_pack("pam")
    finding = scan.Finding(
        severity="High", location="_unix_getpwnam",
        type="use-after-free",
        description="use-after-free: pointer freed via _pam_drop is later dereferenced",
        exploitation="", file="pam_unix.c", model="test", stage="triage",
    )
    kept, dismissed = scan.apply_contract_prefilter([finding], [pack])
    assert len(kept) == 0
    assert len(dismissed) == 1
    assert dismissed[0]["contract_symbol"] == "_pam_drop"


def test_apply_contract_prefilter_keeps_unrelated():
    pack = scan.load_contract_pack("pam")
    finding = scan.Finding(
        severity="High", location="_strbuf_reserve",
        type="heap-overflow",
        description="doubling branch does not account for existing length",
        exploitation="", file="pam_env.c", model="test", stage="triage",
    )
    kept, dismissed = scan.apply_contract_prefilter([finding], [pack])
    assert len(kept) == 1
    assert len(dismissed) == 0


def test_apply_contract_prefilter_requires_both_symbol_and_pattern():
    pack = scan.load_contract_pack("pam")
    finding = scan.Finding(
        severity="High", location="check_auth",
        type="use-after-free",
        description="use-after-free in authentication handler",
        exploitation="", file="pam_unix.c", model="test", stage="triage",
    )
    kept, dismissed = scan.apply_contract_prefilter([finding], [pack])
    assert len(kept) == 1
    assert len(dismissed) == 0


def test_apply_contract_prefilter_debug_macro():
    pack = scan.load_contract_pack("pam")
    finding = scan.Finding(
        severity="Medium", location="do_auth",
        type="format-string",
        description="format string vulnerability in D() debug macro — attacker input reaches printf",
        exploitation="", file="pam_unix.c", model="test", stage="triage",
    )
    kept, dismissed = scan.apply_contract_prefilter([finding], [pack])
    assert len(kept) == 0
    assert len(dismissed) == 1
    assert dismissed[0]["contract_symbol"] == "D("


def test_load_contract_packs_none():
    packs = scan.load_contract_packs("none", [])
    assert packs == []


def test_load_contract_packs_explicit():
    packs = scan.load_contract_packs("pam", [])
    assert len(packs) == 1
    assert packs[0].name == "pam"


def test_confirmation_prompt_includes_contracts(tmp_path):
    """Confirmation prompt gets contract text injected when contracts apply."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "pam_test.c").write_text(
        '#include <security/pam_modules.h>\n'
        'void cleanup() { _pam_drop(ptr); }\n'
    )
    session_id, session_dir = scan.make_session_dir(str(tmp_path / "s"), "pkg")

    finding = scan.Finding(
        severity="High", location="cleanup()",
        type="use-after-free", description="ptr used after _pam_drop",
        exploitation="", file="pam_test.c", model="test", stage="triage",
    )

    prompts_seen = []

    class CaptureBackend(scan.Backend):
        def query(self, system, user, max_tokens=16384):
            prompts_seen.append(user)
            return "OUTCOME: FALSE_POSITIVE\nREASONING: _pam_drop NULLs the pointer"
        def __repr__(self):
            return "test/capture"

    source_file = scan.SourceFile(source_dir / "pam_test.c", scan.load_profile("c_cpp"))
    packs = scan.load_contract_packs("pam", [])

    scan.run_confirmation_pass(
        [finding], [source_file], CaptureBackend(),
        str(source_dir), session_dir,
        contract_packs=packs,
    )

    assert prompts_seen
    prompt_text = prompts_seen[0]
    assert "TRUSTED API CONTRACTS" in prompt_text
    assert "_pam_drop" in prompt_text


# ── File classification tests ────────────────────────────────────────


def test_classify_file_path_production():
    assert scan.classify_file_path("modules/pam_unix/pam_unix_auth.c") == "production"
    assert scan.classify_file_path("libpam/pam_handlers.c") == "production"
    assert scan.classify_file_path("src/main.c") == "production"


def test_classify_file_path_examples():
    assert scan.classify_file_path("examples/xsh.c") == "example"
    assert scan.classify_file_path("example/demo.c") == "example"
    assert scan.classify_file_path("demos/show.py") == "example"
    assert scan.classify_file_path("contrib/helper.c") == "example"


def test_classify_file_path_tests_by_dir():
    assert scan.classify_file_path("xtests/tst-pam_dispatch.c") == "test"
    assert scan.classify_file_path("tests/check_auth.c") == "test"
    assert scan.classify_file_path("test/run.c") == "test"


def test_classify_file_path_tests_by_filename():
    assert scan.classify_file_path("modules/pam_selinux/pam_selinux_check.c") == "test"
    assert scan.classify_file_path("src/tst-overflow.c") == "test"
    assert scan.classify_file_path("src/check_password.c") == "test"
    assert scan.classify_file_path("lib/auth-retval.c") == "test"


def test_classify_file_path_benchmarks():
    assert scan.classify_file_path("benchmarks/perf.c") == "benchmark"
    assert scan.classify_file_path("bench/speed.c") == "benchmark"


def test_classify_file_path_documentation():
    assert scan.classify_file_path("doc/example.c") == "documentation"
    assert scan.classify_file_path("docs/sample.py") == "documentation"


def test_find_source_files_classifies(tmp_path):
    """find_source_files sets file_class on each file."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.c").write_text("int main() {}\n")
    examples = src / "examples"
    examples.mkdir()
    (examples / "demo.c").write_text("int demo() {}\n")
    xtests = src / "xtests"
    xtests.mkdir()
    (xtests / "tst-check.c").write_text("int test() {}\n")

    files = scan.find_source_files(str(src), scan.load_profiles("c_cpp"))
    by_name = {f.path.name: f for f in files}

    assert by_name["main.c"].file_class == "production"
    assert by_name["demo.c"].file_class == "example"
    assert by_name["tst-check.c"].file_class == "test"


def test_pipeline_suppresses_nonprod_files(tmp_path, monkeypatch):
    """Non-production files are excluded from scanning."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "main.c").write_text("int main() { return 0; }\n")
    examples = source_dir / "examples"
    examples.mkdir()
    (examples / "demo.c").write_text("int demo() { return 0; }\n")

    scanned_files = []

    class TrackingBackend(scan.Backend):
        def query(self, system, user, max_tokens=16384):
            label = user.splitlines()[0].removeprefix("SOURCE FILE: ")
            filename = label.split(" (part ", 1)[0].split("::", 1)[0]
            scanned_files.append(filename)
            return "CLEAN"
        def __repr__(self):
            return "test/tracking"

    monkeypatch.setattr(scan, "parse_backend_spec", lambda spec: TrackingBackend())

    args = Namespace(
        source_dir=str(source_dir),
        obs_package=None,
        package_name="pkg",
        output=str(tmp_path / "report.md"),
        json=None,
        scratch_dir=str(tmp_path / "scratch"),
        profile="c_cpp",
        triage="test/tracking",
        reasoning="test/tracking",
        verdict=None,
        triage_only=False,
    )
    result = scan.run_pipeline(args)

    assert any("main.c" in f for f in scanned_files)
    assert not any("demo.c" in f for f in scanned_files)

    suppress_path = Path(result.session_dir) / "suppressed_files" / "nonprod.json"
    assert suppress_path.exists()
    suppressed = scan.load_json(suppress_path)
    suppressed_paths = [f["path"] for f in suppressed["files"]]
    assert any("demo.c" in p for p in suppressed_paths)


# ── Caller-proof rule tests ──────────────────────────────────────────


def test_confirmation_prompt_has_caller_proof_rule(tmp_path):
    """Confirmation prompt includes caller-proof rule and cross-references."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "lib.c").write_text(
        "void vuln_func(char *input) { strcpy(buf, input); }\n"
    )
    (source_dir / "caller.c").write_text(
        '#include "lib.h"\n'
        'int main() { vuln_func(argv[1]); }\n'
    )
    session_id, session_dir = scan.make_session_dir(str(tmp_path / "s"), "pkg")

    finding = scan.Finding(
        severity="High", location="vuln_func",
        type="buffer-overflow",
        description="strcpy with unbounded input",
        exploitation="", file="lib.c",
        model="test", stage="triage",
    )

    prompts_seen = []

    class CaptureBackend(scan.Backend):
        def query(self, system, user, max_tokens=16384):
            prompts_seen.append(user)
            return "OUTCOME: CONFIRMED\nREASONING: caller passes argv"
        def __repr__(self):
            return "test/capture"

    source_file = scan.SourceFile(source_dir / "lib.c", scan.load_profile("c_cpp"))
    scan.run_confirmation_pass(
        [finding], [source_file], CaptureBackend(),
        str(source_dir), session_dir,
    )

    assert prompts_seen
    prompt_text = prompts_seen[0]
    assert "CALLER-PROOF RULE" in prompt_text
    assert "caller.c" in prompt_text
    assert "vuln_func" in prompt_text


def test_confirmation_prompt_caller_proof_no_callers(tmp_path):
    """When no cross-file callers exist, caller_context is empty."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "standalone.c").write_text(
        "static void internal(int x) { return; }\n"
    )
    session_id, session_dir = scan.make_session_dir(str(tmp_path / "s"), "pkg")

    finding = scan.Finding(
        severity="High", location="internal",
        type="integer-overflow",
        description="x can overflow",
        exploitation="", file="standalone.c",
        model="test", stage="triage",
    )

    prompts_seen = []

    class CaptureBackend(scan.Backend):
        def query(self, system, user, max_tokens=16384):
            prompts_seen.append(user)
            return "OUTCOME: NEED_CALLERS\nREASONING: no visible callers\nCALLERS_OF: internal"
        def __repr__(self):
            return "test/capture"

    source_file = scan.SourceFile(source_dir / "standalone.c", scan.load_profile("c_cpp"))
    scan.run_confirmation_pass(
        [finding], [source_file], CaptureBackend(),
        str(source_dir), session_dir,
    )

    assert prompts_seen
    prompt_text = prompts_seen[0]
    assert "CALLER-PROOF RULE" in prompt_text
    assert "CROSS-FILE REFERENCES" not in prompt_text


# ── Auto-dedup tests ────────────────────────────────────────────────


def _make_verdict_payload(file, location, vuln_type, severity="High"):
    return {
        "file": file,
        "verdict": "CONFIRMED",
        "real_severity": severity,
        "verdict_raw": "VERDICT: CONFIRMED\nREASONING: test",
        "stages": ["triage", "reasoning"],
        "findings": [{
            "severity": severity,
            "location": location,
            "type": vuln_type,
            "description": f"vuln in {location}",
        }],
    }


def test_dedup_clusters_same_file_and_type():
    """Multiple findings with same file+type cluster into one."""
    payloads = [
        _make_verdict_payload("pam_env.c", "_strbuf_reserve", "heap-overflow", "Critical"),
        _make_verdict_payload("pam_env.c", "_strbuf_add", "heap-overflow", "Critical"),
        _make_verdict_payload("pam_env.c", "_strbuf_add_string", "heap-overflow", "High"),
    ]
    result = scan.dedup_verdict_findings(payloads)
    assert len(result) == 1
    assert result[0]["dedup_count"] == 3
    assert len(result[0]["related_findings"]) == 2


def test_dedup_clusters_type_families():
    """buffer-overflow and heap-overflow are the same family."""
    payloads = [
        _make_verdict_payload("lib.c", "func_a", "heap-overflow"),
        _make_verdict_payload("lib.c", "func_b", "buffer-overflow"),
    ]
    result = scan.dedup_verdict_findings(payloads)
    assert len(result) == 1
    assert result[0]["dedup_count"] == 2


def test_dedup_keeps_different_files_separate():
    """Same type in different files stays separate."""
    payloads = [
        _make_verdict_payload("a.c", "func_a", "heap-overflow"),
        _make_verdict_payload("b.c", "func_b", "heap-overflow"),
    ]
    result = scan.dedup_verdict_findings(payloads)
    assert len(result) == 2


def test_dedup_keeps_different_types_separate():
    """Different type families in same file stay separate."""
    payloads = [
        _make_verdict_payload("lib.c", "func_a", "heap-overflow"),
        _make_verdict_payload("lib.c", "func_b", "format-string"),
    ]
    result = scan.dedup_verdict_findings(payloads)
    assert len(result) == 2


def test_dedup_passthrough_single():
    """Single findings pass through unchanged."""
    payloads = [_make_verdict_payload("lib.c", "func_a", "heap-overflow")]
    result = scan.dedup_verdict_findings(payloads)
    assert len(result) == 1
    assert "related_findings" not in result[0]
    assert "dedup_count" not in result[0]


def test_dedup_preserves_highest_severity():
    """Primary entry is the one with highest severity."""
    payloads = [
        _make_verdict_payload("lib.c", "func_low", "heap-overflow", "High"),
        _make_verdict_payload("lib.c", "func_high", "buffer-overflow", "Critical"),
    ]
    result = scan.dedup_verdict_findings(payloads)
    assert len(result) == 1
    primary_finding = result[0]["findings"][0]
    assert primary_finding["location"] == "func_high"
    assert result[0]["related_findings"][0]["location"] == "func_low"


# ── Actionability label tests ────────────────────────────────────────


def test_verdict_prompt_has_actionability_labels():
    """All profile verdict prompts use the new label set."""
    for name in scan.available_profile_names():
        profile = scan.load_profile(name)
        vpt = profile.verdict_prompt_template
        assert "REPORT|REPORT_IF_CONFIGURED|UPSTREAM_HARDENING|NEEDS_REPRODUCER|NOISE" in vpt, (
            f"Profile {name} missing new verdict labels"
        )
        assert "CONFIRMED|FALSE_POSITIVE|NEEDS_CONTEXT" not in vpt, (
            f"Profile {name} still has old verdict labels"
        )


def test_verdict_prompt_has_reachability_triad():
    """All profiles require SOURCE_OWNER, CONFIG_GATE, SINK_PRIVILEGE."""
    for name in scan.available_profile_names():
        profile = scan.load_profile(name)
        vpt = profile.verdict_prompt_template
        assert "SOURCE_OWNER:" in vpt, f"Profile {name} missing SOURCE_OWNER"
        assert "CONFIG_GATE:" in vpt, f"Profile {name} missing CONFIG_GATE"
        assert "SINK_PRIVILEGE:" in vpt, f"Profile {name} missing SINK_PRIVILEGE"


def test_extract_config_defaults(tmp_path):
    """Config defaults scanner finds DEFAULT_* and similar macros."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "config.h").write_text(
        '#define DEFAULT_USER_READ_ENVFILE 0\n'
        '#define DEFAULT_RETRY_COUNT 3\n'
        '#define ENABLE_DEBUG 0\n'
        'int x = 5;\n'
    )
    (src / "main.c").write_text(
        '#include "config.h"\n'
        '#define USE_FEATURE_X 1\n'
        'int main() { return 0; }\n'
    )
    result = scan.extract_config_defaults(str(src))
    assert "DEFAULT_USER_READ_ENVFILE = 0" in result
    assert "DEFAULT_RETRY_COUNT = 3" in result
    assert "ENABLE_DEBUG = 0" in result
    assert "USE_FEATURE_X = 1" in result
    assert "int x" not in result


def test_extract_config_defaults_empty(tmp_path):
    """No macros found returns empty string."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.c").write_text("int main() { return 0; }\n")
    assert scan.extract_config_defaults(str(src)) == ""


# ── Codec direction tests ────────────────────────────────────────────


def test_analyze_codec_encode_only(tmp_path):
    """XDR function used only as encoder in clnt_call."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "nis.c").write_text(
        'clnt_call(clnt, YPPASSWDPROC_UPDATE,\n'
        '    (xdrproc_t) xdr_yppasswd, &yppwd,\n'
        '    (xdrproc_t) xdr_int, &status,\n'
        '    timeout);\n'
    )
    dirs = scan.analyze_codec_directions(str(src))
    assert dirs.get("xdr_yppasswd") == "encode"
    assert dirs.get("xdr_int") == "decode"


def test_analyze_codec_explicit_direction(tmp_path):
    """Explicit XDR_ENCODE/XDR_DECODE markers."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "codec.c").write_text(
        'xdrmem_create(&xdr, buf, len, XDR_ENCODE);\n'
        'xdr_mytype(&xdr, &data);\n'
    )
    dirs = scan.analyze_codec_directions(str(src))
    assert dirs.get("xdr_mytype") == "encode"


def test_analyze_codec_no_codecs(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.c").write_text("int main() { return 0; }\n")
    assert scan.analyze_codec_directions(str(src)) == {}


def test_format_codec_directions():
    dirs = {"xdr_yppasswd": "encode", "xdr_int": "decode"}
    result = scan.format_codec_directions(dirs)
    assert "xdr_yppasswd: encode" in result
    assert "xdr_int: decode" in result
    assert "Codec direction" in result


def test_format_codec_directions_empty():
    assert scan.format_codec_directions({}) == ""


# ── Package hints tests ──────────────────────────────────────────────


def test_load_package_hints(tmp_path):
    hints_file = tmp_path / ".scanner-hints.toml"
    hints_file.write_text(
        'facts = ["ROOT_USER = 0 is a constant", "libpamc has no consumers"]\n'
        'dismiss = ["libpamc.*PAM_BP", "pam_selinux_check"]\n'
    )
    hints = scan.load_package_hints(str(tmp_path))
    assert hints is not None
    assert len(hints.facts) == 2
    assert len(hints.dismiss_patterns) == 2
    assert "ROOT_USER" in hints.facts[0]


def test_load_package_hints_missing(tmp_path):
    assert scan.load_package_hints(str(tmp_path)) is None


def test_format_hints_prompt():
    hints = scan.PackageHints(
        facts=["ROOT_USER = 0 is uid 0", "D() is debug-only"],
        dismiss_patterns=[], raw_dismissals=[],
    )
    result = scan.format_hints_prompt(hints)
    assert "PACKAGE-SPECIFIC FACTS" in result
    assert "ROOT_USER" in result


def test_format_hints_prompt_none():
    assert scan.format_hints_prompt(None) == ""


def test_apply_hints_prefilter_dismisses():
    hints = scan.PackageHints(
        facts=[],
        dismiss_patterns=[re.compile(r"pam_selinux_check", re.IGNORECASE)],
        raw_dismissals=["pam_selinux_check"],
    )
    finding = scan.Finding(
        severity="High", location="pam_selinux_check",
        type="privilege-escalation",
        description="setuid binary allows privilege escalation",
        exploitation="", file="pam_selinux_check.c", model="test", stage="triage",
    )
    kept, dismissed = scan.apply_hints_prefilter([finding], hints)
    assert len(kept) == 0
    assert len(dismissed) == 1
    assert "pam_selinux_check" in dismissed[0]["hint_pattern"]


def test_apply_hints_prefilter_keeps_unmatched():
    hints = scan.PackageHints(
        facts=[],
        dismiss_patterns=[re.compile(r"pam_selinux_check", re.IGNORECASE)],
        raw_dismissals=["pam_selinux_check"],
    )
    finding = scan.Finding(
        severity="High", location="_strbuf_reserve",
        type="heap-overflow",
        description="doubling branch overflow",
        exploitation="", file="pam_env.c", model="test", stage="triage",
    )
    kept, dismissed = scan.apply_hints_prefilter([finding], hints)
    assert len(kept) == 1
    assert len(dismissed) == 0


def test_apply_hints_prefilter_none_hints():
    finding = scan.Finding(
        severity="High", location="func",
        type="overflow", description="x",
        exploitation="", file="a.c", model="test", stage="triage",
    )
    kept, dismissed = scan.apply_hints_prefilter([finding], None)
    assert len(kept) == 1
    assert len(dismissed) == 0


# ── Regression corpus tests ──────��───────────────────────────────────


def test_regression_corpus_loads():
    """Corpus JSON is valid and has the required fields."""
    corpus_path = Path(__file__).resolve().parent.parent / "regression" / "corpus.json"
    with corpus_path.open() as f:
        corpus = json.load(f)
    assert len(corpus) >= 10
    verdicts = set()
    for case in corpus:
        assert "id" in case
        assert "expected_verdict" in case
        assert "finding" in case
        assert "snippet" in case or "why_noise" in case or "why_upstream_hardening" in case
        verdicts.add(case["expected_verdict"])
    assert "REPORT" in verdicts
    assert "NOISE" in verdicts
    assert "REPORT_IF_CONFIGURED" in verdicts
    assert "NEEDS_REPRODUCER" in verdicts
    assert "UPSTREAM_HARDENING" in verdicts


# ── Install metadata tests ───────────────────────────────────────────


def test_extract_meson_install_metadata(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "meson.build").write_text(
        "executable('pam_helper', 'helper.c',\n"
        "  install: true,\n"
        "  install_mode: ['rwsr-xr-x', 'root', 'root'],\n"
        ")\n"
        "executable('pam_check', 'check.c',\n"
        "  install: false,\n"
        ")\n"
    )
    meta = scan.extract_meson_install_metadata(str(src))
    assert len(meta) == 2
    helper = [m for m in meta if m["name"] == "pam_helper"][0]
    assert helper["installed"] is True
    assert helper["setuid"] is True
    check = [m for m in meta if m["name"] == "pam_check"][0]
    assert check["installed"] is False
    assert check["setuid"] is False


def test_extract_meson_no_meson(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.c").write_text("int main() {}\n")
    assert scan.extract_meson_install_metadata(str(src)) == []


def test_extract_spec_install_metadata(tmp_path):
    src = tmp_path / "pkg"
    src.mkdir()
    (src / "pam.spec").write_text(
        "%files\n"
        "%attr(4755,root,root) /usr/sbin/unix_chkpwd\n"
        "/usr/lib64/security/pam_unix.so\n"
        "%attr(0755,root,root) /usr/libexec/pam_helper\n"
        "\n"
        "%changelog\n"
    )
    meta = scan.extract_spec_install_metadata(str(src))
    assert len(meta) == 3
    chkpwd = [m for m in meta if "unix_chkpwd" in m["path"]][0]
    assert chkpwd["setuid"] is True
    assert chkpwd["mode"] == "4755"
    helper = [m for m in meta if "pam_helper" in m["path"]][0]
    assert helper["setuid"] is False


def test_format_install_metadata():
    meson = [{"name": "helper", "installed": True, "setuid": True, "source": "meson.build"}]
    spec = [{"path": "/usr/sbin/prog", "mode": "4755", "user": "root",
             "group": "root", "setuid": True, "source": "pkg.spec"}]
    result = scan.format_install_metadata(meson, spec)
    assert "Install metadata" in result
    assert "helper: installed (SETUID)" in result
    assert "/usr/sbin/prog" in result


def test_format_install_metadata_empty():
    assert scan.format_install_metadata([], []) == ""
