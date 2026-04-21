import json
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
    assert "## Stage Summary" in text
    assert "- triage: 2 completed, 1 with findings, 2 total findings" in text


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
