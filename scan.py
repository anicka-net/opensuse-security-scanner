#!/usr/bin/env python3
"""
openSUSE Security Scanner — Multi-model vulnerability scanning pipeline.

Three-stage pipeline with pluggable backends at each stage:

  triage      → Fast pass, flags suspicious files (default: GPT-OSS 20B via ollama)
  reasoning   → Deep analysis on flagged files (default: Gemma 4 31B via ollama)
  verdict     → Verifies exploitability, eliminates FPs (default: Claude via CLI)

Every stage can use any backend: ollama, openai-compatible (llama.cpp, vLLM),
claude, gemini, or codex. Configure via CLI flags or config file.

Usage:
  # Defaults (ollama triage + reasoning, no verdict)
  scan.py --source-dir /path/to/src

  # Full pipeline with Claude verdict
  scan.py --source-dir /path/to/src --verdict claude/opus

  # All stages via ollama (big GPU setup)
  scan.py --source-dir /path/to/src \\
    --triage ollama/gpt-oss-20b \\
    --reasoning ollama/kimi-k2 \\
    --verdict ollama/kimi-k2

  # Frontier models everywhere (token-burning mode)
  scan.py --source-dir /path/to/src \\
    --triage gemini/flash \\
    --reasoning claude/sonnet \\
    --verdict claude/opus

  # llama.cpp server on custom port
  scan.py --source-dir /path/to/src \\
    --triage openai/gpt-oss-20b@http://localhost:8404

  # OBS package
  scan.py --obs-package openSUSE:Factory/zypper

  # Single stage only
  scan.py --source-dir /path/to/src --triage-only
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

import requests


ROOT_DIR = Path(__file__).resolve().parent
PROFILES_DIR = ROOT_DIR / "profiles"


# ── Profiles ────────────────────────────────────────────────────────────


# ── Data types ──────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str
    location: str
    type: str
    description: str
    exploitation: str
    file: str
    model: str
    stage: str
    source: str = ""   # reasoning stage: where untrusted data enters
    sink: str = ""     # reasoning stage: where the dangerous op is

    def key(self) -> str:
        """Normalized key for dedup/consensus."""
        return f"{self.file}:{self.location}:{self.type}".lower()


@dataclass
class ScanResult:
    package: str
    files_scanned: int
    files_with_findings: int
    session_id: str = ""
    session_dir: str = ""
    created_at: str = ""
    findings: List[Finding] = field(default_factory=list)
    clean_files: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    stage_stats: dict = field(default_factory=dict)


@dataclass
class Profile:
    name: str
    extensions: List[str]
    triage_prompt: str
    reasoning_prompt: str
    verdict_prompt_template: str


@dataclass
class SourceFile:
    path: Path
    profile: Profile


# ── Backend abstraction ─────────────────────────────────────────────────

class Backend:
    """Base class for model backends."""

    def query(self, system: str, user: str, max_tokens: int = 4096) -> str:
        raise NotImplementedError


class OllamaBackend(Backend):
    """Ollama API backend."""

    def __init__(self, model: str, base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url.rstrip("/")

    def query(self, system: str, user: str, max_tokens: int = 4096) -> str:
        try:
            resp = requests.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "stream": False,
                    "options": {"temperature": 0.2, "num_predict": max_tokens},
                },
                timeout=600,
            )
            resp.raise_for_status()
            return resp.json()["message"]["content"].strip()
        except Exception as e:
            return f"[ERROR: ollama: {e}]"

    def __repr__(self):
        return f"ollama/{self.model}"


class OpenAIBackend(Backend):
    """OpenAI-compatible API (llama.cpp, vLLM, etc.)."""

    def __init__(self, model: str, base_url: str = "http://localhost:8080",
                 api_key: str = ""):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")

    def query(self, system: str, user: str, max_tokens: int = 4096) -> str:
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            resp = requests.post(
                f"{self.base_url}/v1/chat/completions",
                headers=headers,
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "temperature": 0.2,
                    "max_tokens": max_tokens,
                },
                timeout=600,
            )
            if resp.status_code == 500:
                return "[ERROR: context exceeded]"
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"].strip()
        except Exception as e:
            return f"[ERROR: openai: {e}]"

    def __repr__(self):
        return f"openai/{self.model}@{self.base_url}"


class ClaudeBackend(Backend):
    """Claude via CLI (uses subscription, no API key needed).

    Tested: claude --print --model claude-sonnet-4-6 -p "prompt"
    """

    def __init__(self, model: str = "opus"):
        self.model = model
        self._model_map = {
            "opus": "claude-opus-4-6",
            "sonnet": "claude-sonnet-4-6",
            "haiku": "claude-haiku-4-5-20251001",
        }

    def query(self, system: str, user: str, max_tokens: int = 4096) -> str:
        model_id = self._model_map.get(self.model, self.model)
        prompt = f"{system}\n\n{user}"
        try:
            result = subprocess.run(
                ["claude", "--print", "--model", model_id, "--bare", "-p", prompt],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return f"[ERROR: claude exit {result.returncode}: {result.stderr[:200]}]"
        except FileNotFoundError:
            return "[ERROR: claude CLI not found — install with: npm install -g @anthropic-ai/claude-code]"
        except subprocess.TimeoutExpired:
            return "[ERROR: claude timeout]"

    def __repr__(self):
        return f"claude/{self.model}"


class GeminiBackend(Backend):
    """Gemini via CLI (uses subscription, no API key needed).

    Tested: gemini -p "prompt" -m gemini-2.5-flash
    """

    def __init__(self, model: str = "flash"):
        self.model = model
        self._model_map = {
            "flash": "gemini-2.5-flash",
            "pro": "gemini-2.5-pro",
        }

    def query(self, system: str, user: str, max_tokens: int = 4096) -> str:
        model_id = self._model_map.get(self.model, self.model)
        prompt = f"{system}\n\n{user}"
        try:
            result = subprocess.run(
                ["gemini", "-p", prompt, "-m", model_id],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                # Gemini CLI may print "Loaded cached credentials." prefix
                for prefix in ["Loaded cached credentials."]:
                    if output.startswith(prefix):
                        output = output[len(prefix):].strip()
                return output
            return f"[ERROR: gemini exit {result.returncode}: {result.stderr[:200]}]"
        except FileNotFoundError:
            return "[ERROR: gemini CLI not found — install with: npm install -g @google/gemini-cli]"
        except subprocess.TimeoutExpired:
            return "[ERROR: gemini timeout]"

    def __repr__(self):
        return f"gemini/{self.model}"


class CodexBackend(Backend):
    """OpenAI Codex via CLI (uses ChatGPT subscription, no API key needed).

    Tested: codex exec "prompt" -o /tmp/output.txt
    Uses -o flag to capture clean output without CLI chrome.
    """

    def __init__(self, model: str = ""):
        # Default model is whatever codex defaults to (usually o4-mini)
        self.model = model

    def query(self, system: str, user: str, max_tokens: int = 4096) -> str:
        prompt = f"{system}\n\n{user}"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            outpath = f.name

        try:
            cmd = ["codex", "exec", prompt, "-o", outpath]
            if self.model:
                cmd.extend(["-m", self.model])
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300,
            )
            if os.path.exists(outpath):
                with open(outpath) as f:
                    output = f.read().strip()
                os.unlink(outpath)
                if output:
                    return output
            if result.returncode == 0:
                return result.stdout.strip()
            return f"[ERROR: codex exit {result.returncode}: {result.stderr[:200]}]"
        except FileNotFoundError:
            return "[ERROR: codex CLI not found — install from https://github.com/openai/codex]"
        except subprocess.TimeoutExpired:
            return "[ERROR: codex timeout]"
        finally:
            if os.path.exists(outpath):
                os.unlink(outpath)

    def __repr__(self):
        return f"codex/{self.model or 'default'}"


def load_profile(name: str) -> Profile:
    """Load a technology profile from profiles/<name>.json."""
    path = PROFILES_DIR / f"{name}.json"
    if not path.exists():
        available = ", ".join(sorted(p.stem for p in PROFILES_DIR.glob("*.json")))
        raise ValueError(f"Unknown profile {name!r}. Available: {available}")
    payload = load_json(path)
    return Profile(
        name=payload["name"],
        extensions=list(payload["extensions"]),
        triage_prompt=payload["triage_prompt"],
        reasoning_prompt=payload["reasoning_prompt"],
        verdict_prompt_template=payload["verdict_prompt_template"],
    )


def available_profile_names() -> List[str]:
    """List available profile names."""
    return sorted(p.stem for p in PROFILES_DIR.glob("*.json"))


def load_profiles(spec: str) -> List[Profile]:
    """Load one or more profiles from a comma-separated profile spec."""
    names = [part.strip() for part in spec.split(",") if part.strip()]
    if not names:
        raise ValueError("At least one profile must be specified.")

    if any(name == "auto" for name in names):
        names = available_profile_names()

    profiles = []
    seen = set()
    for name in names:
        profile = load_profile(name)
        if profile.name not in seen:
            profiles.append(profile)
            seen.add(profile.name)
    return profiles


def parse_backend_spec(spec: str) -> Backend:
    """Parse a backend spec string into a Backend instance.

    Formats:
      ollama/model-name                  → OllamaBackend
      ollama/model-name@http://host:port → OllamaBackend with custom URL
      openai/model@http://host:port      → OpenAIBackend (llama.cpp, vLLM)
      claude/opus                        → ClaudeBackend
      claude/sonnet                      → ClaudeBackend
      gemini/flash                       → GeminiBackend
      gemini/pro                         → GeminiBackend
      codex/o3-mini                      → CodexBackend
      codex/gpt-4.1                      → CodexBackend
    """
    if "/" not in spec:
        raise ValueError(f"Invalid backend spec: {spec!r}. Use 'backend/model' format.")

    backend_type, rest = spec.split("/", 1)

    # Parse optional @url suffix
    if "@" in rest:
        model, url = rest.rsplit("@", 1)
    else:
        model, url = rest, None

    if backend_type == "ollama":
        return OllamaBackend(model, url or "http://localhost:11434")
    elif backend_type == "openai":
        return OpenAIBackend(model, url or "http://localhost:8080")
    elif backend_type == "claude":
        return ClaudeBackend(model)
    elif backend_type == "gemini":
        return GeminiBackend(model)
    elif backend_type == "codex":
        return CodexBackend(model)
    else:
        raise ValueError(f"Unknown backend: {backend_type!r}. "
                         f"Use: ollama, openai, claude, gemini, codex")


# ── File handling ───────────────────────────────────────────────────────

DEFAULT_SKIP_DIRS = ("test", "tests", "testing", "t", "testdata")


def find_source_files(source_dir: str, profiles: List[Profile]) -> List[SourceFile]:
    """Find source files and dispatch them to the matching profile by extension."""
    extension_map = {}
    for profile in profiles:
        for ext in profile.extensions:
            extension_map[ext.lower()] = profile

    files = []
    for p in Path(source_dir).rglob("*"):
        profile = extension_map.get(p.suffix.lower())
        if profile and p.is_file():
            # Make the check case-insensitive
            parts = [part.lower() for part in p.parts]
            if any(t in parts for t in DEFAULT_SKIP_DIRS):
                continue
            files.append(SourceFile(path=p, profile=profile))
    files.sort(key=lambda item: item.path.stat().st_size, reverse=True)
    return files


def chunk_file(code: str, max_chars: int = 20000) -> List[str]:
    """Split code into chunks that fit model context."""
    if len(code) <= max_chars:
        return [code]
    chunks = []
    lines = code.split("\n")
    current = []
    current_len = 0
    for line in lines:
        current.append(line)
        current_len += len(line) + 1
        if current_len >= max_chars:
            chunks.append("\n".join(current))
            current = []
            current_len = 0
    if current:
        chunks.append("\n".join(current))
    return chunks


def utc_now() -> str:
    """Return a UTC ISO-8601 timestamp."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def make_session_dir(scratch_dir: str, package_name: str) -> Tuple[str, Path]:
    """Create a per-run session directory in scratch space."""
    safe_package = re.sub(r"[^A-Za-z0-9_.-]+", "-", package_name).strip("-") or "scan"
    session_id = str(uuid.uuid4())
    session_root = Path(scratch_dir).expanduser().resolve() / f"{safe_package}-{session_id}"
    session_root.mkdir(parents=True, exist_ok=False)
    for name in ("triage", "reasoning", "verdict"):
        (session_root / name).mkdir()
    return session_id, session_root


def write_json(path: Path, payload: dict):
    """Write JSON with stable formatting."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


def load_json(path: Path) -> dict:
    """Load one JSON document."""
    with path.open() as f:
        return json.load(f)


def append_jsonl(path: Path, payload: dict):
    """Append one JSON object per line."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        json.dump(payload, f)
        f.write("\n")


def stage_record_path(session_dir: Path, stage_name: str, relpath: str) -> Path:
    """Return the per-file stage record path inside the session."""
    return session_dir / stage_name / f"{relpath}.json"


def consensus_record_path(session_dir: Path, finding: Finding) -> Path:
    """Return the per-consensus-group verdict record path."""
    digest = hashlib.sha1(finding.key().encode("utf-8")).hexdigest()[:12]
    return session_dir / "verdict" / f"{finding.file}.{digest}.json"


def save_stage_file_output(session_dir: Path, stage_name: str, backend: Backend,
                           relpath: str, chunk_records: List[dict]):
    """Persist all outputs for one file in one stage."""
    findings = []
    for chunk in chunk_records:
        findings.extend(chunk["findings"])

    payload = {
        "file": relpath,
        "stage": stage_name,
        "backend": repr(backend),
        "created_at": utc_now(),
        "chunk_count": len(chunk_records),
        "finding_count": len(findings),
        "chunks": chunk_records,
        "findings": findings,
    }
    write_json(stage_record_path(session_dir, stage_name, relpath), payload)
    append_jsonl(
        session_dir / "progress.jsonl",
        {
            "created_at": payload["created_at"],
            "stage": stage_name,
            "file": relpath,
            "backend": repr(backend),
            "chunk_count": len(chunk_records),
            "finding_count": len(findings),
        },
    )


def save_verdict_output(session_dir: Path, group: dict):
    """Persist verdict output for one consensus group."""
    first = group["findings"][0]
    payload = {
        "file": first.file,
        "key": first.key(),
        "created_at": utc_now(),
        "verdict": group.get("verdict", "NEEDS_CONTEXT"),
        "verdict_raw": group.get("verdict_raw", ""),
        "findings": [asdict(f) for f in group["findings"]],
        "confirmation_count": group["count"],
        "stages": sorted(group.get("stages", [])),
    }
    write_json(consensus_record_path(session_dir, first), payload)


def load_stage_findings(session_dir: Path, stage_name: str) -> List[Finding]:
    """Load parsed findings for a stage from the session directory."""
    findings = []
    for path in sorted((session_dir / stage_name).rglob("*.json")):
        payload = load_json(path)
        for entry in payload.get("findings", []):
            findings.append(Finding(**entry))
    return findings


def load_progress_entries(session_dir: Path) -> List[dict]:
    """Load progress events from the session directory."""
    path = session_dir / "progress.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def compute_stage_stats(session_dir: Path) -> dict:
    """Summarize persisted progress by stage."""
    stats = {}
    for stage in ("triage", "reasoning", "verdict"):
        entries = [e for e in load_progress_entries(session_dir) if e["stage"] == stage]
        stats[stage] = {
            "completed_files": len(entries),
            "files_with_findings": sum(1 for e in entries if e.get("finding_count", 0) > 0),
            "total_findings": sum(e.get("finding_count", 0) for e in entries),
        }
    return stats


def format_findings_for_verdict(items: List[Finding]) -> str:
    """Render grouped findings so verdict can distinguish separate hypotheses."""
    if not items:
        return "(not flagged by this stage)"

    lines = []
    for idx, f in enumerate(items, 1):
        line = f"{idx}. [{f.severity}] {f.location}: {f.description}"
        if f.source:
            line += f"\n   Source: {f.source}"
        if f.sink:
            line += f"\n   Sink: {f.sink}"
        lines.append(line)
    return "\n".join(lines)


def build_verdict_group_notes(group: dict) -> Tuple[str, str]:
    """Explain confidence and when a group contains multiple hypotheses."""
    if group["count"] > 1:
        consensus_note = ("Both stages independently flagged this location — "
                          "higher confidence this is a real issue.")
    else:
        stage = list(group["stages"])[0] if group.get("stages") else "unknown"
        consensus_note = (f"Only flagged by {stage} stage — "
                          f"the other stage did not find this. Examine carefully.")

    reasoning_with_chain = [
        f for f in group["findings"]
        if f.stage == "reasoning" and (f.source or f.sink)
    ]
    if len(reasoning_with_chain) > 1:
        hypothesis_note = (
            f"Reasoning stage supplied {len(reasoning_with_chain)} distinct "
            "source/sink hypotheses for this grouped location. They may describe "
            "the same bug from different angles or different exploit paths. "
            "Assess each numbered hypothesis before collapsing them together."
        )
    elif len(group["findings"]) > 1:
        hypothesis_note = (
            "Multiple findings were merged into this grouped location. Review the "
            "numbered items below before deciding whether they describe one bug "
            "or multiple related paths."
        )
    else:
        hypothesis_note = ""

    return consensus_note, hypothesis_note


# ── Finding parser ──────────────────────────────────────────────────────

def parse_findings(raw: str, filename: str, model: str, stage: str) -> List[Finding]:
    """Extract structured findings from model output."""
    if "CLEAN" in raw and "FINDING" not in raw:
        return []
    if raw.startswith("[ERROR") or raw == "[EMPTY]":
        return []

    findings = []
    blocks = re.split(r"FINDING:", raw)
    for block in blocks[1:]:
        severity = _extract(block, r"SEVERITY:\s*(\w+)")
        location = _extract(block, r"LOCATION:\s*(.+?)(?:\n|TYPE:)")
        ftype = _extract(block, r"TYPE:\s*(.+?)(?:\n|DESCRIPTION:|SOURCE:)")
        source = _extract(block, r"SOURCE:\s*(.+?)(?=\nSINK:|\nDESCRIPTION:|\nEND_FINDING|\Z)", re.DOTALL)
        sink = _extract(block, r"SINK:\s*(.+?)(?=\nDESCRIPTION:|\nEND_FINDING|\Z)", re.DOTALL)
        desc = _extract(block, r"DESCRIPTION:\s*(.+?)(?:\n(?:EXPLOITATION|END_FINDING))", re.DOTALL)
        exploit = _extract(block, r"EXPLOITATION:\s*(.+?)(?:\n(?:END_FINDING|FINDING|$))", re.DOTALL)

        if severity and (desc or location):
            findings.append(Finding(
                severity=severity.strip(),
                location=(location or "unknown").strip(),
                type=(ftype or "unknown").strip(),
                description=(desc or "").strip(),
                exploitation=(exploit or "").strip(),
                file=filename,
                model=model,
                stage=stage,
                source=(source or "").strip(),
                sink=(sink or "").strip(),
            ))

    # Fallback: unstructured SEVERITY: lines (DOTALL so we cross newlines)
    if not findings:
        for m in re.finditer(r"SEVERITY:\s*(\w+).*?LOCATION:\s*(.+?)(?:\n)", raw, re.DOTALL):
            findings.append(Finding(
                severity=m.group(1).strip(),
                location=m.group(2).strip(),
                type="unstructured",
                description="(see raw output)",
                exploitation="",
                file=filename,
                model=model,
                stage=stage,
            ))

    return findings


def _extract(text: str, pattern: str, flags: int = 0) -> Optional[str]:
    m = re.search(pattern, text, flags)
    return m.group(1) if m else None


# ── OBS integration ─────────────────────────────────────────────────────

def checkout_obs_package(project_package: str, work_dir: str) -> str:
    """Checkout a package from OBS and extract source."""
    project, package = project_package.split("/", 1)

    print(f"Checking out {project}/{package}...", flush=True)
    subprocess.run(
        ["osc", "co", project, package],
        cwd=work_dir, check=True, capture_output=True,
    )

    pkg_path = os.path.join(work_dir, project, package)
    tarballs = sorted(Path(pkg_path).glob("*.tar.*"))
    if not tarballs:
        tarballs = sorted(Path(pkg_path).glob("*.tgz"))
    if not tarballs:
        raise RuntimeError(f"No tarball found in {pkg_path}")

    src_dir = os.path.join(work_dir, "src")
    os.makedirs(src_dir, exist_ok=True)
    subprocess.run(
        ["tar", "xf", str(tarballs[0]), "-C", src_dir],
        check=True, capture_output=True,
    )

    extracted = [d for d in Path(src_dir).iterdir() if d.is_dir()]
    return str(extracted[0]) if extracted else src_dir


# ── Pipeline stages ─────────────────────────────────────────────────────

def run_scan_stage(files: List[SourceFile], backend: Backend,
                   stage_name: str, source_dir: str, session_dir: Path):
    """Run a scanning stage over files and persist all outputs."""
    for i, source_file in enumerate(files):
        filepath = source_file.path
        profile = source_file.profile
        relpath = str(filepath.relative_to(source_dir))
        record_path = stage_record_path(session_dir, stage_name, relpath)
        if record_path.exists():
            print(f"  [{i+1}/{len(files)}] {relpath} [{profile.name}] (cached)", flush=True)
            continue

        code = filepath.read_text(errors="replace")
        chunks = chunk_file(code)

        print(
            f"  [{i+1}/{len(files)}] {relpath} [{profile.name}] ({len(code)} chars, {len(chunks)} chunk(s))",
            flush=True,
        )

        chunk_records = []
        for ci, chunk in enumerate(chunks):
            label = relpath
            if len(chunks) > 1:
                label = f"{relpath} (part {ci+1}/{len(chunks)})"
            user_msg = f"SOURCE FILE: {label}\n```\n{chunk}\n```"

            system_prompt = profile.triage_prompt if stage_name == "triage" else profile.reasoning_prompt
            raw = backend.query(system_prompt, user_msg)
            findings = parse_findings(raw, relpath, repr(backend), stage_name)
            chunk_records.append({
                "chunk_index": ci + 1,
                "label": label,
                "raw_output": raw,
                "findings": [asdict(f) for f in findings],
            })
            if findings:
                for f in findings:
                    print(f"    -> {f.severity}: {f.location} ({f.type})", flush=True)
        save_stage_file_output(session_dir, stage_name, backend, relpath, chunk_records)


def run_verdict_stage(consensus: List[dict], backend: Backend,
                      source_dir: str, session_dir: Path,
                      profile_by_file: dict) -> List[dict]:
    """Run verdict stage: verify findings against source code."""
    for group in consensus:
        filepath = Path(source_dir) / group["findings"][0].file
        profile = profile_by_file[group["findings"][0].file]
        if not filepath.exists():
            group["verdict"] = "FILE_NOT_FOUND"
            save_verdict_output(session_dir, group)
            continue

        full_code = filepath.read_text(errors="replace")
        # Cap source to avoid blowing context on the verdict model.
        # 30k chars is ~8k tokens — leaves room for findings + response.
        code = full_code[:30000]
        if len(full_code) > 30000:
            code += f"\n\n... [{len(full_code) - 30000} chars truncated] ..."
        # Format findings by stage so verdict sees what each scanner found
        triage_items = [f for f in group["findings"] if f.stage == "triage"]
        reasoning_items = [f for f in group["findings"] if f.stage == "reasoning"]
        consensus_note, hypothesis_note = build_verdict_group_notes(group)

        prompt = profile.verdict_prompt_template.format(
            filename=group["findings"][0].file,
            triage_findings=format_findings_for_verdict(triage_items),
            reasoning_findings=format_findings_for_verdict(reasoning_items),
            consensus_note=consensus_note,
            hypothesis_note=hypothesis_note,
            code=code,
        )
        raw = backend.query("", prompt)
        group["verdict_raw"] = raw

        # Parse verdict — match the actual VERDICT: line to avoid
        # false matches from the word appearing in reasoning text
        verdict_match = re.search(r"VERDICT:\s*(CONFIRMED|FALSE_POSITIVE|NEEDS_CONTEXT)", raw)
        if verdict_match:
            group["verdict"] = verdict_match.group(1)
        else:
            group["verdict"] = "NEEDS_CONTEXT"

        status = group["verdict"]
        print(f"  {group['findings'][0].file}: {status}", flush=True)
        save_verdict_output(session_dir, group)

    return consensus


def compute_consensus(findings: List[Finding]) -> List[dict]:
    """Group findings by location and count cross-stage confirmation."""
    groups = {}
    for f in findings:
        key = f.key()
        if key not in groups:
            groups[key] = {"findings": [], "stages": set(), "count": 0}
        groups[key]["findings"].append(f)
        groups[key]["stages"].add(f.stage)
        groups[key]["count"] = len(groups[key]["stages"])

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(
        groups.values(),
        key=lambda g: (
            -g["count"],
            severity_order.get(g["findings"][0].severity.lower(), 4),
        ),
    )


# ── Main pipeline ───────────────────────────────────────────────────────

def run_pipeline(args) -> ScanResult:
    """Run the full multi-stage scanning pipeline."""
    resume_session = getattr(args, "resume_session", None)
    profile_spec = getattr(args, "profile", "auto")
    profiles = load_profiles(profile_spec)

    # Parse backends
    triage_backend = parse_backend_spec(args.triage)
    reasoning_backend = parse_backend_spec(args.reasoning) if not args.triage_only else None
    verdict_backend = parse_backend_spec(args.verdict) if args.verdict else None

    if resume_session:
        session_dir = Path(resume_session).expanduser().resolve()
        metadata = load_json(session_dir / "metadata.json")
        session_id = metadata["session_id"]
        created_at = metadata["created_at"]
        package_name = metadata["package"]
        source_dir = metadata["source_dir"]
        profiles = load_profiles(metadata.get("profiles", profile_spec))
        metadata["backends"] = {
            "triage": repr(triage_backend),
            "reasoning": repr(reasoning_backend) if reasoning_backend else None,
            "verdict": repr(verdict_backend) if verdict_backend else None,
        }
        write_json(session_dir / "metadata.json", metadata)
    else:
        package_name = args.package_name
        if args.obs_package:
            package_name = package_name or args.obs_package.split("/")[-1]
        elif args.source_dir:
            package_name = package_name or Path(args.source_dir).name
        else:
            package_name = package_name or "scan"

        session_id, session_dir = make_session_dir(args.scratch_dir, package_name)
        created_at = utc_now()
        metadata = {
            "session_id": session_id,
            "created_at": created_at,
            "package": package_name,
            "profiles": ",".join(profile.name for profile in profiles),
            "source_dir": None,
            "obs_package": args.obs_package,
            "backends": {
                "triage": repr(triage_backend),
                "reasoning": repr(reasoning_backend) if reasoning_backend else None,
                "verdict": repr(verdict_backend) if verdict_backend else None,
            },
        }
        write_json(session_dir / "metadata.json", metadata)

        # Resolve source
        if args.obs_package:
            work_dir = str(session_dir / "work")
            Path(work_dir).mkdir(parents=True, exist_ok=True)
            source_dir = checkout_obs_package(args.obs_package, work_dir)
        else:
            source_dir = args.source_dir

        metadata["source_dir"] = source_dir
        write_json(session_dir / "metadata.json", metadata)

    result = ScanResult(
        package=package_name,
        files_scanned=0,
        files_with_findings=0,
        session_id=session_id,
        session_dir=str(session_dir),
        created_at=created_at,
    )

    files = find_source_files(source_dir, profiles)
    if not files:
        print(f"No matching source files found in {source_dir}", flush=True)
        return result

    result.files_scanned = len(files)
    print(f"\nSession: {session_id}", flush=True)
    print(f"Session dir: {session_dir}", flush=True)
    if resume_session:
        print("Resuming existing session.", flush=True)
    print(f"\nFound {len(files)} source files in {source_dir}", flush=True)

    # ── Stage 1: Triage ──
    print(f"\n{'='*60}", flush=True)
    print(f"TRIAGE ({triage_backend})", flush=True)
    print(f"{'='*60}", flush=True)

    run_scan_stage(files, triage_backend, "triage", source_dir, session_dir)
    triage_findings = load_stage_findings(session_dir, "triage")

    if not triage_findings:
        print("\nTriage: All files clean.", flush=True)
        result.clean_files = [str(f.path.relative_to(source_dir)) for f in files]
        result.stage_stats = compute_stage_stats(session_dir)
        return result

    flagged_files = {f.file for f in triage_findings}
    result.files_with_findings = len(flagged_files)
    result.clean_files = [
        str(f.path.relative_to(source_dir))
        for f in files
        if str(f.path.relative_to(source_dir)) not in flagged_files
    ]
    print(
        f"\nTriage: {len(triage_findings)} findings in {len(flagged_files)} files",
        flush=True,
    )

    if args.triage_only:
        result.findings = triage_findings
        result.stage_stats = compute_stage_stats(session_dir)
        return result

    # ── Stage 2: Reasoning ──
    print(f"\n{'='*60}", flush=True)
    print(f"REASONING ({reasoning_backend})", flush=True)
    print(f"{'='*60}", flush=True)

    flagged_paths = [f for f in files if str(f.path.relative_to(source_dir)) in flagged_files]
    run_scan_stage(
        flagged_paths, reasoning_backend, "reasoning", source_dir, session_dir
    )
    reasoning_findings = load_stage_findings(session_dir, "reasoning")

    all_findings = triage_findings + reasoning_findings
    consensus = compute_consensus(all_findings)

    confirmed_count = sum(1 for c in consensus if c["count"] > 1)
    print(f"\nReasoning: {len(reasoning_findings)} findings", flush=True)
    print(
        f"Consensus: {len(consensus)} unique, {confirmed_count} confirmed by both",
        flush=True,
    )

    if not verdict_backend:
        result.findings = [f for group in consensus for f in group["findings"]]
        result.stage_stats = compute_stage_stats(session_dir)
        return result

    # ── Stage 3: Verdict ──
    print(f"\n{'='*60}", flush=True)
    print(f"VERDICT ({verdict_backend})", flush=True)
    print(f"{'='*60}", flush=True)

    profile_by_file = {str(f.path.relative_to(source_dir)): f.profile for f in files}
    consensus = run_verdict_stage(consensus, verdict_backend, source_dir, session_dir, profile_by_file)

    # Filter: keep only confirmed findings
    for group in consensus:
        if group.get("verdict") == "FALSE_POSITIVE":
            continue
        result.findings.extend(group["findings"])

    result.stage_stats = compute_stage_stats(session_dir)
    return result


# ── Report generation ───────────────────────────────────────────────────

def generate_report(result: ScanResult, output_path: str):
    """Generate a markdown report."""
    lines = [
        f"# {result.package} Security Scan Report\n",
        f"**Date**: {result.created_at}",
        f"**Session UUID**: {result.session_id}",
        f"**Session Dir**: {result.session_dir}",
        f"**Files scanned**: {result.files_scanned}",
        f"**Files with findings**: {result.files_with_findings}",
        f"**Total findings**: {len(result.findings)}\n",
    ]

    if result.stage_stats:
        lines.append("## Stage Summary\n")
        for stage in ("triage", "reasoning", "verdict"):
            stats = result.stage_stats.get(stage)
            if not stats:
                continue
            lines.append(
                f"- {stage}: {stats['completed_files']} completed, "
                f"{stats['files_with_findings']} with findings, "
                f"{stats['total_findings']} total findings"
            )
        lines.append("")

    if result.findings:
        lines.append("## Findings\n")
        for f in result.findings:
            lines.append(f"### [{f.severity}] {f.location}")
            lines.append(f"**File**: {f.file}")
            lines.append(f"**Type**: {f.type}")
            lines.append(f"**Model**: {f.model} (stage: {f.stage})")
            if f.source:
                lines.append(f"**Source**: {f.source}")
            if f.sink:
                lines.append(f"**Sink**: {f.sink}")
            lines.append(f"**Description**: {f.description}")
            if f.exploitation:
                lines.append(f"**Exploitation**: {f.exploitation}")
            lines.append("")

    if result.clean_files:
        lines.append("## Files confirmed clean\n")
        for f in result.clean_files:
            lines.append(f"- {f}")

    report = "\n".join(lines)
    with open(output_path, "w") as f:
        f.write(report)
    print(f"\nReport written to {output_path}", flush=True)


# ── CLI ─────────────────────────────────────────────────────────────────

CONFIG_KEYS = {
    "source_dir",
    "obs_package",
    "resume_session",
    "package_name",
    "output",
    "json",
    "scratch_dir",
    "profile",
    "triage",
    "reasoning",
    "verdict",
    "triage_only",
}


def load_config_file(path: Path) -> dict:
    """Load and validate TOML config."""
    with path.open("rb") as f:
        config = tomllib.load(f)

    if not isinstance(config, dict):
        raise ValueError("Config root must be a TOML table.")

    unknown = sorted(set(config) - CONFIG_KEYS)
    if unknown:
        raise ValueError(
            "Unknown config key(s): " + ", ".join(unknown) +
            ". Supported keys: " + ", ".join(sorted(CONFIG_KEYS))
        )

    return config

def main():
    # Load config file if present
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument("--config", default="config.toml",
                               help="Path to TOML configuration file.")
    config_args, _ = config_parser.parse_known_args()

    config = {}
    if Path(config_args.config).exists():
        try:
            config = load_config_file(Path(config_args.config))
        except ValueError as e:
            config_parser.error(str(e))

    parser = argparse.ArgumentParser(
        description="Multi-model security scanner for software packages",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Backend spec format: backend/model[@url]

  ollama/gpt-oss-20b                  Ollama (default port 11434)
  ollama/kimi-k2@http://host:11434    Ollama on custom host
  openai/gpt-oss-20b@http://host:8404 llama.cpp / vLLM server
  claude/opus                         Claude via CLI (opus, sonnet, haiku)
  gemini/flash                        Google Gemini (flash, pro)
  codex/o3-mini                       OpenAI API (any model name)
""",
        parents=[config_parser],
    )

    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("--source-dir", help="Path to extracted package source")
    source.add_argument("--obs-package",
                        help="OBS project/package (e.g. openSUSE:Factory/zypper)")
    source.add_argument("--resume-session",
                        help="Resume an existing session directory")

    parser.add_argument("--package-name", help="Override auto-detected package name")
    parser.add_argument("--output", default="report.md", help="Output report path")
    parser.add_argument("--json", default=None, help="JSON output path")
    parser.add_argument("--scratch-dir", default="/tmp/opensuse-security-scanner",
                        help="Scratch root for per-run session directories")
    parser.add_argument("--profile", default="auto",
                        help="Technology profile set: auto or comma-separated names "
                             "(e.g. c_cpp,python,bash)")

    # Stage configuration
    parser.add_argument("--triage", default="ollama/gpt-oss-20b",
                        help="Triage stage backend (default: ollama/gpt-oss-20b)")
    parser.add_argument("--reasoning", default="ollama/gemma4:31b",
                        help="Reasoning stage backend (default: ollama/gemma4:31b)")
    parser.add_argument("--verdict", default=None,
                        help="Verdict stage backend (disabled by default). "
                             "E.g.: claude/opus, gemini/flash, codex/o3-mini")

    parser.add_argument("--triage-only", action="store_true",
                        help="Run only the triage stage")

    parser.set_defaults(**config)
    args = parser.parse_args()

    if not any([args.source_dir, args.obs_package, args.resume_session]):
        parser.error("A source must be provided via --source-dir, --obs-package, or --resume-session, or in the config file.")

    result = run_pipeline(args)

    generate_report(result, args.output)

    if args.json:
        with open(args.json, "w") as f:
            json.dump({
                "package": result.package,
                "session_id": result.session_id,
                "session_dir": result.session_dir,
                "created_at": result.created_at,
                "files_scanned": result.files_scanned,
                "stage_stats": result.stage_stats,
                "findings": [asdict(f) for f in result.findings],
                "clean_files": result.clean_files,
                "errors": result.errors,
            }, f, indent=2)
        print(f"JSON written to {args.json}", flush=True)


if __name__ == "__main__":
    main()
