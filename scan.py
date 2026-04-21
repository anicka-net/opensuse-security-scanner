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
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional, Tuple

import requests


# ── Prompt ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a paranoid security auditor with decades of experience finding bugs in C/C++ code.
Your job is to find REAL vulnerabilities that could be exploited by an attacker.

Be suspicious. Assume the worst. If something COULD be a vulnerability, report it.
Better to flag a false positive than miss a real bug.

Focus on:
1. Buffer overflows, heap overflows, stack overflows
2. Command injection, shell metacharacter injection
3. Path traversal, symlink attacks, directory escape
4. Integer overflow/underflow leading to wrong allocations or bounds checks
5. Format string vulnerabilities
6. TOCTOU race conditions in file or permission checks
7. Missing or inadequate input validation on external data (network, files, env vars, user input)
8. Cryptographic weaknesses (weak hashing, timing attacks, verification bypasses)
9. Privilege escalation vectors, missing privilege drops
10. Use-after-free, double-free, null pointer dereference
11. Missing bounds checks on array/buffer access
12. Unsafe string operations (strcpy, strcat, sprintf without length limits)

For each finding report in this exact format:

FINDING:
SEVERITY: Critical/High/Medium/Low
LOCATION: function_name (file context)
TYPE: vulnerability category
DESCRIPTION: what the bug is, be specific about the code
EXPLOITATION: concrete attack scenario
END_FINDING

If the code is genuinely clean, say exactly: CLEAN
Do NOT report style issues, missing comments, or theoretical concerns that require impossible preconditions."""

VERDICT_PROMPT_TEMPLATE = """\
You are reviewing security scan findings for {filename}.

Previous scanners flagged the following potential issues:

{findings_context}

Your job is to verify each finding:
1. Is it a REAL vulnerability or a false positive?
2. If real, is it actually EXPLOITABLE? Check:
   - Who controls the input? (user, network, root-only, internal)
   - What privilege boundary is crossed?
   - What is the actual attack surface?
3. Rate the real-world severity.

For each finding, respond:
VERDICT: [CONFIRMED|FALSE_POSITIVE|NEEDS_CONTEXT]
REAL_SEVERITY: [Critical|High|Medium|Low|None]
REASONING: [why]

Source code:
```
{code}
```"""


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

    def key(self) -> str:
        """Normalized key for dedup/consensus."""
        return f"{self.file}:{self.location}:{self.type}".lower()


@dataclass
class ScanResult:
    package: str
    files_scanned: int
    files_with_findings: int
    findings: List[Finding] = field(default_factory=list)
    clean_files: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


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
            return "[ERROR: gemini CLI not found — install with: npm install -g @anthropic-ai/gemini-cli... wait no: npm install -g @anthropic-ai/gemini-cli is wrong. Check https://github.com/google-gemini/gemini-cli]"
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

C_EXTENSIONS = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hxx"}


def find_source_files(source_dir: str) -> List[Path]:
    """Find all C/C++ source files, sorted by size (largest first)."""
    files = []
    for p in Path(source_dir).rglob("*"):
        if p.suffix.lower() in C_EXTENSIONS and p.is_file():
            parts = p.parts
            if any(t in parts for t in ("test", "tests", "testing", "t", "testdata")):
                continue
            files.append(p)
    files.sort(key=lambda p: p.stat().st_size, reverse=True)
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
        ftype = _extract(block, r"TYPE:\s*(.+?)(?:\n|DESCRIPTION:)")
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

    print(f"Checking out {project}/{package}...")
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

def run_scan_stage(files: List[Path], backend: Backend,
                   stage_name: str, source_dir: str) -> List[Finding]:
    """Run a scanning stage over files using the given backend."""
    all_findings = []
    for i, filepath in enumerate(files):
        relpath = str(filepath.relative_to(source_dir))
        code = filepath.read_text(errors="replace")
        chunks = chunk_file(code)

        print(f"  [{i+1}/{len(files)}] {relpath} ({len(code)} chars, {len(chunks)} chunk(s))")

        for ci, chunk in enumerate(chunks):
            label = relpath
            if len(chunks) > 1:
                label = f"{relpath} (part {ci+1}/{len(chunks)})"
            user_msg = f"SOURCE FILE: {label}\n```\n{chunk}\n```"

            raw = backend.query(SYSTEM_PROMPT, user_msg)
            findings = parse_findings(raw, relpath, repr(backend), stage_name)
            if findings:
                for f in findings:
                    print(f"    -> {f.severity}: {f.location} ({f.type})")
                all_findings.extend(findings)

    return all_findings


def run_verdict_stage(consensus: List[dict], backend: Backend,
                      source_dir: str) -> List[dict]:
    """Run verdict stage: verify findings against source code."""
    for group in consensus:
        filepath = Path(source_dir) / group["findings"][0].file
        if not filepath.exists():
            group["verdict"] = "FILE_NOT_FOUND"
            continue

        full_code = filepath.read_text(errors="replace")
        # Cap source to avoid blowing context on the verdict model.
        # 30k chars is ~8k tokens — leaves room for findings + response.
        code = full_code[:30000]
        if len(full_code) > 30000:
            code += f"\n\n... [{len(full_code) - 30000} chars truncated] ..."
        findings_text = "\n".join(
            f"- [{f.severity}] {f.location}: {f.description}"
            for f in group["findings"]
        )
        prompt = VERDICT_PROMPT_TEMPLATE.format(
            filename=group["findings"][0].file,
            findings_context=findings_text,
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
        print(f"  {group['findings'][0].file}: {status}")

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
    # Parse backends
    triage_backend = parse_backend_spec(args.triage)
    reasoning_backend = parse_backend_spec(args.reasoning) if not args.triage_only else None
    verdict_backend = parse_backend_spec(args.verdict) if args.verdict else None

    # Resolve source
    if args.obs_package:
        work_dir = tempfile.mkdtemp(prefix="scanner-")
        source_dir = checkout_obs_package(args.obs_package, work_dir)
        package_name = args.obs_package.split("/")[-1]
    else:
        source_dir = args.source_dir
        package_name = args.package_name or Path(source_dir).name

    result = ScanResult(package=package_name, files_scanned=0, files_with_findings=0)

    files = find_source_files(source_dir)
    if not files:
        print(f"No C/C++ source files found in {source_dir}")
        return result

    result.files_scanned = len(files)
    print(f"\nFound {len(files)} source files in {source_dir}")

    # ── Stage 1: Triage ──
    print(f"\n{'='*60}")
    print(f"TRIAGE ({triage_backend})")
    print(f"{'='*60}")

    triage_findings = run_scan_stage(files, triage_backend, "triage", source_dir)

    if not triage_findings:
        print("\nTriage: All files clean.")
        result.clean_files = [str(f.relative_to(source_dir)) for f in files]
        return result

    flagged_files = {f.file for f in triage_findings}
    result.files_with_findings = len(flagged_files)
    result.clean_files = [
        str(f.relative_to(source_dir))
        for f in files
        if str(f.relative_to(source_dir)) not in flagged_files
    ]
    print(f"\nTriage: {len(triage_findings)} findings in {len(flagged_files)} files")

    if args.triage_only:
        result.findings = triage_findings
        return result

    # ── Stage 2: Reasoning ──
    print(f"\n{'='*60}")
    print(f"REASONING ({reasoning_backend})")
    print(f"{'='*60}")

    flagged_paths = [f for f in files if str(f.relative_to(source_dir)) in flagged_files]
    reasoning_findings = run_scan_stage(
        flagged_paths, reasoning_backend, "reasoning", source_dir
    )

    all_findings = triage_findings + reasoning_findings
    consensus = compute_consensus(all_findings)

    confirmed_count = sum(1 for c in consensus if c["count"] > 1)
    print(f"\nReasoning: {len(reasoning_findings)} findings")
    print(f"Consensus: {len(consensus)} unique, {confirmed_count} confirmed by both")

    if not verdict_backend:
        result.findings = [f for group in consensus for f in group["findings"]]
        return result

    # ── Stage 3: Verdict ──
    print(f"\n{'='*60}")
    print(f"VERDICT ({verdict_backend})")
    print(f"{'='*60}")

    consensus = run_verdict_stage(consensus, verdict_backend, source_dir)

    # Filter: keep only confirmed findings
    for group in consensus:
        if group.get("verdict") == "FALSE_POSITIVE":
            continue
        result.findings.extend(group["findings"])

    return result


# ── Report generation ───────────────────────────────────────────────────

def generate_report(result: ScanResult, output_path: str):
    """Generate a markdown report."""
    lines = [
        f"# {result.package} Security Scan Report\n",
        f"**Files scanned**: {result.files_scanned}",
        f"**Files with findings**: {result.files_with_findings}",
        f"**Total findings**: {len(result.findings)}\n",
    ]

    if result.findings:
        lines.append("## Findings\n")
        for f in result.findings:
            lines.append(f"### [{f.severity}] {f.location}")
            lines.append(f"**File**: {f.file}")
            lines.append(f"**Type**: {f.type}")
            lines.append(f"**Model**: {f.model} (stage: {f.stage})")
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
    print(f"\nReport written to {output_path}")


# ── CLI ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Multi-model security scanner for C/C++ packages",
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
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--source-dir", help="Path to extracted package source")
    source.add_argument("--obs-package",
                        help="OBS project/package (e.g. openSUSE:Factory/zypper)")

    parser.add_argument("--package-name", help="Override auto-detected package name")
    parser.add_argument("--output", default="report.md", help="Output report path")
    parser.add_argument("--json", default=None, help="JSON output path")

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

    args = parser.parse_args()
    result = run_pipeline(args)

    generate_report(result, args.output)

    if args.json:
        with open(args.json, "w") as f:
            json.dump({
                "package": result.package,
                "files_scanned": result.files_scanned,
                "findings": [asdict(f) for f in result.findings],
                "clean_files": result.clean_files,
                "errors": result.errors,
            }, f, indent=2)
        print(f"JSON written to {args.json}")


if __name__ == "__main__":
    main()
