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
from typing import Dict, List, Optional, Tuple

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

import requests


ROOT_DIR = Path(__file__).resolve().parent
PROFILES_DIR = ROOT_DIR / "profiles"
CONTRACTS_DIR = ROOT_DIR / "contracts"


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
    file_class: str = "production"


# ── File classification ───────────────────────────────────────────────

_NONPROD_DIR_PATTERNS = (
    "examples", "example", "demo", "demos", "sample", "samples",
    "xtests", "xtest", "benchmarks", "benchmark", "bench",
    "doc", "docs", "documentation",
    "contrib",
)

_NONPROD_FILENAME_PATTERNS = [
    re.compile(r"^tst[-_]"),
    re.compile(r"[-_]example\."),
    re.compile(r"[-_]demo\."),
    re.compile(r"^example[-_.]"),
]


def classify_file_path(relpath: str) -> str:
    parts = [p.lower() for p in Path(relpath).parts]
    for part in parts[:-1]:
        if part in _NONPROD_DIR_PATTERNS:
            if part in ("doc", "docs", "documentation"):
                return "documentation"
            if part in ("benchmarks", "benchmark", "bench"):
                return "benchmark"
            if part in ("examples", "example", "demo", "demos",
                        "sample", "samples", "contrib"):
                return "example"
            return "test"
        if part in DEFAULT_SKIP_DIRS:
            return "test"
    filename = parts[-1] if parts else ""
    for pat in _NONPROD_FILENAME_PATTERNS:
        if pat.search(filename):
            return "test"
    return "production"


# ── Contracts ──────────────────────────────────────────────────────────

@dataclass
class ContractEntry:
    id: str
    symbol: str
    kind: str
    behavior: str
    source: str
    dismiss_patterns: List[re.Pattern]


@dataclass
class ContractPack:
    name: str
    description: str
    detect_includes: List[str]
    contracts: List[ContractEntry]


def load_contract_pack(name: str) -> ContractPack:
    path = CONTRACTS_DIR / f"{name}.json"
    if not path.exists():
        available = ", ".join(sorted(p.stem for p in CONTRACTS_DIR.glob("*.json")))
        raise ValueError(f"Unknown contract pack {name!r}. Available: {available}")
    payload = load_json(path)
    entries = []
    for c in payload.get("contracts", []):
        patterns = []
        for pat in c.get("dismiss_if", []):
            try:
                patterns.append(re.compile(pat, re.IGNORECASE))
            except re.error:
                pass
        entries.append(ContractEntry(
            id=c["id"], symbol=c["symbol"], kind=c["kind"],
            behavior=c["behavior"], source=c.get("source", ""),
            dismiss_patterns=patterns,
        ))
    return ContractPack(
        name=payload["name"],
        description=payload.get("description", ""),
        detect_includes=payload.get("detect", {}).get("includes", []),
        contracts=entries,
    )


def available_contract_packs() -> List[str]:
    if not CONTRACTS_DIR.exists():
        return []
    return sorted(p.stem for p in CONTRACTS_DIR.glob("*.json"))


def detect_contract_packs(files: List[SourceFile]) -> List[ContractPack]:
    available = available_contract_packs()
    if not available:
        return []
    packs = [load_contract_pack(name) for name in available]
    sample_lines = set()
    for sf in files[:200]:
        try:
            with open(sf.path, errors="replace") as fh:
                for i, line in enumerate(fh):
                    if i >= 100:
                        break
                    if "#include" in line:
                        sample_lines.add(line.strip())
        except OSError:
            pass
    activated = []
    for pack in packs:
        for header in pack.detect_includes:
            if any(header in line for line in sample_lines):
                activated.append(pack)
                break
    return activated


def load_contract_packs(spec: str, files: List[SourceFile]) -> List[ContractPack]:
    if spec == "none":
        return []
    if spec == "auto":
        return detect_contract_packs(files)
    return [load_contract_pack(name.strip()) for name in spec.split(",") if name.strip()]


def contracts_for_code(code: str, packs: List[ContractPack]) -> List[ContractEntry]:
    relevant = []
    for pack in packs:
        for entry in pack.contracts:
            if entry.symbol in code:
                relevant.append(entry)
    return relevant


def format_contracts_prompt(entries: List[ContractEntry]) -> str:
    if not entries:
        return ""
    lines = [
        "\nTRUSTED API CONTRACTS (verified ground truth — do not second-guess these):\n"
    ]
    for e in entries:
        lines.append(f"  - {e.symbol} ({e.kind}): {e.behavior}")
    lines.append("")
    return "\n".join(lines)


def apply_contract_annotations(
    findings: List["Finding"], packs: List[ContractPack],
) -> Dict[str, str]:
    """Annotate findings that match known contracts. Returns a dict of
    finding_key -> annotation text.  Findings are NOT removed — the
    annotation is injected into the confirmation prompt so the model
    can weigh it alongside full context."""
    if not packs:
        return {}
    all_entries = [e for p in packs for e in p.contracts]
    annotations: Dict[str, str] = {}
    for f in findings:
        desc_lower = f.description.lower() if f.description else ""
        for entry in all_entries:
            if entry.symbol.lower() not in desc_lower:
                continue
            for pat in entry.dismiss_patterns:
                if pat.search(desc_lower):
                    annotations[f.key()] = (
                        f"\nNOTE — a known API contract may apply: "
                        f"{entry.symbol} ({entry.kind}): {entry.behavior}  "
                        f"Verify whether this contract fully rules out the "
                        f"described mechanism, or whether aliasing / indirect "
                        f"references bypass the contract.\n"
                    )
                    break
            if f.key() in annotations:
                break
    return annotations


# ── Package hints ──────────────────────────────────────────────────────

HINTS_FILENAME = ".scanner-hints.toml"


@dataclass
class PackageHints:
    facts: List[str]
    dismiss_patterns: List[re.Pattern]
    raw_dismissals: List[str]


def load_package_hints(source_dir: str) -> Optional[PackageHints]:
    hints_path = Path(source_dir) / HINTS_FILENAME
    if not hints_path.exists():
        return None
    with hints_path.open("rb") as f:
        data = tomllib.load(f)
    facts = list(data.get("facts", []))
    raw_dismissals = list(data.get("dismiss", []))
    patterns = []
    for pat in raw_dismissals:
        try:
            patterns.append(re.compile(pat, re.IGNORECASE))
        except re.error:
            pass
    return PackageHints(facts=facts, dismiss_patterns=patterns,
                        raw_dismissals=raw_dismissals)


def format_hints_prompt(hints: PackageHints) -> str:
    if not hints or not hints.facts:
        return ""
    lines = [
        "\nPACKAGE-SPECIFIC FACTS (from prior audit, verified ground truth):\n"
    ]
    for fact in hints.facts:
        lines.append(f"  - {fact}")
    lines.append("")
    return "\n".join(lines)


def apply_hints_annotations(
    findings: List["Finding"], hints: Optional[PackageHints],
) -> Dict[str, str]:
    """Annotate findings that match package hint patterns. Returns a dict
    of finding_key -> annotation text.  Findings are NOT removed."""
    if not hints or not hints.dismiss_patterns:
        return {}
    annotations: Dict[str, str] = {}
    for f in findings:
        desc_lower = (f.description or "").lower()
        loc_lower = (f.location or "").lower()
        text = f"{loc_lower} {desc_lower}"
        for pat in hints.dismiss_patterns:
            if pat.search(text):
                annotations[f.key()] = (
                    f"\nNOTE — a package hint suggests this may be noise "
                    f"(pattern: {pat.pattern}). Verify against the code "
                    f"before dismissing.\n"
                )
                break
    return annotations


# ── Backend abstraction ─────────────────────────────────────────────────

class Backend:
    """Base class for model backends."""

    def query(self, system: str, user: str, max_tokens: int = 16384) -> str:
        raise NotImplementedError


class OllamaBackend(Backend):
    """Ollama API backend."""

    def __init__(self, model: str, base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url.rstrip("/")

    def query(self, system: str, user: str, max_tokens: int = 16384) -> str:
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

    def query(self, system: str, user: str, max_tokens: int = 16384) -> str:
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

    def query(self, system: str, user: str, max_tokens: int = 16384) -> str:
        model_id = self._model_map.get(self.model, self.model)
        prompt = f"{system}\n\n{user}"
        try:
            # Pass prompt via -p flag directly.  Python subprocess
            # uses execve which supports the full OS ARG_MAX (~2MB).
            # Note: --bare requires API auth; omit it for subscription.
            result = subprocess.run(
                ["claude", "--print", "--model", model_id,
                 "-p", prompt],
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

    def query(self, system: str, user: str, max_tokens: int = 16384) -> str:
        model_id = self._model_map.get(self.model, self.model)
        prompt = f"{system}\n\n{user}"
        try:
            # Pipe prompt via stdin, -p "" triggers non-interactive mode
            # while reading the actual prompt from stdin (avoids arg limits)
            result = subprocess.run(
                ["gemini", "-p", "", "-m", model_id],
                input=prompt,
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
        # "default" means use whatever codex defaults to (empty = no -m flag)
        self.model = "" if model == "default" else model

    def query(self, system: str, user: str, max_tokens: int = 16384) -> str:
        prompt = f"{system}\n\n{user}"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            outpath = f.name

        try:
            # Use "-" as prompt arg to read from stdin (avoids CLI arg
            # length limits on large prompts like verdict with source code)
            cmd = ["codex", "exec", "-", "-o", outpath]
            if self.model:
                cmd.extend(["-m", self.model])
            result = subprocess.run(
                cmd, input=prompt,
                capture_output=True, text=True, timeout=300,
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
            relpath = str(p.relative_to(source_dir))
            file_class = classify_file_path(relpath)
            files.append(SourceFile(path=p, profile=profile, file_class=file_class))
    files.sort(key=lambda item: item.path.stat().st_size, reverse=True)
    return files


def _strip_comments_and_strings(code: str) -> str:
    """Replace comments and string literals with spaces, preserving newlines.

    Used for reliable brace-depth tracking in C/C++ code.
    """
    result = []
    i = 0
    while i < len(code):
        if code[i:i+2] == "//":
            # Line comment — skip to end of line
            while i < len(code) and code[i] != "\n":
                result.append(" ")
                i += 1
        elif code[i:i+2] == "/*":
            # Block comment — skip to */
            result.append(" ")
            result.append(" ")
            i += 2
            while i < len(code) and code[i:i+2] != "*/":
                result.append("\n" if code[i] == "\n" else " ")
                i += 1
            if i < len(code):
                result.append(" ")
                result.append(" ")
                i += 2
        elif code[i] in ('"', "'"):
            # String or char literal — skip to closing quote
            quote = code[i]
            result.append(" ")
            i += 1
            while i < len(code) and code[i] != quote:
                if code[i] == "\\":
                    result.append(" ")
                    i += 1
                result.append(" " if code[i] != "\n" else "\n")
                i += 1
            if i < len(code):
                result.append(" ")
                i += 1
        else:
            result.append(code[i])
            i += 1
    return "".join(result)


# Regex for C/C++ function definitions at file scope.
# Matches: optional qualifiers, return type, function name, parameter list, {
# Must start at column 0 (or after leading whitespace that looks like file scope).
_C_FUNC_DEF_RE = re.compile(
    r'^(?:static\s+|inline\s+|extern\s+|__attribute__\S+\s+)*'  # qualifiers
    r'(?:(?:const\s+|unsigned\s+|signed\s+|struct\s+|enum\s+|union\s+)*'
    r'[a-zA-Z_]\w*(?:\s*\*)*)'  # return type
    r'\s+'
    r'([a-zA-Z_]\w*)'  # function name (capture group 1)
    r'\s*\([^)]*\)',  # parameter list
    re.MULTILINE,
)


def extract_c_functions(code: str) -> List[Tuple[str, str]]:
    """Extract individual C/C++ functions from source code.

    Returns a list of (function_name, function_code) tuples.
    Prepends file-level declarations (structs, typedefs, macros) as
    context for each function.
    """
    lines = code.split("\n")
    clean = _strip_comments_and_strings(code)
    clean_lines = clean.split("\n")
    functions: List[Tuple[str, str]] = []
    preamble_end = 0  # line index where first function starts

    # Find function boundaries by tracking brace depth on cleaned code
    depth = 0
    in_function = False
    func_start = 0
    func_name = ""

    for i, cline in enumerate(clean_lines):
        if not in_function and depth == 0 and "{" in cline:
            # At file scope with an opening brace — look back to see if
            # the preceding lines form a function signature.  Walk back
            # until we hit a statement terminator (; or }) or start of file,
            # stopping at blank lines or preprocessor directives that break
            # up declarations.
            sig_start = i
            for j in range(i - 1, max(-1, i - 30), -1):
                prev = clean_lines[j].strip()
                if not prev:
                    # Blank line breaks the chain only if we already saw signature content
                    if sig_start < i:
                        break
                    continue
                if prev.endswith(";") or prev.endswith("}"):
                    break
                if prev.startswith("#"):
                    # Preprocessor line — don't include, but don't break
                    # (common to have #ifdef/#endif around attributes)
                    continue
                sig_start = j

            # Collect signature lines and check for a function definition pattern
            sig_joined = " ".join(
                line for line in clean_lines[sig_start:i + 1]
                if not line.strip().startswith("#")
            )
            m = _C_FUNC_DEF_RE.search(sig_joined)
            if m:
                name = m.group(1)
                if name not in ("if", "while", "for", "switch", "do",
                                "else", "return", "sizeof", "typeof",
                                "defined"):
                    in_function = True
                    func_name = name
                    # Also include preceding comment block as part of the function
                    func_start = sig_start
                    for k in range(sig_start - 1, -1, -1):
                        line_k = lines[k].strip()
                        if line_k.startswith("/*") or line_k.startswith("//"):
                            func_start = k
                        elif line_k.endswith("*/"):
                            func_start = k
                            # Walk up the comment block
                            for kk in range(k - 1, -1, -1):
                                if "/*" in lines[kk]:
                                    func_start = kk
                                    break
                                if not lines[kk].strip() or "*" in lines[kk]:
                                    func_start = kk
                                else:
                                    break
                            break
                        elif not line_k:
                            continue
                        else:
                            break
                    if preamble_end == 0:
                        preamble_end = func_start

        depth += cline.count("{") - cline.count("}")

        if in_function and depth == 0:
            func_body = "\n".join(lines[func_start:i + 1])
            functions.append((func_name, func_body))
            in_function = False

    # Build preamble: everything before the first function (structs, typedefs, etc.)
    preamble = "\n".join(lines[:preamble_end]).strip()
    if len(preamble) > 3000:
        preamble = preamble[:3000] + "\n// ... (preamble truncated)"

    if preamble:
        functions = [
            (name, f"// File-level declarations for context:\n{preamble}\n\n"
                   f"// Function under review:\n{body}")
            for name, body in functions
        ]

    return functions


# ── Python function extractor ──────────────────────────────────────────

# Matches `def name(` or `async def name(` with any leading whitespace.
_PY_DEF_RE = re.compile(r'^(\s*)(?:async\s+)?def\s+([a-zA-Z_]\w*)\s*\(', re.MULTILINE)


def extract_python_functions(code: str) -> List[Tuple[str, str]]:
    """Extract Python functions and methods.

    Uses indentation to find function bodies.  Class methods are
    qualified as ``ClassName.method``.  Preamble (imports, top-level
    constants, class definitions) is prepended as context.
    """
    lines = code.split("\n")
    functions: List[Tuple[str, str]] = []
    # Find all function definitions and their indent levels
    matches = []
    class_stack: List[Tuple[int, str]] = []  # (indent, class_name)

    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        # Pop class stack when dedenting out
        while class_stack and class_stack[-1][0] >= indent:
            class_stack.pop()
        # Track class declarations
        class_m = re.match(r'class\s+([A-Za-z_]\w*)', stripped)
        if class_m:
            class_stack.append((indent, class_m.group(1)))
            continue
        # Track function declarations
        def_m = re.match(r'(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(', stripped)
        if def_m:
            name = def_m.group(1)
            if class_stack:
                name = f"{class_stack[-1][1]}.{name}"
            matches.append((i, indent, name))

    preamble_end = matches[0][0] if matches else len(lines)

    # Build preamble: everything before first function, plus class headers
    preamble_parts = []
    preamble_parts.extend(lines[:preamble_end])
    preamble = "\n".join(preamble_parts).strip()
    if len(preamble) > 3000:
        preamble = preamble[:3000] + "\n# ... (preamble truncated)"

    # Extract each function: from def line until indent drops back
    for idx, (start, indent, name) in enumerate(matches):
        # Find end: next line at indent <= function indent
        end = len(lines)
        for j in range(start + 1, len(lines)):
            line = lines[j]
            stripped = line.lstrip()
            if not stripped or stripped.startswith("#"):
                continue
            line_indent = len(line) - len(stripped)
            if line_indent <= indent:
                end = j
                break
        # Include decorator lines immediately before
        real_start = start
        for k in range(start - 1, -1, -1):
            line_k = lines[k].strip()
            if line_k.startswith("@") or line_k == "":
                real_start = k
            else:
                break
        body = "\n".join(lines[real_start:end]).rstrip()
        if preamble:
            wrapped = (f"# File-level context:\n{preamble}\n\n"
                       f"# Function under review:\n{body}")
        else:
            wrapped = body
        functions.append((name, wrapped))

    return functions


# ── Bash function extractor ────────────────────────────────────────────

# Matches `name() {` or `function name {` at line start.
_BASH_FUNC_RE = re.compile(
    r'^(?:function\s+([A-Za-z_][\w\-]*)\s*(?:\(\s*\))?\s*\{|'
    r'([A-Za-z_][\w\-]*)\s*\(\s*\)\s*\{)',
    re.MULTILINE,
)


def extract_bash_functions(code: str) -> List[Tuple[str, str]]:
    """Extract Bash function definitions.

    Handles both `name() { ... }` and `function name { ... }` forms.
    Skips content inside heredocs and single/double-quoted strings for
    brace counting.  Preamble is everything before the first function
    (set -e, source lines, variable defs).
    """
    functions: List[Tuple[str, str]] = []
    lines = code.split("\n")
    # Build a cleaned version for brace counting: strip quoted strings only.
    # (Bash strings are simpler than C — no /* */ comments.)
    cleaned = []
    i = 0
    in_heredoc = False
    heredoc_marker = ""
    for line in lines:
        s = line
        if in_heredoc:
            if line.strip() == heredoc_marker:
                in_heredoc = False
            cleaned.append("")  # hide heredoc contents
            continue
        # Detect heredoc start
        hd = re.search(r"<<-?\s*['\"]?(\w+)['\"]?", line)
        if hd:
            heredoc_marker = hd.group(1)
            in_heredoc = True
        # Strip single-line comments
        s = re.sub(r'(?<![\\$])#.*$', '', s)
        # Strip double-quoted strings (preserve braces? No — drop them)
        s = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', '""', s)
        s = re.sub(r"'[^']*'", "''", s)
        cleaned.append(s)

    preamble_end = None
    depth = 0
    in_func = False
    func_start = 0
    func_name = ""

    for i, line in enumerate(cleaned):
        if not in_func:
            m = _BASH_FUNC_RE.search(line)
            if m:
                func_name = m.group(1) or m.group(2)
                func_start = i
                in_func = True
                depth = line.count("{") - line.count("}")
                if preamble_end is None:
                    preamble_end = i
                if depth <= 0:
                    # Single-line function (unusual but possible)
                    body = lines[func_start]
                    functions.append((func_name, body))
                    in_func = False
                continue
        else:
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                body = "\n".join(lines[func_start:i + 1])
                functions.append((func_name, body))
                in_func = False

    if preamble_end is None:
        preamble_end = 0
    preamble = "\n".join(lines[:preamble_end]).strip()
    if len(preamble) > 3000:
        preamble = preamble[:3000] + "\n# ... (preamble truncated)"

    if preamble:
        functions = [
            (name, f"# File-level context:\n{preamble}\n\n"
                   f"# Function under review:\n{body}")
            for name, body in functions
        ]

    return functions


# ── Rust function extractor ────────────────────────────────────────────

# Matches fn definitions; handles pub/async/const/unsafe/extern qualifiers.
_RUST_FN_RE = re.compile(
    r'^(?:\s*)(?:pub(?:\([^)]*\))?\s+)?(?:const\s+|async\s+|unsafe\s+|'
    r'extern\s+("[^"]*")?\s*)*fn\s+([A-Za-z_]\w*)',
    re.MULTILINE,
)


def extract_rust_functions(code: str) -> List[Tuple[str, str]]:
    """Extract Rust fn definitions.

    Includes fns inside impl/trait blocks (qualified as Type::method).
    Preamble: use statements, struct/enum/trait definitions.
    """
    functions: List[Tuple[str, str]] = []
    lines = code.split("\n")
    cleaned = _strip_comments_and_strings(code).split("\n")

    # Track impl/trait context via brace depth
    depth = 0
    impl_stack: List[Tuple[int, str]] = []  # (depth_at_open, type_name)
    in_fn = False
    fn_start = 0
    fn_name = ""
    fn_depth_start = 0
    preamble_end = None

    # Pre-scan: find all `fn NAME` lines.  For each, walk forward to find
    # the opening `{` (signature may span multiple lines with generics/args).
    pending_fn: Optional[Tuple[int, str]] = None

    for i, cline in enumerate(cleaned):
        if not in_fn:
            # Check impl/trait block start
            impl_m = re.match(r'\s*impl(?:\s*<[^>]*>)?\s+(?:([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s+for\s+)?([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)(?:\s*<[^>]*>)?', cline)
            if impl_m and "{" in cline:
                type_name = impl_m.group(2)
                impl_stack.append((depth, type_name))

            # Did we find a `fn NAME` on this line? Remember it.
            fn_m = _RUST_FN_RE.search(cline)
            if fn_m:
                name = fn_m.group(2)
                if impl_stack:
                    name = f"{impl_stack[-1][1]}::{name}"
                # Could be a trait method declaration (no body, ends with `;`)
                # or a real definition (eventually has `{`).  Hold it until
                # we see either `;` or `{`.
                pending_fn = (i, name)

            if pending_fn is not None and "{" in cline:
                fn_start_line, candidate_name = pending_fn
                fn_name = candidate_name
                fn_start = fn_start_line
                fn_depth_start = depth
                in_fn = True
                pending_fn = None
                if preamble_end is None:
                    preamble_end = fn_start
            elif pending_fn is not None and ";" in cline and "{" not in cline:
                # trait method declaration without body — skip
                pending_fn = None

        depth += cline.count("{") - cline.count("}")

        # Pop impl_stack when exiting
        while impl_stack and depth <= impl_stack[-1][0]:
            impl_stack.pop()

        if in_fn and depth <= fn_depth_start:
            body = "\n".join(lines[fn_start:i + 1])
            functions.append((fn_name, body))
            in_fn = False

    if preamble_end is None:
        preamble_end = 0
    preamble = "\n".join(lines[:preamble_end]).strip()
    if len(preamble) > 3000:
        preamble = preamble[:3000] + "\n// ... (preamble truncated)"

    if preamble:
        functions = [
            (name, f"// File-level context:\n{preamble}\n\n"
                   f"// Function under review:\n{body}")
            for name, body in functions
        ]

    return functions


# ── Ruby function extractor ────────────────────────────────────────────

_RUBY_DEF_RE = re.compile(r'^(\s*)def\s+((?:self\.)?[A-Za-z_]\w*[?!=]?)')


def extract_ruby_functions(code: str) -> List[Tuple[str, str]]:
    """Extract Ruby def blocks.

    Handles nested defs inside class/module blocks, qualified as
    Class#method.  Matches ``def ... end`` pairs via keyword tracking
    (class/module/def/do/begin/if/while/case/unless open, end closes).
    """
    functions: List[Tuple[str, str]] = []
    lines = code.split("\n")

    # Build a token-stripped view to avoid matching 'end' inside strings
    # (simplified — full Ruby string parsing is complex)
    cleaned = []
    for line in lines:
        # Strip line comments
        s = re.sub(r'(?<!\\)#.*$', '', line)
        # Strip simple strings
        s = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', '""', s)
        s = re.sub(r"'[^'\\]*(?:\\.[^'\\]*)*'", "''", s)
        cleaned.append(s)

    class_stack: List[Tuple[int, str]] = []  # (depth_at_open, name)
    depth = 0
    in_def = False
    def_start = 0
    def_depth = 0
    def_name = ""
    preamble_end = None

    # Keywords that open a block (require matching 'end')
    # def, class, module, do, begin, if (at start of line), unless, while, until, case
    # We only need to distinguish 'def' specifically; others just increment depth.
    opener_re = re.compile(
        r'(?:^|\s)(?:class|module|def|do|begin|if|unless|while|until|case)\b(?!\s*:)'
    )
    # Postfix `if`/`unless` don't increment — match only when at logical start
    inline_opener_re = re.compile(r'\bdo\s*(?:\|[^|]*\|)?\s*$')

    for i, cline in enumerate(cleaned):
        stripped = cline.strip()
        if not stripped:
            continue

        # Count block openers on this line
        opens = 0
        closes = len(re.findall(r'\bend\b', cline))

        # Defs start a block
        def_m = _RUBY_DEF_RE.match(cline)
        if def_m:
            opens += 1
            if not in_def:
                name = def_m.group(2)
                if class_stack:
                    sep = "." if name.startswith("self.") else "#"
                    name = f"{class_stack[-1][1]}{sep}{name.removeprefix('self.')}"
                def_name = name
                def_start = i
                def_depth = depth
                in_def = True
                if preamble_end is None:
                    preamble_end = i

        # Class/module
        cls_m = re.match(r'\s*(?:class|module)\s+([A-Za-z_][\w:]*)', cline)
        if cls_m and not in_def:
            opens += 1
            class_stack.append((depth, cls_m.group(1)))

        # Other block openers (only at statement start, not postfix)
        if re.match(r'\s*(?:begin|case)\b', cline):
            opens += 1
        if re.match(r'\s*(?:if|unless|while|until)\b', cline) and not re.search(r';\s*end\s*$', cline):
            opens += 1
        if inline_opener_re.search(cline):
            opens += 1

        depth += opens - closes

        while class_stack and depth <= class_stack[-1][0]:
            class_stack.pop()

        if in_def and depth <= def_depth:
            body = "\n".join(lines[def_start:i + 1])
            functions.append((def_name, body))
            in_def = False

    if preamble_end is None:
        preamble_end = 0
    preamble = "\n".join(lines[:preamble_end]).strip()
    if len(preamble) > 3000:
        preamble = preamble[:3000] + "\n# ... (preamble truncated)"

    if preamble:
        functions = [
            (name, f"# File-level context:\n{preamble}\n\n"
                   f"# Function under review:\n{body}")
            for name, body in functions
        ]

    return functions


# ── Perl function extractor ────────────────────────────────────────────

_PERL_SUB_RE = re.compile(
    r'^\s*sub\s+([A-Za-z_]\w*)(?:\s*(?:\([^)]*\))?(?:\s*:\s*[A-Za-z_]\w*)*)?\s*\{',
    re.MULTILINE,
)


def extract_perl_functions(code: str) -> List[Tuple[str, str]]:
    """Extract Perl `sub` definitions.

    Handles prototype syntax (``sub name ($$)``) and attributes.
    Preamble: use statements, package declarations, global vars.
    """
    functions: List[Tuple[str, str]] = []
    lines = code.split("\n")

    cleaned = []
    for line in lines:
        s = re.sub(r'(?<![\$@%&\\])#.*$', '', line)
        s = re.sub(r'"[^"\\]*(?:\\.[^"\\]*)*"', '""', s)
        s = re.sub(r"'[^']*'", "''", s)
        cleaned.append(s)

    depth = 0
    in_sub = False
    sub_start = 0
    sub_depth = 0
    sub_name = ""
    preamble_end = None

    for i, cline in enumerate(cleaned):
        if not in_sub:
            m = _PERL_SUB_RE.search(cline)
            if m:
                sub_name = m.group(1)
                sub_start = i
                sub_depth = depth
                in_sub = True
                if preamble_end is None:
                    preamble_end = i
        depth += cline.count("{") - cline.count("}")
        if in_sub and depth <= sub_depth:
            body = "\n".join(lines[sub_start:i + 1])
            functions.append((sub_name, body))
            in_sub = False

    if preamble_end is None:
        preamble_end = 0
    preamble = "\n".join(lines[:preamble_end]).strip()
    if len(preamble) > 3000:
        preamble = preamble[:3000] + "\n# ... (preamble truncated)"

    if preamble:
        functions = [
            (name, f"# File-level context:\n{preamble}\n\n"
                   f"# Function under review:\n{body}")
            for name, body in functions
        ]

    return functions


# ── JavaScript/TypeScript function extractor ───────────────────────────

# Multiple forms we recognize at top level or inside class bodies:
#   function name(...)
#   async function name(...)
#   class Foo { method(...) { ... } }
#   export [default] function name(...)
_JS_FUNC_RE = re.compile(
    r'^(?:\s*)(?:export\s+(?:default\s+)?)?'
    r'(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(',
    re.MULTILINE,
)
# Inside class bodies: methodName(params) { or *methodName(params) { or
# async methodName(params) { or get name() / set name(v)
_JS_METHOD_RE = re.compile(
    r'^\s*(?:static\s+)?(?:async\s+|get\s+|set\s+)?\*?\s*'
    r'([A-Za-z_$#][\w$]*)\s*\([^)]*\)\s*\{',
)
_JS_CLASS_RE = re.compile(r'^\s*(?:export\s+(?:default\s+)?)?class\s+([A-Za-z_$][\w$]*)')


def extract_node_functions(code: str) -> List[Tuple[str, str]]:
    """Extract JS/TS top-level functions and class methods.

    Arrow functions assigned to consts are *not* extracted — too noisy
    and mostly short.  Focus is on named ``function`` declarations and
    class methods, which is where exploitable logic usually lives.
    """
    functions: List[Tuple[str, str]] = []
    lines = code.split("\n")
    cleaned = _strip_comments_and_strings(code).split("\n")

    depth = 0
    class_stack: List[Tuple[int, str]] = []
    in_fn = False
    fn_start = 0
    fn_depth_start = 0
    fn_name = ""
    preamble_end = None

    # Reserved JS keywords that look like methods but aren't
    _JS_KEYWORDS = {
        "if", "else", "while", "for", "switch", "return", "throw",
        "try", "catch", "finally", "do", "with", "typeof", "instanceof",
        "new", "delete", "void", "in", "of", "yield", "await",
        "function", "class", "var", "let", "const", "break", "continue",
    }

    for i, cline in enumerate(cleaned):
        if not in_fn:
            # Class declaration
            cls_m = _JS_CLASS_RE.match(cline)
            if cls_m and "{" in cline:
                class_stack.append((depth, cls_m.group(1)))

            # Top-level function declaration
            fn_m = _JS_FUNC_RE.search(cline)
            if fn_m and "{" in cline:
                name = fn_m.group(1)
                fn_name = name
                fn_start = i
                fn_depth_start = depth
                in_fn = True
                if preamble_end is None:
                    preamble_end = i
            # Class method — only when we're inside a class body
            elif class_stack and depth > class_stack[-1][0]:
                # Only look one level deep into the class (not nested blocks)
                if depth == class_stack[-1][0] + 1:
                    meth_m = _JS_METHOD_RE.match(cline)
                    if meth_m and meth_m.group(1) not in _JS_KEYWORDS:
                        name = f"{class_stack[-1][1]}.{meth_m.group(1)}"
                        fn_name = name
                        fn_start = i
                        fn_depth_start = depth
                        in_fn = True
                        if preamble_end is None:
                            preamble_end = i

        depth += cline.count("{") - cline.count("}")

        while class_stack and depth <= class_stack[-1][0]:
            class_stack.pop()

        if in_fn and depth <= fn_depth_start:
            body = "\n".join(lines[fn_start:i + 1])
            functions.append((fn_name, body))
            in_fn = False

    if preamble_end is None:
        preamble_end = 0
    preamble = "\n".join(lines[:preamble_end]).strip()
    if len(preamble) > 3000:
        preamble = preamble[:3000] + "\n// ... (preamble truncated)"

    if preamble:
        functions = [
            (name, f"// File-level context:\n{preamble}\n\n"
                   f"// Function under review:\n{body}")
            for name, body in functions
        ]

    return functions


# ── Dispatch table ─────────────────────────────────────────────────────

FUNCTION_EXTRACTORS = {
    "c_cpp": extract_c_functions,
    "python": extract_python_functions,
    "bash": extract_bash_functions,
    "rust": extract_rust_functions,
    "ruby": extract_ruby_functions,
    "perl": extract_perl_functions,
    "node": extract_node_functions,
}


def extract_functions(code: str, profile_name: str) -> List[Tuple[str, str]]:
    """Dispatch to the right language extractor.

    Returns an empty list for unknown profiles, letting the caller
    fall back to whole-file scanning.
    """
    extractor = FUNCTION_EXTRACTORS.get(profile_name)
    if extractor is None:
        return []
    try:
        return extractor(code)
    except Exception as e:
        # Extractors are best-effort — never crash the scan
        print(f"    [WARN] Function extraction failed for {profile_name}: {e}",
              flush=True)
        return []


def chunk_file(code: str, max_chars: int = 40000) -> List[str]:
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


# ── Include / import resolution ────────────────────────────────────────

# Maximum total chars of resolved header context to prepend.
HEADER_BUDGET = 8000


def _resolve_c_includes(code: str, source_dir: str, filepath: Path) -> str:
    """Resolve local #include "..." directives for C/C++ files.

    Returns function/class/struct declarations from found headers,
    capped to HEADER_BUDGET chars.
    """
    includes = re.findall(r'#include\s+"([^"]+)"', code)
    if not includes:
        return ""

    source_root = Path(source_dir)
    base_dir = filepath.parent
    snippets = []
    seen = set()
    budget = HEADER_BUDGET

    for inc in includes:
        if inc in seen:
            continue
        seen.add(inc)

        # Search relative to the current file first, then preserve the
        # include path within the source tree before falling back to
        # basename-only matching for simple includes like "foo.h".
        candidates = [base_dir / inc, source_root / inc]
        if "/" in inc:
            candidates.extend(source_root.rglob(inc))
        else:
            candidates.extend(source_root.rglob(Path(inc).name))

        unique_candidates = []
        seen_candidates = set()
        for candidate in candidates:
            candidate = candidate.resolve()
            if candidate in seen_candidates:
                continue
            seen_candidates.add(candidate)
            unique_candidates.append(candidate)

        for candidate in unique_candidates:
            if candidate.is_file():
                try:
                    header = candidate.read_text(errors="replace")
                except OSError:
                    continue
                # Extract declarations: function signatures, class/struct/enum
                # definitions, typedefs, #define macros for key constants
                decls = _extract_c_declarations(header)
                if decls:
                    rel = str(candidate.relative_to(source_root)) if candidate.is_relative_to(source_root) else str(candidate)
                    snippet = f"// --- {rel} (declarations) ---\n{decls}"
                    if len(snippet) <= budget:
                        snippets.append(snippet)
                        budget -= len(snippet)
                break
    return "\n".join(snippets)


def _extract_c_declarations(header: str) -> str:
    """Extract function declarations, class/struct definitions from C/C++ header."""
    lines = header.split("\n")
    result = []
    in_block = False
    brace_depth = 0

    for line in lines:
        stripped = line.strip()
        # Skip comments and preprocessor guards
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue
        if stripped.startswith("#ifndef") or stripped.startswith("#define") or stripped.startswith("#endif"):
            continue
        if stripped.startswith("#pragma"):
            continue
        # Include relevant #define macros (not guards)
        if stripped.startswith("#define") and "(" in stripped:
            result.append(stripped)
            continue
        # Function declarations (ending with ;)
        if re.match(r'^\s*(static\s+|inline\s+|extern\s+|virtual\s+)*([\w:*&<>,\s]+)\s+\w+\s*\(', stripped):
            if stripped.endswith(";"):
                result.append(stripped)
                continue
            # Multi-line declaration — take until ;
            if ";" not in stripped and "{" not in stripped:
                result.append(stripped)
                continue
        # Class/struct/enum declarations
        if re.match(r'^\s*(class|struct|enum|typedef|using|namespace)\s', stripped):
            result.append(stripped)
            continue

    return "\n".join(result)


def _resolve_python_imports(code: str, source_dir: str, filepath: Path) -> str:
    """Resolve local imports for Python files."""
    imports = re.findall(r'(?:from\s+(\S+)\s+import|import\s+(\S+))', code)
    if not imports:
        return ""

    snippets = []
    seen = set()
    budget = HEADER_BUDGET

    for frm, imp in imports:
        mod = frm or imp
        if mod in seen or mod.startswith(("os", "sys", "re", "json", "typing",
                                          "pathlib", "collections", "functools",
                                          "subprocess", "datetime", "hashlib",
                                          "urllib", "http", "socket", "logging")):
            continue
        seen.add(mod)

        # Convert module path to file path
        mod_path = mod.replace(".", "/")
        candidates = list(Path(source_dir).rglob(f"{mod_path}.py"))
        candidates.extend(Path(source_dir).rglob(f"{mod_path}/__init__.py"))

        for candidate in candidates:
            if candidate.is_file():
                try:
                    content = candidate.read_text(errors="replace")
                except OSError:
                    continue
                # Extract function/class definitions
                decls = _extract_python_declarations(content)
                if decls:
                    rel = str(candidate.relative_to(source_dir))
                    snippet = f"# --- {rel} (declarations) ---\n{decls}"
                    if len(snippet) <= budget:
                        snippets.append(snippet)
                        budget -= len(snippet)
                break

    return "\n".join(snippets)


def _extract_python_declarations(content: str) -> str:
    """Extract function and class signatures from Python source."""
    lines = content.split("\n")
    result = []
    for line in lines:
        stripped = line.strip()
        if re.match(r'^(def|class|async\s+def)\s+\w+', stripped):
            result.append(stripped)
    return "\n".join(result)


def _resolve_node_imports(code: str, source_dir: str, filepath: Path) -> str:
    """Resolve local relative imports for Node.js / TypeScript files."""
    source_root = Path(source_dir)
    snippets = []
    seen = set()
    budget = HEADER_BUDGET

    patterns = [
        r'import\s+(?:[^"\']+\s+from\s+)?["\'](\.{1,2}/[^"\']+)["\']',
        r'export\s+\*\s+from\s+["\'](\.{1,2}/[^"\']+)["\']',
        r'require\(\s*["\'](\.{1,2}/[^"\']+)["\']\s*\)',
    ]
    imports = []
    for pattern in patterns:
        imports.extend(re.findall(pattern, code))

    for mod in imports:
        if mod in seen:
            continue
        seen.add(mod)

        candidates = _node_module_candidates(filepath, mod)
        for candidate in candidates:
            if not candidate.is_file():
                continue
            try:
                content = candidate.read_text(errors="replace")
            except OSError:
                continue
            decls = _extract_node_declarations(content)
            if decls:
                rel = str(candidate.relative_to(source_root)) if candidate.is_relative_to(source_root) else str(candidate)
                snippet = f"// --- {rel} (declarations) ---\n{decls}"
                if len(snippet) <= budget:
                    snippets.append(snippet)
                    budget -= len(snippet)
            break

    return "\n".join(snippets)


def _node_module_candidates(filepath: Path, mod: str) -> List[Path]:
    """Return candidate file paths for a relative Node.js module import."""
    base = filepath.parent / mod
    extensions = ["", ".js", ".mjs", ".cjs", ".ts"]
    candidates = [base.with_suffix(ext) if ext else base for ext in extensions]
    candidates.extend((base / "index").with_suffix(ext) for ext in extensions[1:])
    return _dedupe_paths(candidates)


def _extract_node_declarations(content: str) -> str:
    """Extract function/class/type declarations from Node.js / TypeScript files."""
    lines = content.split("\n")
    result = []
    for line in lines:
        stripped = line.strip()
        if re.match(r'^(export\s+)?(async\s+)?function\s+\w+', stripped):
            result.append(stripped)
            continue
        if re.match(r'^(export\s+)?class\s+\w+', stripped):
            result.append(stripped)
            continue
        if re.match(r'^(export\s+)?(const|let|var)\s+\w+\s*=\s*(async\s*)?(\([^)]*\)|\w+)\s*=>', stripped):
            result.append(stripped)
            continue
        if re.match(r'^(export\s+)?(interface|type|enum)\s+\w+', stripped):
            result.append(stripped)
            continue
    return "\n".join(result)


def _resolve_ruby_requires(code: str, source_dir: str, filepath: Path) -> str:
    """Resolve local Ruby require_relative and relative require directives."""
    source_root = Path(source_dir)
    snippets = []
    seen = set()
    budget = HEADER_BUDGET

    requires = re.findall(r'require_relative\s+["\']([^"\']+)["\']', code)
    requires.extend(
        mod for mod in re.findall(r'require\s+["\']([^"\']+)["\']', code)
        if mod.startswith(("./", "../"))
    )

    for mod in requires:
        if mod in seen:
            continue
        seen.add(mod)

        base = (filepath.parent / mod) if mod.startswith(("./", "../")) else (filepath.parent / mod)
        candidates = _dedupe_paths([base, base.with_suffix(".rb")])
        for candidate in candidates:
            if not candidate.is_file():
                continue
            try:
                content = candidate.read_text(errors="replace")
            except OSError:
                continue
            decls = _extract_ruby_declarations(content)
            if decls:
                rel = str(candidate.relative_to(source_root)) if candidate.is_relative_to(source_root) else str(candidate)
                snippet = f"# --- {rel} (declarations) ---\n{decls}"
                if len(snippet) <= budget:
                    snippets.append(snippet)
                    budget -= len(snippet)
            break

    return "\n".join(snippets)


def _extract_ruby_declarations(content: str) -> str:
    """Extract method/class/module declarations from Ruby source."""
    lines = content.split("\n")
    result = []
    for line in lines:
        stripped = line.strip()
        if re.match(r'^(class|module)\s+[A-Z]\w*(::[A-Z]\w*)*', stripped):
            result.append(stripped)
            continue
        if re.match(r'^def\s+(self\.)?\w+[!?=]?', stripped):
            result.append(stripped)
            continue
    return "\n".join(result)


def _resolve_perl_imports(code: str, source_dir: str, filepath: Path) -> str:
    """Resolve local Perl modules loaded via use/require."""
    source_root = Path(source_dir)
    lib_dirs = [filepath.parent, source_root]
    snippets = []
    seen = set()
    budget = HEADER_BUDGET

    for lib_dir in re.findall(r'use\s+lib\s+["\']([^"\']+)["\']', code):
        lib_dirs.append((filepath.parent / lib_dir).resolve())

    modules = []
    modules.extend(("file", match) for match in re.findall(r'require\s+["\']([^"\']+)["\']', code))
    modules.extend(("module", match) for match in re.findall(r'(?:use|require)\s+([A-Za-z_]\w*(?:::\w+)*)\s*[;)]', code))

    for kind, mod in modules:
        key = (kind, mod)
        if key in seen:
            continue
        seen.add(key)

        if kind == "file":
            base = filepath.parent / mod
            candidates = [base]
        else:
            rel = Path(*mod.split("::")).with_suffix(".pm")
            candidates = [lib_dir / rel for lib_dir in lib_dirs]

        for candidate in _dedupe_paths(candidates):
            if not candidate.is_file():
                continue
            try:
                content = candidate.read_text(errors="replace")
            except OSError:
                continue
            decls = _extract_perl_declarations(content)
            if decls:
                rel = str(candidate.relative_to(source_root)) if candidate.is_relative_to(source_root) else str(candidate)
                snippet = f"# --- {rel} (declarations) ---\n{decls}"
                if len(snippet) <= budget:
                    snippets.append(snippet)
                    budget -= len(snippet)
            break

    return "\n".join(snippets)


def _extract_perl_declarations(content: str) -> str:
    """Extract package and sub declarations from Perl source."""
    lines = content.split("\n")
    result = []
    for line in lines:
        stripped = line.strip()
        if re.match(r'^package\s+\w+(?:::\w+)*\s*;', stripped):
            result.append(stripped)
            continue
        if re.match(r'^sub\s+\w+', stripped):
            result.append(stripped)
            continue
        if re.match(r'^use\s+constant\s+\w+', stripped):
            result.append(stripped)
            continue
    return "\n".join(result)


def _resolve_rust_modules(code: str, source_dir: str, filepath: Path) -> str:
    """Resolve local Rust modules referenced by mod/use statements."""
    source_root = Path(source_dir)
    crate_root = _guess_rust_crate_root(source_root, filepath)
    snippets = []
    seen = set()
    budget = HEADER_BUDGET

    mod_names = re.findall(r'^\s*(?:pub\s+)?mod\s+([A-Za-z_]\w*)\s*;', code, re.MULTILINE)
    use_specs = re.findall(r'^\s*use\s+([^;]+);', code, re.MULTILINE)

    candidates = []
    for name in mod_names:
        candidates.extend(_rust_mod_candidates(filepath.parent, name))

    for spec in use_specs:
        candidates.extend(_rust_use_candidates(spec, filepath, crate_root))

    for candidate in _dedupe_paths(candidates):
        key = str(candidate)
        if key in seen or not candidate.is_file():
            continue
        seen.add(key)
        try:
            content = candidate.read_text(errors="replace")
        except OSError:
            continue
        decls = _extract_rust_declarations(content)
        if decls:
            rel = str(candidate.relative_to(source_root)) if candidate.is_relative_to(source_root) else str(candidate)
            snippet = f"// --- {rel} (declarations) ---\n{decls}"
            if len(snippet) <= budget:
                snippets.append(snippet)
                budget -= len(snippet)

    return "\n".join(snippets)


def _guess_rust_crate_root(source_root: Path, filepath: Path) -> Path:
    """Guess the crate root directory for a Rust source file."""
    for parent in [filepath.parent, *filepath.parents]:
        if parent == source_root.parent:
            break
        if (parent / "Cargo.toml").exists():
            src_dir = parent / "src"
            return src_dir if src_dir.is_dir() else parent
    src_dir = source_root / "src"
    return src_dir if src_dir.is_dir() else source_root


def _rust_mod_candidates(base_dir: Path, name: str) -> List[Path]:
    """Return candidate file paths for a Rust mod declaration."""
    return [base_dir / f"{name}.rs", base_dir / name / "mod.rs"]


def _rust_use_candidates(spec: str, filepath: Path, crate_root: Path) -> List[Path]:
    """Return candidate module files for a Rust use path."""
    spec = spec.strip()
    spec = re.sub(r'\s+as\s+\w+$', "", spec)
    spec = spec.replace("::{self", "").replace(", self}", "")
    head = spec.split("::")
    if not head:
        return []

    if head[0] == "crate":
        parts = [part for part in head[1:] if part and part != "self"]
        return _rust_module_chain_candidates(crate_root, parts)
    if head[0] == "super":
        up = 0
        while up < len(head) and head[up] == "super":
            up += 1
        base = filepath.parent
        for _ in range(up):
            base = base.parent
        parts = [part for part in head[up:] if part and part != "self"]
        return _rust_module_chain_candidates(base, parts)
    if head[0] == "self":
        parts = [part for part in head[1:] if part and part != "self"]
        return _rust_module_chain_candidates(filepath.parent, parts)
    return []


def _rust_module_chain_candidates(base: Path, parts: List[str]) -> List[Path]:
    """Resolve a Rust module chain to possible source files."""
    if not parts:
        return []
    current = base
    candidates = []
    for idx, part in enumerate(parts):
        file_candidate = current / f"{part}.rs"
        mod_candidate = current / part / "mod.rs"
        if idx == len(parts) - 1:
            candidates.extend([file_candidate, mod_candidate])
        elif mod_candidate.exists():
            current = mod_candidate.parent
        elif file_candidate.exists():
            current = file_candidate.parent
        else:
            current = current / part
    return candidates


def _extract_rust_declarations(content: str) -> str:
    """Extract declarations from Rust source."""
    lines = content.split("\n")
    result = []
    for line in lines:
        stripped = line.strip()
        if re.match(r'^(pub\s+)?(async\s+)?fn\s+\w+', stripped):
            result.append(stripped)
            continue
        if re.match(r'^(pub\s+)?(struct|enum|trait|type|mod)\s+\w+', stripped):
            result.append(stripped)
            continue
        if re.match(r'^impl(?:<[^>]+>)?\s+', stripped):
            result.append(stripped)
            continue
    return "\n".join(result)


def _resolve_bash_sources(code: str, source_dir: str, filepath: Path) -> str:
    """Resolve source/. commands for bash files."""
    sources = re.findall(r'(?:source|\.) ["\'"]?([^\s"\']+)', code)
    if not sources:
        return ""

    snippets = []
    budget = HEADER_BUDGET

    for src in sources:
        name = Path(src).name
        candidates = list(Path(source_dir).rglob(name))
        for candidate in candidates:
            if candidate.is_file():
                try:
                    content = candidate.read_text(errors="replace")
                except OSError:
                    continue
                # Extract function definitions
                funcs = re.findall(r'^(\w+\s*\(\)\s*\{)', content, re.MULTILINE)
                if funcs:
                    rel = str(candidate.relative_to(source_dir))
                    snippet = f"# --- {rel} (functions) ---\n" + "\n".join(funcs)
                    if len(snippet) <= budget:
                        snippets.append(snippet)
                        budget -= len(snippet)
                break

    return "\n".join(snippets)


def _dedupe_paths(paths: List[Path]) -> List[Path]:
    """Preserve order while deduplicating candidate paths."""
    result = []
    seen = set()
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        result.append(path)
    return result


def resolve_includes(code: str, source_dir: str, filepath: Path,
                     profile_name: str) -> str:
    """Resolve local includes/imports and return declaration context.

    Returns a string of resolved declarations to prepend to the source,
    or empty string if nothing found.
    """
    resolvers = {
        "c_cpp": _resolve_c_includes,
        "python": _resolve_python_imports,
        "bash": _resolve_bash_sources,
        "node": _resolve_node_imports,
        "ruby": _resolve_ruby_requires,
        "perl": _resolve_perl_imports,
        "rust": _resolve_rust_modules,
    }
    resolver = resolvers.get(profile_name)
    if not resolver:
        return ""
    result = resolver(code, source_dir, filepath)
    if result:
        return f"\n// === Resolved local declarations (from project headers/imports) ===\n{result}\n// === End resolved declarations ===\n\n"
    return ""


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
        "real_severity": group.get("real_severity"),
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


def find_failed_files(session_dir: Path, stage_name: str) -> List[str]:
    """Find files where every chunk returned an error (context exceeded, etc).

    These files were never actually analyzed and should be forwarded to the
    next pipeline stage rather than silently treated as clean.
    """
    failed = []
    for path in sorted((session_dir / stage_name).rglob("*.json")):
        payload = load_json(path)
        chunks = payload.get("chunks", [])
        if not chunks:
            continue
        all_errored = all(
            c.get("raw_output", "").startswith("[ERROR:")
            for c in chunks
        )
        if all_errored:
            failed.append(payload["file"])
    return failed


def find_chunked_files(session_dir: Path, stage_name: str) -> List[str]:
    """Find files that were split into multiple chunks for a stage.

    Chunked files lose cross-function context and may miss
    vulnerabilities that span multiple parts of the file.  These
    should be forwarded to the next stage even when clean, because
    a larger-context model may catch what the chunks missed.
    """
    chunked = []
    for path in sorted((session_dir / stage_name).rglob("*.json")):
        payload = load_json(path)
        if payload.get("chunk_count", 1) > 1:
            chunked.append(payload["file"])
    return chunked


def load_progress_entries(session_dir: Path) -> List[dict]:
    """Load progress events from the session directory."""
    path = session_dir / "progress.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def compute_stage_stats(session_dir: Path) -> dict:
    """Summarize persisted progress by stage."""
    stats = {}
    for stage in ("triage", "triage_catchup", "triage_confirm",
                  "triage_confirm_callers", "reasoning", "verdict"):
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
                   stage_name: str, source_dir: str, session_dir: Path,
                   triage_hints: Optional[Dict[str, List]] = None):
    """Run a scanning stage over files and persist all outputs.

    triage_hints: when running reasoning stage, optionally maps relpath
    to list of triage findings for that file.  Appended as focus hints
    so the reasoning model knows where triage flagged issues.
    """
    for i, source_file in enumerate(files):
        filepath = source_file.path
        profile = source_file.profile
        relpath = str(filepath.relative_to(source_dir))
        record_path = stage_record_path(session_dir, stage_name, relpath)
        if record_path.exists():
            print(f"  [{i+1}/{len(files)}] {relpath} [{profile.name}] (cached)", flush=True)
            continue

        code = filepath.read_text(errors="replace")

        # Prepend resolved local declarations from headers/imports
        header_ctx = resolve_includes(code, source_dir, filepath, profile.name)
        if header_ctx:
            code = header_ctx + code

        chunks = chunk_file(code)

        print(
            f"  [{i+1}/{len(files)}] {relpath} [{profile.name}] ({len(code)} chars, {len(chunks)} chunk(s))",
            flush=True,
        )

        # Build triage hint suffix for reasoning stage
        hint_suffix = ""
        if triage_hints and relpath in triage_hints:
            hints = triage_hints[relpath]
            hint_lines = []
            for h in hints:
                loc = h.location if hasattr(h, 'location') else h.get('location', '?')
                typ = h.type if hasattr(h, 'type') else h.get('type', '?')
                hint_lines.append(f"  - {loc}: {typ}")
            hint_suffix = (
                "\n\nNOTE: A separate triage scanner flagged these areas "
                "in this file — use this as focus guidance, but do your "
                "own independent analysis:\n" + "\n".join(hint_lines)
            )

        chunk_records = []
        for ci, chunk in enumerate(chunks):
            label = relpath
            if len(chunks) > 1:
                label = f"{relpath} (part {ci+1}/{len(chunks)})"
            user_msg = f"SOURCE FILE: {label}\n```\n{chunk}\n```{hint_suffix}"

            system_prompt = profile.reasoning_prompt
            if stage_name in ("triage", "triage_catchup"):
                system_prompt = profile.triage_prompt
            raw = backend.query(system_prompt, user_msg)

            # On context overflow, re-chunk this chunk smaller and retry
            if raw and "[ERROR: context exceeded]" in raw:
                sub_chunks = chunk_file(chunk, max_chars=len(chunk) // 2 or 1000)
                if len(sub_chunks) > 1:
                    print(f"    [WARN] Context exceeded for {label}, "
                          f"re-chunking into {len(sub_chunks)} smaller pieces",
                          flush=True)
                    for sci, sc in enumerate(sub_chunks):
                        sub_label = f"{relpath} (part {ci+1}.{sci+1}/{len(chunks)})"
                        sub_msg = f"SOURCE FILE: {sub_label}\n```\n{sc}\n```{hint_suffix}"
                        sub_raw = backend.query(system_prompt, sub_msg)
                        if not sub_raw or not sub_raw.strip():
                            sub_raw = backend.query(system_prompt, sub_msg)
                            if not sub_raw or not sub_raw.strip():
                                sub_raw = "[ERROR: empty response from model after retry]"
                        sub_findings = parse_findings(sub_raw, relpath, repr(backend), stage_name)
                        chunk_records.append({
                            "chunk_index": len(chunk_records) + 1,
                            "label": sub_label,
                            "raw_output": sub_raw,
                            "findings": [asdict(f) for f in sub_findings],
                        })
                        if sub_findings:
                            for f in sub_findings:
                                print(f"    -> {f.severity}: {f.location} ({f.type})", flush=True)
                    continue

            # Retry once on empty response — models sometimes silently
            # return empty when near context limits
            if not raw or not raw.strip():
                print(f"    [WARN] Empty response, retrying...", flush=True)
                raw = backend.query(system_prompt, user_msg)
                if not raw or not raw.strip():
                    raw = "[ERROR: empty response from model after retry]"
                    print(f"    [ERROR] Empty response persists for {label}", flush=True)

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


def run_function_level_triage(files: List[SourceFile], backend: Backend,
                              source_dir: str, session_dir: Path):
    """Run paranoid triage on each function individually.

    Extracts functions from C/C++ files and scans each one separately
    with the paranoid triage prompt.  This catches subtle bugs (like
    arithmetic errors in buffer calculations) that get lost when the
    model sees the entire file at once.

    For non-C/C++ files, falls back to whole-file scanning.
    """
    stage_name = "triage_catchup"

    for i, source_file in enumerate(files):
        filepath = source_file.path
        profile = source_file.profile
        relpath = str(filepath.relative_to(source_dir))
        record_path = stage_record_path(session_dir, stage_name, relpath)
        if record_path.exists():
            print(f"  [{i+1}/{len(files)}] {relpath} (cached)", flush=True)
            continue

        code = filepath.read_text(errors="replace")

        # Extract functions via the right language extractor, or fall
        # back to whole-file scanning for unsupported profiles.
        functions = extract_functions(code, profile.name)
        if not functions:
            functions = [("(whole file)", code)]

        print(
            f"  [{i+1}/{len(files)}] {relpath} [{profile.name}] "
            f"({len(functions)} function(s))",
            flush=True,
        )

        system_prompt = profile.triage_prompt
        chunk_records = []

        for fi, (func_name, func_code) in enumerate(functions):
            label = f"{relpath}::{func_name}"
            user_msg = f"SOURCE FILE: {label}\n```\n{func_code}\n```"

            raw = backend.query(system_prompt, user_msg)

            if not raw or not raw.strip():
                raw = backend.query(system_prompt, user_msg)
                if not raw or not raw.strip():
                    raw = "[ERROR: empty response from model after retry]"

            findings = parse_findings(raw, relpath, repr(backend), stage_name)
            chunk_records.append({
                "chunk_index": fi + 1,
                "label": label,
                "raw_output": raw,
                "findings": [asdict(f) for f in findings],
            })
            if findings:
                for f in findings:
                    print(f"    -> {f.severity}: {f.location} ({f.type})", flush=True)

        save_stage_file_output(session_dir, stage_name, backend, relpath, chunk_records)


# ── Confirmation passes (2 and 3) ──────────────────────────────────────

CONFIRMATION_PROMPT = """A previous function-level scan flagged a
potential vulnerability:

FINDING:
SEVERITY: {severity}
LOCATION: {location}
TYPE: {type}
DESCRIPTION: {description}

Now I'm showing you the WHOLE file. Decide which of these applies:

  CONFIRMED — one of:
    (a) the exact mechanism described is real and exploitable, OR
    (b) the described mechanism is slightly wrong but a related real
        vulnerability exists in the same code (e.g. the bug is in a
        helper the finding didn't name, or the category label is off
        but the code is genuinely unsafe).  State the corrected
        mechanism in REASONING.

  FALSE_POSITIVE — the code is genuinely safe.  Your reasoning must:
    - If rejecting due to preconditions: cite the specific check and
      where it lives.
    - If rejecting because input is "not attacker-controlled" or
      "physically impossible": state the concrete assumption and
      whether it is enforced by code visible in this file or merely
      trusted from an external library, kernel, or filesystem layout.
      Trusted-from-upstream is weaker than enforced-in-scope.

  NEED_CALLERS — you cannot decide without seeing how specific functions
    are called from other files.  Specify which functions.

CALLER-PROOF RULE: If your reasoning says a function parameter is
"attacker-controlled" or "user-supplied", you MUST cite at least one
concrete call site (from the cross-file references below, or from
within this file) where untrusted data actually reaches that parameter.
If no such call site is visible, use NEED_CALLERS — do NOT assume
parameters are attacker-controlled just because they could theoretically
be. Conversely, if cross-file references show callers pass only trusted
values (constants, root-owned paths, compile-time sizes), that is
evidence for FALSE_POSITIVE.
{caller_context}

KEY PROCEDURE — when the finding involves a sink that calls a helper
(allocator, validator, reserve/resize/grow, length-check), DO NOT just
refute the finding's wording.  Open the helper's code and check it
branch by branch.

For grow/resize/reserve helpers specifically:
  - Identify every branch that sets the new capacity `s`.
  - For each branch, find concrete (existing_length, current_size,
    requested_add) tuples that reach that branch.
  - For each branch, check: does `s >= existing_length + requested_add
    + 1` (where +1 covers a null terminator, if applicable)?
  - A doubling branch (`s = size * 2`) is a classic bug site: if the
    guard only ensures `size * 2 >= add + 1` but not `size * 2 >=
    len + add + 1`, then a full buffer (len ≈ size) with moderate add
    overflows the realloc'd region.
  - Do NOT accept "the helper returns success so it must be fine";
    prove the post-resize capacity in every branch.

For validator helpers: check each input class the validator accepts,
not just the class the finding mentions.

For integer-arithmetic bugs: if the finding mentions overflow, consider
whether the arithmetic can also silently truncate, wrap to a small
value, or produce a negative signed value that becomes a huge unsigned
after a cast.

If while evaluating this finding you notice a SEPARATE real
vulnerability in the same file, surface it as ADDITIONAL_FINDING.
{contracts}{hints}
Respond in this exact format (no other text):

OUTCOME: CONFIRMED | FALSE_POSITIVE | NEED_CALLERS
REASONING: <concrete path from input to sink; OR what specifically
            rules out exploitation.  If CONFIRMED (b), name the real
            mechanism and the function/branch that owns the root cause.
            For resize helpers, show the (len, size, add) tuple that
            triggers the unsafe branch, or prove every branch is safe.>
CALLERS_OF: <comma-separated function names, only if NEED_CALLERS>
ADDITIONAL_FINDING: <optional — SEVERITY / LOCATION / TYPE / DESCRIPTION
                     of a separate vuln noticed in passing; omit the
                     line entirely if none>

Source file:
```
{code}
```"""


CALLER_PROMPT = """You previously flagged a vulnerability and said you
needed to see callers from other files to judge exploitability:

FINDING:
SEVERITY: {severity}
LOCATION: {location}
TYPE: {type}
DESCRIPTION: {description}

PREVIOUS REASONING: {reasoning}

Below are heuristic cross-file references (grep-based lines that mention
the requested symbols). They are NOT verified call edges — a line that
looks like a call may be a comment, a declaration, a string literal, a
same-name symbol in a different namespace, or a match inside an unrelated
macro. Use them only as auxiliary context: if a reference is genuinely
a call with attacker-reachable input, it supports CONFIRMED; if every
candidate reference is ambiguous or non-callable, that does NOT by
itself prove the sink is unreachable.

{callers}

Given these references, finalize your evaluation:

OUTCOME: CONFIRMED | FALSE_POSITIVE
REASONING: <why — if CONFIRMED, name the specific reference line that
            represents a real call and trace untrusted input from there
            to the sink. If FALSE_POSITIVE, explain what rules out
            exploitation without over-trusting the grep results.>
"""


def _parse_confirmation_outcome(raw: str) -> dict:
    """Parse OUTCOME / REASONING / CALLERS_OF lines from a confirmation response."""
    outcome_m = re.search(
        r"OUTCOME:\s*(CONFIRMED|FALSE_POSITIVE|NEED_CALLERS)",
        raw,
    )
    outcome = outcome_m.group(1) if outcome_m else "UNPARSED"
    # REASONING is everything after REASONING: up to CALLERS_OF:,
    # ADDITIONAL_FINDING:, or EOF
    reason_m = re.search(
        r"REASONING:\s*(.+?)(?=\n\s*CALLERS_OF:|\n\s*ADDITIONAL_FINDING:|\Z)",
        raw, re.DOTALL,
    )
    reasoning = reason_m.group(1).strip() if reason_m else ""
    callers_m = re.search(
        r"CALLERS_OF:\s*(.+?)(?=\n\s*ADDITIONAL_FINDING:|\n|$)", raw,
    )
    callers_of = callers_m.group(1).strip() if callers_m else ""
    # ADDITIONAL_FINDING is free-form — the model may put a multi-line
    # description or a compact one-liner.  Capture everything up to EOF.
    additional_m = re.search(
        r"ADDITIONAL_FINDING:\s*(.+?)\Z", raw, re.DOTALL,
    )
    additional = additional_m.group(1).strip() if additional_m else ""
    return {
        "outcome": outcome,
        "reasoning": reasoning,
        "callers_of": callers_of,
        "additional_finding": additional,
        "raw": raw,
    }


def run_confirmation_pass(catchup_findings: List[Finding],
                          files: List[SourceFile],
                          backend: Backend,
                          source_dir: str,
                          session_dir: Path,
                          contract_packs: Optional[List[ContractPack]] = None,
                          package_hints: Optional[PackageHints] = None,
                          finding_annotations: Optional[Dict[str, str]] = None,
                          ) -> Dict[str, dict]:
    """Whole-file confirmation pass (pass 2) for catch-up findings.

    For each finding from function-level catch-up, re-send the finding
    plus the whole file and ask whether it holds up in the broader
    context.  Saves one JSON per file to session_dir/triage_confirm/.

    Returns a dict keyed by finding.key() mapping to the parsed
    outcome (outcome, reasoning, callers_of, raw).
    """
    stage_name = "triage_confirm"
    (session_dir / stage_name).mkdir(exist_ok=True)
    file_by_relpath = {str(sf.path.relative_to(source_dir)): sf for sf in files}

    # Group findings by file
    by_file: Dict[str, List[Finding]] = {}
    for f in catchup_findings:
        by_file.setdefault(f.file, []).append(f)

    results: Dict[str, dict] = {}

    for i, (relpath, file_findings) in enumerate(sorted(by_file.items())):
        record_path = session_dir / stage_name / f"{relpath}.json"
        if record_path.exists():
            payload = load_json(record_path)
            for ev in payload.get("evaluations", []):
                results[ev["finding_key"]] = ev
            print(f"  [{i+1}/{len(by_file)}] {relpath} (cached)", flush=True)
            continue

        source_file = file_by_relpath.get(relpath)
        if source_file is None:
            continue

        code = source_file.path.read_text(errors="replace")
        # Cap to avoid blowing context
        if len(code) > 40000:
            code = code[:40000] + "\n\n// ... [file truncated]"

        contract_entries = contracts_for_code(code, contract_packs or [])
        contracts_text = format_contracts_prompt(contract_entries)

        print(
            f"  [{i+1}/{len(by_file)}] {relpath} ({len(file_findings)} finding(s))"
            + (f" [{len(contract_entries)} contract(s)]" if contract_entries else ""),
            flush=True,
        )

        evaluations = []
        for finding in file_findings:
            caller_ctx = find_cross_references(
                finding, source_dir, relpath,
            )
            hints_text = format_hints_prompt(package_hints) if package_hints else ""
            annotation = (finding_annotations or {}).get(finding.key(), "")
            prompt = CONFIRMATION_PROMPT.format(
                severity=finding.severity,
                location=finding.location,
                type=finding.type,
                description=finding.description + annotation,
                code=code,
                contracts=contracts_text,
                hints=hints_text,
                caller_context=caller_ctx,
            )
            raw = backend.query("", prompt)
            if not raw or not raw.strip():
                raw = backend.query("", prompt)
                if not raw or not raw.strip():
                    raw = "[ERROR: empty response from model after retry]"
            parsed = _parse_confirmation_outcome(raw)
            parsed["finding_key"] = finding.key()
            evaluations.append(parsed)
            results[finding.key()] = parsed
            print(f"    -> {parsed['outcome']}: {finding.location}", flush=True)

        record_path.parent.mkdir(parents=True, exist_ok=True)
        write_json(record_path, {
            "file": relpath,
            "stage": stage_name,
            "backend": repr(backend),
            "created_at": utc_now(),
            "evaluations": evaluations,
        })
        append_jsonl(
            session_dir / "progress.jsonl",
            {
                "created_at": utc_now(),
                "stage": stage_name,
                "file": relpath,
                "backend": repr(backend),
                "chunk_count": len(evaluations),
                "finding_count": sum(1 for e in evaluations
                                     if e["outcome"] == "CONFIRMED"),
            },
        )

    return results


def run_caller_pass(catchup_findings: List[Finding],
                    confirmation_results: Dict[str, dict],
                    backend: Backend,
                    source_dir: str,
                    session_dir: Path) -> Dict[str, dict]:
    """Caller-context pass (pass 3) for findings that asked for callers.

    For each catch-up finding whose confirmation said NEED_CALLERS,
    use find_cross_references to pull call sites from other files and
    ask the model to finalize its verdict.  Saves per-file JSON to
    session_dir/triage_confirm_callers/.

    Returns a dict keyed by finding.key() with updated outcomes.
    """
    stage_name = "triage_confirm_callers"

    # Filter to findings with NEED_CALLERS outcome
    needs = [
        f for f in catchup_findings
        if confirmation_results.get(f.key(), {}).get("outcome") == "NEED_CALLERS"
    ]
    if not needs:
        return {}

    (session_dir / stage_name).mkdir(exist_ok=True)
    by_file: Dict[str, List[Finding]] = {}
    for f in needs:
        by_file.setdefault(f.file, []).append(f)

    results: Dict[str, dict] = {}

    for i, (relpath, file_findings) in enumerate(sorted(by_file.items())):
        record_path = session_dir / stage_name / f"{relpath}.json"
        if record_path.exists():
            payload = load_json(record_path)
            for ev in payload.get("evaluations", []):
                results[ev["finding_key"]] = ev
            print(f"  [{i+1}/{len(by_file)}] {relpath} (cached)", flush=True)
            continue

        print(
            f"  [{i+1}/{len(by_file)}] {relpath} ({len(file_findings)} finding(s))",
            flush=True,
        )

        evaluations = []
        for finding in file_findings:
            prior = confirmation_results.get(finding.key(), {})
            # Honor CALLERS_OF if the model specified which symbols it needs
            requested = prior.get("callers_of", "")
            requested_symbols = [
                s.strip() for s in re.split(r'[,\s]+', requested) if s.strip()
            ] if requested else None
            callers = find_cross_references(
                finding, source_dir, finding.file,
                symbols=requested_symbols,
            )
            if not callers:
                callers = "(no call sites found in other files)"
            prompt = CALLER_PROMPT.format(
                severity=finding.severity,
                location=finding.location,
                type=finding.type,
                description=finding.description,
                reasoning=prior.get("reasoning", ""),
                callers=callers,
            )
            raw = backend.query("", prompt)
            if not raw or not raw.strip():
                raw = backend.query("", prompt)
                if not raw or not raw.strip():
                    raw = "[ERROR: empty response from model after retry]"
            parsed = _parse_confirmation_outcome(raw)
            parsed["finding_key"] = finding.key()
            evaluations.append(parsed)
            results[finding.key()] = parsed
            print(f"    -> {parsed['outcome']}: {finding.location}", flush=True)

        record_path.parent.mkdir(parents=True, exist_ok=True)
        write_json(record_path, {
            "file": relpath,
            "stage": stage_name,
            "backend": repr(backend),
            "created_at": utc_now(),
            "evaluations": evaluations,
        })
        append_jsonl(
            session_dir / "progress.jsonl",
            {
                "created_at": utc_now(),
                "stage": stage_name,
                "file": relpath,
                "backend": repr(backend),
                "chunk_count": len(evaluations),
                "finding_count": sum(1 for e in evaluations
                                     if e["outcome"] == "CONFIRMED"),
            },
        )

    return results


def load_confirmation_results(session_dir: Path,
                              stage_name: str = "triage_confirm") -> Dict[str, dict]:
    """Load all confirmation evaluations from a session stage."""
    results: Dict[str, dict] = {}
    stage_dir = session_dir / stage_name
    if not stage_dir.exists():
        return results
    for path in sorted(stage_dir.rglob("*.json")):
        payload = load_json(path)
        for ev in payload.get("evaluations", []):
            results[ev["finding_key"]] = ev
    return results


def find_cross_references(finding: Finding, source_dir: str,
                          finding_file: str,
                          symbols: Optional[List[str]] = None) -> str:
    """Find likely cross-file references for the flagged symbol.

    This is a heuristic: it extracts likely symbols from the finding
    and searches other project files for invocation-shaped references.

    If ``symbols`` is given, use those names verbatim instead of
    guessing from the finding.  Useful when the model explicitly
    requests callers of a specific function via CALLERS_OF.
    """
    if symbols:
        candidates = [s for s in symbols if s]
    else:
        location = finding.location or ""
        candidates = []
        match = re.match(r'(\w+(?:::\w+)?)', location)
        if match:
            candidates.append(match.group(1))
        if finding.sink:
            sink_match = re.match(r'[`]?(\w+(?:::\w+)?)', finding.sink)
            if sink_match:
                candidates.append(sink_match.group(1))

    if not candidates:
        return ""

    snippets = []
    seen = set()
    budget = 6000  # chars budget for cross-references
    src = Path(source_dir)
    include_patterns = [
        "*.cpp", "*.c", "*.h", "*.hpp",
        "*.py", "*.rb", "*.rake", "*.gemspec", "*.sh",
        "*.rs", "*.js", "*.ts", "*.mjs", "*.cjs",
        "*.pl", "*.pm", "*.t",
    ]

    for term in candidates:
        if term.lower() in ("return", "if", "for", "while", "int", "void",
                            "string", "char", "bool", "auto", "const"):
            continue
        pattern = _cross_reference_regex(term)
        if not pattern:
            continue
        try:
            result = subprocess.run(
                ["grep", "-rEn", *[f"--include={p}" for p in include_patterns],
                 pattern, source_dir],
                capture_output=True, text=True, timeout=10,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue

        for line in result.stdout.splitlines():
            try:
                match_file, lineno, content = line.split(":", 2)
                relpath = str(Path(match_file).relative_to(src))
            except (ValueError, IndexError):
                continue
            if relpath == finding_file:
                continue
            if not _looks_like_cross_reference(content, term):
                continue
            snippet = f"{relpath}:{lineno}:{content.strip()}"
            if snippet in seen:
                continue
            seen.add(snippet)
            if len(snippet) <= budget:
                snippets.append(snippet)
                budget -= len(snippet) + 1
            if budget <= 0:
                break
        if budget <= 0:
            break

    if not snippets:
        return ""

    return (
        "\n\nPOSSIBLE CROSS-FILE REFERENCES:\n"
        "These are heuristic reference lines from other files, not verified call sites.\n"
        "Use them only as auxiliary context when judging exploitability.\n"
        + "\n".join(snippets)
    )


def _cross_reference_regex(term: str) -> str:
    """Build a grep regex for invocation-shaped references to a symbol."""
    escaped = re.escape(term)
    if "::" in term:
        return rf'(^|[^A-Za-z0-9_]){escaped}\s*\('
    return rf'(^|[^A-Za-z0-9_:.>])(?:[A-Za-z_]\w*(?:::\w+|->\w+|\.\w+)?\s*)?{escaped}\s*\('


def _looks_like_cross_reference(content: str, term: str) -> bool:
    """Filter grep matches down to plausible invocation references."""
    stripped = content.strip()
    if not stripped:
        return False
    if stripped.startswith(("#", "//", "/*", "*", "import ", "from ", "use ",
                            "require ", "require_relative ", "include ", ".include")):
        return False
    if re.match(r'^\s*(class|struct|enum|typedef|using|namespace|module|package|trait|impl)\b', stripped):
        return False
    if re.match(r'^\s*(def|sub|fn)\s+', stripped):
        return False
    if re.match(r'^\s*(public|private|protected|static|virtual|inline|extern|export)\b.*\b'
                + re.escape(term.split("::")[-1]) + r'\s*\(', stripped):
        return False
    if re.match(r'^\s*[\w:<>&*\[\],\s]+\b' + re.escape(term.split("::")[-1]) + r'\s*\([^;{]*\)\s*(?:\{|;)?\s*$',
                stripped):
        return False
    if re.match(r'^\s*[^=]+=\s*["\'][^"\']*' + re.escape(term.split("::")[-1]) + r'\s*\([^"\']*["\']\s*;?\s*$',
                stripped):
        return False
    if re.match(r'^[\'"`].*[\'"`]\s*$', stripped):
        return False
    return True


# ── Codec direction analysis ──────────────────────────────────────────

_CODEC_FUNC_RE = re.compile(r'\b(xdr_\w+|asn1_\w+|ber_\w+|der_\w+)\b')

_XDR_ENCODE_PATTERNS = [
    re.compile(r'\bclnt_call\s*\([^,]+,\s*\w+\s*,\s*\(\s*xdrproc_t\s*\)\s*(\w+)'),
    re.compile(r'\bXDR_ENCODE\b'),
    re.compile(r'\bxdrmem_create\s*\([^)]*XDR_ENCODE'),
    re.compile(r'\bxdrrec_create\s*\([^)]*XDR_ENCODE'),
]

_XDR_DECODE_PATTERNS = [
    re.compile(r'\bclnt_call\s*\([^,]+,[^,]+,[^,]+,[^,]+,\s*\(\s*xdrproc_t\s*\)\s*(\w+)'),
    re.compile(r'\bXDR_DECODE\b'),
    re.compile(r'\bxdrmem_create\s*\([^)]*XDR_DECODE'),
    re.compile(r'\bxdr_replymsg\b'),
]


def analyze_codec_directions(source_dir: str) -> Dict[str, str]:
    results: Dict[str, str] = {}
    src = Path(source_dir)
    for p in sorted(src.rglob("*.[ch]")):
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        codec_funcs = set(_CODEC_FUNC_RE.findall(text))
        if not codec_funcs:
            continue
        for func in codec_funcs:
            if func in results:
                continue
            is_encoder = any(
                func in (m.group(1) if m.lastindex else "")
                for pat in _XDR_ENCODE_PATTERNS
                for m in pat.finditer(text)
            ) or any(
                pat.search(text) and func in text
                for pat in _XDR_ENCODE_PATTERNS
                if not pat.groups
            )
            is_decoder = any(
                func in (m.group(1) if m.lastindex else "")
                for pat in _XDR_DECODE_PATTERNS
                for m in pat.finditer(text)
            ) or any(
                pat.search(text) and func in text
                for pat in _XDR_DECODE_PATTERNS
                if not pat.groups
            )
            if is_encoder and is_decoder:
                results[func] = "both"
            elif is_encoder:
                results[func] = "encode"
            elif is_decoder:
                results[func] = "decode"
    return results


def format_codec_directions(directions: Dict[str, str]) -> str:
    if not directions:
        return ""
    lines = [
        "\n\n// === Codec direction analysis ===\n"
        "// Usage direction of XDR/ASN.1 codec functions in this package.\n"
        "// Decode-side bugs do NOT apply to encode-only usage.\n"
    ]
    for func, direction in sorted(directions.items()):
        lines.append(f"  {func}: {direction}")
    lines.append("// === End codec direction analysis ===\n")
    return "\n".join(lines)


# ── Build/install metadata ────────────────────────────────────────────

_MESON_FUNC_START_RE = re.compile(
    r"(executable|shared_library|static_library|install_data|install_headers)"
    r"\s*\(\s*'([^']+)'"
)


def _extract_meson_block(text: str, start: int) -> str:
    """Extract a balanced-paren block starting from the '(' after function name."""
    paren_pos = text.find("(", start)
    if paren_pos < 0:
        return ""
    depth = 0
    i = paren_pos
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[paren_pos + 1:i]
        elif ch == "#":
            nl = text.find("\n", i)
            i = nl if nl >= 0 else len(text)
            continue
        elif ch in ("'", '"'):
            close = text.find(ch, i + 1)
            if close >= 0:
                i = close
        i += 1
    return text[paren_pos + 1:]

_SPEC_ATTR_RE = re.compile(
    r"^%attr\s*\(\s*([0-7]+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)\s*(.+)$",
    re.MULTILINE,
)
_SPEC_FILES_RE = re.compile(
    r"^(/\S+)",
    re.MULTILINE,
)


def extract_meson_install_metadata(source_dir: str) -> List[dict]:
    results = []
    src = Path(source_dir)
    for meson_file in sorted(src.rglob("meson.build")):
        try:
            text = meson_file.read_text(errors="replace")
        except OSError:
            continue
        for m in _MESON_FUNC_START_RE.finditer(text):
            name = m.group(2)
            body = _extract_meson_block(text, m.start())
            inst_m = re.search(r'install\s*:\s*(true|false)', body)
            if not inst_m:
                continue
            installed = inst_m.group(1) == "true"
            mode_m = re.search(r"install_mode\s*:\s*\[([^\]]*)\]", body)
            if not mode_m:
                mode_m = re.search(r"install_mode\s*:\s*'([^']*)'", body)
            mode_str = mode_m.group(1).split(",")[0].strip("' \"") if mode_m else ""
            setuid = ("s" in mode_str[:4] or mode_str.startswith("4")) if mode_str else False
            results.append({
                "name": name,
                "installed": installed,
                "setuid": setuid,
                "source": str(meson_file.relative_to(src)),
            })
    return results


def extract_spec_install_metadata(source_dir: str) -> List[dict]:
    results = []
    src = Path(source_dir)
    for spec_file in sorted(src.rglob("*.spec")):
        try:
            text = spec_file.read_text(errors="replace")
        except OSError:
            continue
        in_files = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("%files"):
                in_files = True
                continue
            if in_files and stripped.startswith("%"):
                if not stripped.startswith("%attr") and not stripped.startswith("%dir"):
                    in_files = False
                    continue
            if not in_files:
                continue
            attr_m = _SPEC_ATTR_RE.match(stripped)
            if attr_m:
                mode, user, group, path = attr_m.groups()
                setuid = mode.startswith("4")
                results.append({
                    "path": path.strip(),
                    "mode": mode,
                    "user": user,
                    "group": group,
                    "setuid": setuid,
                    "source": str(spec_file.relative_to(src)),
                })
            else:
                file_m = _SPEC_FILES_RE.match(stripped)
                if file_m:
                    results.append({
                        "path": file_m.group(1).strip(),
                        "mode": "",
                        "user": "",
                        "group": "",
                        "setuid": False,
                        "source": str(spec_file.relative_to(src)),
                    })
    return results


def format_install_metadata(meson_meta: List[dict],
                            spec_meta: List[dict]) -> str:
    if not meson_meta and not spec_meta:
        return ""
    lines = [
        "\n\n// === Install metadata ===\n"
    ]
    if meson_meta:
        lines.append("// From meson.build:")
        for m in meson_meta:
            status = "installed" if m["installed"] else "NOT installed"
            setuid = " (SETUID)" if m["setuid"] else ""
            lines.append(f"  {m['name']}: {status}{setuid}  ({m['source']})")
    if spec_meta:
        lines.append("// From RPM .spec:")
        for s in spec_meta:
            setuid = " (SETUID)" if s["setuid"] else ""
            mode = f" mode={s['mode']}" if s["mode"] else ""
            lines.append(f"  {s['path']}{mode}{setuid}  ({s['source']})")
    lines.append("// === End install metadata ===\n")
    return "\n".join(lines)


_CONFIG_DEFAULT_RE = re.compile(
    r'^\s*#\s*define\s+(DEFAULT_\w+|ENABLE_\w+|DISABLE_\w+|USE_\w+|'
    r'WITH_\w+|WITHOUT_\w+|OPT_\w+|HAVE_\w+)\s+(.+?)(?:\s*/\*.*)?$',
    re.MULTILINE,
)


def extract_config_defaults(source_dir: str) -> str:
    defaults = []
    seen = set()
    src = Path(source_dir)
    for p in sorted(src.rglob("*.[ch]")):
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        for m in _CONFIG_DEFAULT_RE.finditer(text):
            macro, value = m.group(1), m.group(2).strip()
            if macro in seen:
                continue
            seen.add(macro)
            relpath = str(p.relative_to(src))
            defaults.append(f"  {macro} = {value}  ({relpath})")
    if not defaults:
        return ""
    return (
        "\n\n// === Package config defaults (from source #define) ===\n"
        + "\n".join(defaults[:50])
        + "\n// === End config defaults ===\n"
    )


def run_verdict_stage(consensus: List[dict], backend: Backend,
                      source_dir: str, session_dir: Path,
                      profile_by_file: dict,
                      package_hints: Optional[PackageHints] = None,
                      ) -> List[dict]:
    """Run verdict stage: verify findings against source code."""
    # Load any confirmation-pass outputs so we can show them to verdict
    confirm_results = load_confirmation_results(session_dir, "triage_confirm")
    caller_results = load_confirmation_results(session_dir, "triage_confirm_callers")
    config_defaults_section = extract_config_defaults(source_dir)
    codec_directions = analyze_codec_directions(source_dir)
    meson_meta = extract_meson_install_metadata(source_dir)
    spec_meta = extract_spec_install_metadata(source_dir)
    install_section = format_install_metadata(meson_meta, spec_meta)
    codec_section = format_codec_directions(codec_directions)

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

        # Find cross-references: how are the flagged functions called
        # from other files? This gives verdict the caller context it
        # needs to assess exploitability without seeing every file.
        xrefs = ""
        for f in group["findings"]:
            xrefs += find_cross_references(
                f, source_dir, group["findings"][0].file
            )

        # Format findings by stage so verdict sees what each scanner found
        triage_items = [f for f in group["findings"] if f.stage == "triage"]
        reasoning_items = [f for f in group["findings"] if f.stage == "reasoning"]
        consensus_note, hypothesis_note = build_verdict_group_notes(group)

        # Collect confirmation-pass notes for findings in this group
        confirm_notes = []
        for f in group["findings"]:
            ev = confirm_results.get(f.key())
            if ev:
                note = (f"Confirmation pass (whole-file): {ev['outcome']}\n"
                        f"  Reasoning: {ev['reasoning']}")
                confirm_notes.append(note)
            ev_caller = caller_results.get(f.key())
            if ev_caller:
                note = (f"Caller-context pass: {ev_caller['outcome']}\n"
                        f"  Reasoning: {ev_caller['reasoning']}")
                confirm_notes.append(note)

        aux_section = ""
        if xrefs:
            aux_section += (
                "\n\n// === Auxiliary cross-file reference hints ===\n"
                "// The following section is heuristic context from other files.\n"
                "// It is not part of the source file above and it is not a verified call graph.\n"
                f"{xrefs}\n"
                "// === End auxiliary cross-file reference hints ===\n"
            )
        if confirm_notes:
            aux_section += (
                "\n\n// === Prior confirmation pass notes ===\n"
                "// The triage model was asked to re-evaluate its function-level\n"
                "// findings against the whole file (and cross-file callers where\n"
                "// requested).  Treat this as prior analysis, not ground truth.\n"
                + "\n\n".join(confirm_notes) +
                "\n// === End confirmation pass notes ===\n"
            )
        if config_defaults_section:
            aux_section += config_defaults_section
        if codec_section:
            aux_section += codec_section
        if install_section:
            aux_section += install_section
        hints_section = format_hints_prompt(package_hints) if package_hints else ""
        if hints_section:
            aux_section += hints_section

        prompt = profile.verdict_prompt_template.format(
            filename=group["findings"][0].file,
            triage_findings=format_findings_for_verdict(triage_items),
            reasoning_findings=format_findings_for_verdict(reasoning_items),
            consensus_note=consensus_note,
            hypothesis_note=hypothesis_note,
            code=code + aux_section,
        )
        raw = backend.query("", prompt)
        group["verdict_raw"] = raw

        # Parse verdict — new actionability labels + backward compat
        verdict_match = re.search(
            r"VERDICT:\s*(REPORT_IF_CONFIGURED|REPORT|UPSTREAM_HARDENING|"
            r"NEEDS_REPRODUCER|NOISE|CONFIRMED|FALSE_POSITIVE|NEEDS_CONTEXT)",
            raw,
        )
        if verdict_match:
            v = verdict_match.group(1)
            _COMPAT = {
                "CONFIRMED": "REPORT",
                "FALSE_POSITIVE": "NOISE",
                "NEEDS_CONTEXT": "NEEDS_REPRODUCER",
            }
            group["verdict"] = _COMPAT.get(v, v)
        else:
            group["verdict"] = "NEEDS_REPRODUCER"
        severity_match = re.search(r"REAL_SEVERITY:\s*(Critical|High|Medium|Low|None)", raw)
        group["real_severity"] = severity_match.group(1) if severity_match else None

        source_m = re.search(r"SOURCE_OWNER:\s*(\S+)", raw)
        group["source_owner"] = source_m.group(1) if source_m else ""
        config_m = re.search(r"CONFIG_GATE:\s*(\S+)", raw)
        group["config_gate"] = config_m.group(1) if config_m else ""
        sink_m = re.search(r"SINK_PRIVILEGE:\s*(\S+)", raw)
        group["sink_privilege"] = sink_m.group(1) if sink_m else ""

        status = group["verdict"]
        triad = ""
        if group["source_owner"] or group["config_gate"] or group["sink_privilege"]:
            triad = (f" [{group['source_owner'] or '?'} / "
                     f"{group['config_gate'] or '?'} / "
                     f"{group['sink_privilege'] or '?'}]")
        print(f"  {group['findings'][0].file}: {status}{triad}", flush=True)
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

    nonprod_files = [f for f in files if f.file_class != "production"]
    prod_files = [f for f in files if f.file_class == "production"]
    if nonprod_files:
        by_class: Dict[str, int] = {}
        for f in nonprod_files:
            by_class[f.file_class] = by_class.get(f.file_class, 0) + 1
        class_summary = ", ".join(f"{n} {cls}" for cls, n in sorted(by_class.items()))
        print(f"\nFile classification: {len(prod_files)} production, "
              f"{len(nonprod_files)} suppressed ({class_summary})", flush=True)
        suppress_dir = session_dir / "suppressed_files"
        suppress_dir.mkdir(exist_ok=True)
        write_json(suppress_dir / "nonprod.json", {
            "created_at": utc_now(),
            "files": [
                {"path": str(f.path.relative_to(source_dir)), "class": f.file_class}
                for f in nonprod_files
            ],
        })
    files = prod_files

    result.files_scanned = len(files)

    contracts_spec = getattr(args, "contracts", "auto")
    contract_packs = load_contract_packs(contracts_spec, files)
    if contract_packs:
        pack_names = ", ".join(p.name for p in contract_packs)
        n_contracts = sum(len(p.contracts) for p in contract_packs)
        print(f"\nContracts: {pack_names} ({n_contracts} entries)", flush=True)

    package_hints = load_package_hints(source_dir)
    if package_hints:
        print(f"\nPackage hints: {len(package_hints.facts)} fact(s), "
              f"{len(package_hints.dismiss_patterns)} dismissal(s)", flush=True)

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

    # Detect files that failed triage entirely (context exceeded, etc.)
    # These must still go to reasoning — they weren't analyzed, not clean.
    triage_failed = set(find_failed_files(session_dir, "triage"))

    # Files that were chunked lose cross-function context and may miss
    # vulnerabilities.  Forward them to reasoning even if triage found
    # nothing — the reasoning model typically has a larger context window.
    triage_chunked = set(find_chunked_files(session_dir, "triage"))
    # Only forward chunked files that weren't already flagged or failed
    triage_extra = triage_chunked - {f.file for f in triage_findings} - triage_failed

    triage_forwarded = triage_failed | triage_extra
    if triage_forwarded:
        parts = []
        if triage_failed:
            parts.append(f"{len(triage_failed)} failed")
        if triage_extra:
            parts.append(f"{len(triage_extra)} chunked-but-clean")
        print(
            f"\n[WARN] {len(triage_forwarded)} file(s) forwarded to reasoning "
            f"({', '.join(parts)}): {', '.join(sorted(triage_forwarded))}",
            flush=True,
        )

    def recompute_clean_files(kept_findings: List[Finding]) -> None:
        """Mark files clean if no kept finding references them.

        Called after each late pipeline return so files forwarded to
        catch-up that ended up clean still appear in the report's
        clean list.
        """
        flagged_now = {f.file for f in kept_findings}
        result.files_with_findings = len(flagged_now)
        result.clean_files = [
            str(f.path.relative_to(source_dir))
            for f in files
            if str(f.path.relative_to(source_dir)) not in flagged_now
        ]

    if not triage_findings and not triage_forwarded:
        print("\nTriage: All files clean.", flush=True)
        result.clean_files = [str(f.path.relative_to(source_dir)) for f in files]
        result.stage_stats = compute_stage_stats(session_dir)
        return result

    flagged_files = {f.file for f in triage_findings} | triage_forwarded
    result.files_with_findings = len(flagged_files)
    result.clean_files = [
        str(f.path.relative_to(source_dir))
        for f in files
        if str(f.path.relative_to(source_dir)) not in flagged_files
    ]
    print(
        f"\nTriage: {len(triage_findings)} findings in "
        f"{len(flagged_files - triage_forwarded)} files"
        + (f" + {len(triage_forwarded)} forwarded" if triage_forwarded else ""),
        flush=True,
    )

    if args.triage_only:
        result.findings = triage_findings
        # Do NOT call recompute_clean_files here: forwarded files have not
        # been analyzed past triage, so they must stay excluded from
        # clean_files.  The flagged_files block above already set
        # result.clean_files correctly (triage findings ∪ forwarded).
        result.stage_stats = compute_stage_stats(session_dir)
        return result

    # ── Stage 1b: Triage catch-up (function-level) ──
    # Files that triage couldn't analyze get a function-by-function
    # paranoid pass using the reasoning backend.  Whole-file scanning
    # misses subtle bugs that get lost in the noise — scanning each
    # function individually lets the model focus on the logic.
    if triage_forwarded and reasoning_backend:
        forwarded_paths = [
            f for f in files
            if str(f.path.relative_to(source_dir)) in triage_forwarded
        ]
        print(f"\n{'='*60}", flush=True)
        print(f"TRIAGE CATCH-UP — function-level ({reasoning_backend})", flush=True)
        print(f"  Paranoid triage on {len(forwarded_paths)} file(s), "
              f"one function at a time", flush=True)
        print(f"{'='*60}", flush=True)

        run_function_level_triage(
            forwarded_paths, reasoning_backend, source_dir, session_dir,
        )
        catchup_findings = load_stage_findings(session_dir, "triage_catchup")
        # Re-tag as "triage" so they count in cross-stage consensus
        for f in catchup_findings:
            f.stage = "triage"
        if catchup_findings:
            catchup_files = {f.file for f in catchup_findings}
            print(
                f"\nCatch-up: {len(catchup_findings)} findings in "
                f"{len(catchup_files)} files",
                flush=True,
            )
        else:
            print("\nCatch-up: no additional findings.", flush=True)

        # ── Collect annotations from contracts and hints ──
        finding_annotations: Dict[str, str] = {}
        if catchup_findings and contract_packs:
            contract_notes = apply_contract_annotations(catchup_findings, contract_packs)
            if contract_notes:
                finding_annotations.update(contract_notes)
                print(f"\nContract annotations: {len(contract_notes)} finding(s) "
                      f"matched known API contracts (kept for model review)",
                      flush=True)
        if catchup_findings and package_hints:
            hints_notes = apply_hints_annotations(catchup_findings, package_hints)
            if hints_notes:
                for k, v in hints_notes.items():
                    finding_annotations[k] = finding_annotations.get(k, "") + v
                print(f"\nHints annotations: {len(hints_notes)} finding(s) "
                      f"matched package hints (kept for model review)",
                      flush=True)

        # ── Stage 1c: Confirmation pass (whole-file) ──
        # For each catch-up finding, re-ask with the whole file as context.
        # The model may ask for callers — if so, we run pass 3.
        if catchup_findings:
            print(f"\n{'='*60}", flush=True)
            print(f"CONFIRMATION (whole-file, {reasoning_backend})", flush=True)
            print(f"  Re-evaluating {len(catchup_findings)} catch-up finding(s) "
                  f"with full file context", flush=True)
            print(f"{'='*60}", flush=True)

            confirmation = run_confirmation_pass(
                catchup_findings, files, reasoning_backend,
                source_dir, session_dir,
                contract_packs=contract_packs,
                package_hints=package_hints,
                finding_annotations=finding_annotations,
            )
            n_need_callers = sum(1 for v in confirmation.values()
                                 if v["outcome"] == "NEED_CALLERS")
            if n_need_callers:
                print(f"\n{'='*60}", flush=True)
                print(f"CALLER CONTEXT PASS ({reasoning_backend})", flush=True)
                print(f"  {n_need_callers} finding(s) need cross-file callers",
                      flush=True)
                print(f"{'='*60}", flush=True)
                caller_results = run_caller_pass(
                    catchup_findings, confirmation, reasoning_backend,
                    source_dir, session_dir,
                )
                # Caller-pass outcomes override confirmation outcomes
                confirmation = {**confirmation, **caller_results}

            n_confirmed = sum(1 for v in confirmation.values()
                              if v["outcome"] == "CONFIRMED")
            n_fp = sum(1 for v in confirmation.values()
                       if v["outcome"] == "FALSE_POSITIVE")
            print(
                f"\nConfirmation: {n_confirmed} confirmed, {n_fp} FP, "
                f"{len(confirmation) - n_confirmed - n_fp} ambiguous",
                flush=True,
            )

            # Drop catch-up findings that confirmation rejected.  Their
            # reasoning stays in session_dir/triage_confirm/ for the
            # report.  Ambiguous (UNPARSED / missing) outcomes are kept
            # to fail safe — verdict can still reject them later.
            kept = [
                f for f in catchup_findings
                if confirmation.get(f.key(), {}).get("outcome") != "FALSE_POSITIVE"
            ]
            dropped = len(catchup_findings) - len(kept)
            if dropped:
                print(f"  Dropped {dropped} catch-up finding(s) rejected by "
                      f"confirmation.", flush=True)
            catchup_findings = kept

        triage_findings = triage_findings + catchup_findings

    # ── Stage 2: Reasoning ──
    print(f"\n{'='*60}", flush=True)
    print(f"REASONING ({reasoning_backend})", flush=True)
    print(f"{'='*60}", flush=True)

    # Re-compute flagged files: catch-up may have found new ones
    flagged_files = {f.file for f in triage_findings} | triage_forwarded
    flagged_paths = [f for f in files if str(f.path.relative_to(source_dir)) in flagged_files]

    # Build triage hints: map each flagged file to its triage findings
    triage_hints = {}
    for f in triage_findings:
        triage_hints.setdefault(f.file, []).append(f)

    run_scan_stage(
        flagged_paths, reasoning_backend, "reasoning", source_dir, session_dir,
        triage_hints=triage_hints,
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
        recompute_clean_files(result.findings)
        result.stage_stats = compute_stage_stats(session_dir)
        return result

    # ── Stage 3: Verdict ──
    print(f"\n{'='*60}", flush=True)
    print(f"VERDICT ({verdict_backend})", flush=True)
    print(f"{'='*60}", flush=True)

    profile_by_file = {str(f.path.relative_to(source_dir)): f.profile for f in files}
    consensus = run_verdict_stage(consensus, verdict_backend, source_dir, session_dir, profile_by_file,
                                  package_hints=package_hints)

    # Filter: keep everything except NOISE
    for group in consensus:
        if group.get("verdict") == "NOISE":
            continue
        result.findings.extend(group["findings"])

    recompute_clean_files(result.findings)
    result.stage_stats = compute_stage_stats(session_dir)
    return result


# ── Report generation ───────────────────────────────────────────────────

def generate_report(result: ScanResult, output_path: str):
    """Generate a markdown report with verdict results when available."""
    session_dir = Path(result.session_dir) if result.session_dir else None

    # Load verdict data if available
    verdict_groups: Dict[str, List[dict]] = {}
    _VERDICT_COMPAT = {
        "CONFIRMED": "REPORT",
        "FALSE_POSITIVE": "NOISE",
        "NEEDS_CONTEXT": "NEEDS_REPRODUCER",
    }
    if session_dir and (session_dir / "verdict").exists():
        for path in sorted((session_dir / "verdict").rglob("*.json")):
            payload = load_json(path)
            v = payload.get("verdict", "NEEDS_REPRODUCER")
            v = _VERDICT_COMPAT.get(v, v)
            verdict_groups.setdefault(v, []).append(payload)

    has_verdicts = any(verdict_groups.values())

    lines = [
        f"# {result.package} Security Scan Report\n",
        f"**Date**: {result.created_at}",
        f"**Session**: {result.session_id}\n",
    ]

    # Stage summary
    if result.stage_stats:
        lines.append("## Scan funnel\n")
        nonprod_path = session_dir / "suppressed_files" / "nonprod.json" if session_dir else None
        if nonprod_path and nonprod_path.exists():
            nonprod_data = load_json(nonprod_path)
            n_suppressed = len(nonprod_data.get("files", []))
            if n_suppressed:
                lines.append(f"- **Files suppressed (non-production)**: {n_suppressed}")
        lines.append(f"- **Files scanned**: {result.files_scanned}")
        for stage in ("triage", "triage_catchup", "triage_confirm",
                  "triage_confirm_callers", "reasoning", "verdict"):
            stats = result.stage_stats.get(stage)
            if not stats or not stats.get("completed_files"):
                continue
            label = {
                "triage_catchup": "Triage catch-up",
                "triage_confirm": "Confirmation (whole-file)",
                "triage_confirm_callers": "Confirmation (callers)",
            }.get(stage, stage.capitalize())
            lines.append(
                f"- **{label}**: {stats['completed_files']} files, "
                f"{stats['files_with_findings']} with findings, "
                f"{stats['total_findings']} total findings"
            )
        if has_verdicts:
            counts = {k: len(v) for k, v in verdict_groups.items() if v}
            parts = []
            for label in ("REPORT", "REPORT_IF_CONFIGURED", "UPSTREAM_HARDENING",
                          "NEEDS_REPRODUCER", "NOISE"):
                if counts.get(label):
                    parts.append(f"**{label}**: {counts[label]}")
            if parts:
                lines.append("- " + " | ".join(parts))
        lines.append("")

    # When verdicts exist, report by actionability
    if has_verdicts:
        _VERDICT_SECTIONS = [
            ("REPORT", "Actionable findings (REPORT)",
             "Real vulnerabilities reachable under default configuration."),
            ("REPORT_IF_CONFIGURED", "Config-gated findings (REPORT_IF_CONFIGURED)",
             "Real vulnerabilities whose reachability depends on a non-default configuration."),
            ("UPSTREAM_HARDENING", "Upstream hardening (UPSTREAM_HARDENING)",
             "Real code bugs that are dormant in practice — worth a hardening patch."),
            ("NEEDS_REPRODUCER", "Needs reproducer (NEEDS_REPRODUCER)",
             "Findings that look real but lack a proven exploitation path."),
        ]
        for verdict_key, heading, description in _VERDICT_SECTIONS:
            items = verdict_groups.get(verdict_key, [])
            if not items:
                continue
            if verdict_key == "REPORT":
                items = dedup_verdict_findings(items)
            lines.append(f"## {heading}\n")
            lines.append(f"*{description}*\n")
            for payload in items:
                _format_verdict_finding(lines, payload)

        noise = verdict_groups.get("NOISE", [])
        if noise:
            lines.append("## Dismissed as noise (NOISE)\n")
            for payload in noise:
                finding = payload.get("findings", [{}])[0]
                lines.append(
                    f"- ~~[{finding.get('severity', '?')}] "
                    f"{payload.get('file', '?')}: "
                    f"{finding.get('type', '?')}~~"
                )
            lines.append("")
    elif result.findings:
        # No verdict — list raw findings
        lines.append("## Findings\n")
        for f in result.findings:
            lines.append(f"### [{f.severity}] {f.location}")
            lines.append(f"**File**: {f.file}")
            lines.append(f"**Type**: {f.type}")
            lines.append(f"**Stage**: {f.stage} ({f.model})")
            if f.source:
                lines.append(f"**Source**: {f.source}")
            if f.sink:
                lines.append(f"**Sink**: {f.sink}")
            lines.append(f"\n{f.description}\n")

    if result.clean_files:
        lines.append("## Files confirmed clean\n")
        lines.append(f"{len(result.clean_files)} files passed all stages.\n")

    report = "\n".join(lines)
    with open(output_path, "w") as f:
        f.write(report)
    print(f"\nReport written to {output_path}", flush=True)


def _format_verdict_finding(lines: list, payload: dict):
    """Format a single verdict finding for the report."""
    finding = payload.get("findings", [{}])[0]
    stages = payload.get("stages", [])
    stage_str = " + ".join(stages) if stages else "?"
    display_severity = payload.get("real_severity") or finding.get("severity", "?")

    lines.append(f"### [{display_severity}] {finding.get('location', '?')}")
    lines.append(f"**File**: {payload.get('file', '?')}")
    lines.append(f"**Type**: {finding.get('type', '?')}")
    lines.append(f"**Stages**: {stage_str}")
    if payload.get("real_severity"):
        lines.append(f"**Final severity**: {payload['real_severity']}")

    triad_parts = []
    if payload.get("source_owner"):
        triad_parts.append(f"Source: {payload['source_owner']}")
    if payload.get("config_gate"):
        triad_parts.append(f"Config: {payload['config_gate']}")
    if payload.get("sink_privilege"):
        triad_parts.append(f"Privilege: {payload['sink_privilege']}")
    if triad_parts:
        lines.append(f"**Reachability**: {' | '.join(triad_parts)}")

    if finding.get("source"):
        lines.append(f"**Source**: {finding['source']}")
    if finding.get("sink"):
        lines.append(f"**Sink**: {finding['sink']}")
    lines.append(f"\n{finding.get('description', '')}")

    # Include verdict reasoning if available
    verdict_raw = payload.get("verdict_raw", "")
    reasoning_match = re.search(r"REASONING:\s*(.+?)(?:\n\n|\Z)", verdict_raw, re.DOTALL)
    if reasoning_match:
        lines.append(f"\n**Verdict reasoning**: {reasoning_match.group(1).strip()[:500]}")

    related = payload.get("related_findings", [])
    if related:
        lines.append(f"\n**Same root cause** ({len(related)} additional call site(s)):")
        for r in related:
            lines.append(f"- [{r['severity']}] {r['location']}: {r['description']}")

    lines.append("")


_TYPE_FAMILY = {
    "heap-overflow": "overflow", "buffer-overflow": "overflow",
    "stack-overflow": "overflow", "integer-overflow": "overflow",
    "out-of-bounds-write": "overflow", "out-of-bounds-read": "overflow",
    "use-after-free": "memory-safety", "double-free": "memory-safety",
    "command-injection": "injection", "shell-injection": "injection",
    "code-injection": "injection", "sql-injection": "injection",
    "path-traversal": "path-traversal", "directory-traversal": "path-traversal",
}


def _type_family(vuln_type: str) -> str:
    return _TYPE_FAMILY.get(vuln_type.lower().strip(), vuln_type.lower().strip())


def _dedup_key(payload: dict) -> str:
    finding = payload.get("findings", [{}])[0]
    file_ = payload.get("file", "")
    type_fam = _type_family(finding.get("type", ""))
    return f"{file_}::{type_fam}"


def dedup_verdict_findings(payloads: List[dict]) -> List[dict]:
    groups: Dict[str, List[dict]] = {}
    for p in payloads:
        key = _dedup_key(p)
        groups.setdefault(key, []).append(p)

    result = []
    for key, group in groups.items():
        if len(group) == 1:
            result.append(group[0])
            continue
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        group.sort(key=lambda p: severity_order.get(
            (p.get("real_severity") or p.get("findings", [{}])[0].get("severity", "info")).lower(), 5
        ))
        primary = dict(group[0])
        related = []
        for p in group[1:]:
            f = p.get("findings", [{}])[0]
            related.append({
                "location": f.get("location", "?"),
                "description": f.get("description", "")[:200],
                "severity": p.get("real_severity") or f.get("severity", "?"),
            })
        primary["related_findings"] = related
        primary["dedup_count"] = len(group)
        result.append(primary)
    return result


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
    "contracts",
    "triage",
    "reasoning",
    "verdict",
    "triage_only",
}

CONFIG_STRING_KEYS = {
    "source_dir",
    "obs_package",
    "resume_session",
    "package_name",
    "output",
    "json",
    "scratch_dir",
    "profile",
    "contracts",
    "triage",
    "reasoning",
    "verdict",
}

CONFIG_BOOL_KEYS = {
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

    for key in CONFIG_STRING_KEYS:
        if key in config and config[key] is not None and not isinstance(config[key], str):
            raise ValueError(f"Config key {key!r} must be a string.")

    for key in CONFIG_BOOL_KEYS:
        if key in config and not isinstance(config[key], bool):
            raise ValueError(f"Config key {key!r} must be a boolean.")

    source_keys = [key for key in ("source_dir", "obs_package", "resume_session") if config.get(key)]
    if len(source_keys) > 1:
        raise ValueError(
            "Config keys source_dir, obs_package, and resume_session are mutually exclusive. "
            f"Got: {', '.join(source_keys)}"
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
    parser.add_argument("--contracts", default="auto",
                        help="Contract packs: auto (detect from includes), none, "
                             "or comma-separated names (e.g. pam)")

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
