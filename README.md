# openSUSE Security Scanner

Multi-model vulnerability scanning pipeline for C/C++ packages.
Three independent stages — triage, reasoning, verdict — each
backed by any LLM you choose: local models via ollama/llama.cpp,
or frontier APIs via Claude, Gemini, or Codex CLIs.

This tool is designed for analyst assistance, not autonomous security
sign-off. A "clean" report means "nothing survived this pipeline under
this model mix," not "this package is vulnerability-free."

## How it works

```
Source code (OBS or local)
        |
        v
  +-----------+     Paranoid pattern matching.
  |  TRIAGE   |     Flags anything suspicious.
  |  (fast)   |     ~70% of files come back clean.
  +-----------+
        |  flagged files only
        v
  +-----------+     Independent chain analysis.
  | REASONING |     Traces data flow source -> sink.
  |  (deep)   |     Rules out common FP patterns.
  +-----------+
        |  findings from both stages
        v
  +-----------+     Sees what both stages found.
  |  VERDICT  |     Checks privilege boundaries,
  | (precise) |     attack surface, exploitability.
  +-----------+
        |
        v
  Markdown + JSON report
```

Triage and reasoning scan independently — neither sees the other's
output. This means cross-stage consensus is genuine signal: if both
flag the same function, it's likely real. The verdict stage sees
everything and makes the final call.

## Quick start

```bash
# Scan an OBS package with local models (ollama)
python3 scan.py --obs-package openSUSE:Factory/zypper

# Scan a local source tree
python3 scan.py --source-dir /path/to/extracted-source

# Triage only (single stage, fast)
python3 scan.py --source-dir ./src --triage-only
```

For regular use, prefer local models for triage and reasoning and reserve
frontier models for verdict or high-value packages. A full frontier run on
large packages can be slow and expensive.

## Recommended setup

Based on testing against packages with known vulnerabilities
(open-iscsi DHCPv6 strlen bug, transactional-update popen injection):

| Stage | Model | Why | VRAM |
|-------|-------|-----|------|
| Triage | GPT-OSS 20B | Good signal-to-noise in current repo testing. | 13 GB |
| Reasoning | Gemma 4 31B | Good chain-analysis behavior in current repo testing. | 33 GB |
| Verdict | Claude / Gemini / Codex | Stronger privilege-boundary and exploitability review. | API |

```bash
# Recommended: local triage + reasoning, Claude verdict
python3 scan.py \
  --obs-package openSUSE:Factory/zypper \
  --triage ollama/gpt-oss-20b \
  --reasoning ollama/gemma4:31b \
  --verdict claude/opus

# Same but with llama.cpp servers instead of ollama
python3 scan.py \
  --obs-package openSUSE:Factory/zypper \
  --triage openai/gpt-oss-20b@http://localhost:8404 \
  --reasoning openai/gemma-4-31b@http://localhost:8405 \
  --verdict claude/opus
```

## Backend reference

Every stage accepts a backend spec in `backend/model[@url]` format:

| Backend | Format | Auth | Notes |
|---------|--------|------|-------|
| ollama | `ollama/model-name` | None | Default port 11434. Custom: `ollama/model@http://host:port` |
| openai | `openai/model@http://host:port` | Optional `OPENAI_API_KEY` | Works with llama.cpp, vLLM, any OpenAI-compatible server |
| claude | `claude/opus`, `claude/sonnet`, `claude/haiku` | CLI subscription | Uses `claude` CLI, no API key needed |
| gemini | `gemini/flash`, `gemini/pro` | CLI subscription | Uses `gemini` CLI, no API key needed |
| codex | `codex/default` | CLI subscription | Uses `codex` CLI, no API key needed |

### Examples

```bash
# All local (two GPUs)
--triage ollama/gpt-oss-20b --reasoning ollama/gemma4:31b

# Mixed local + API
--triage ollama/gpt-oss-20b --reasoning gemini/flash --verdict claude/opus

# All frontier (burns tokens, but works without GPUs)
--triage gemini/flash --reasoning claude/sonnet --verdict claude/opus

# Big GPU setup with Kimi K2 via ollama
--triage ollama/gpt-oss-20b --reasoning ollama/kimi-k2 --verdict ollama/kimi-k2
```

## What each stage does

### Triage

Paranoid pattern matcher. Told to "assume the worst" and flag
anything that could be a vulnerability. Casts a wide net. Typically
flags 20-40% of files. False positive rate depends on model —
GPT-OSS 20B is the best we tested (zero FP on known-clean files).

### Reasoning

Independent chain analyst. Does NOT see triage results. Uses a
different prompt focused on tracing data flow from untrusted source
to dangerous sink. Must describe the complete vulnerability chain.
Explicitly checks for common false positive patterns before
reporting (abort-on-failure allocators, exit() error handlers,
literal format strings, integer promotion safety, root-only
contexts).

### Verdict

Final reviewer. Sees findings from BOTH previous stages, grouped
by stage with a consensus note ("both stages flagged this" vs
"only triage flagged this — examine carefully"). Checks privilege
boundaries, D-Bus policy, attack surface. Filters out false
positives. Only confirmed findings appear in the final report.

## Session persistence

Every run creates a session directory under `--scratch-dir`
(default: `/tmp/opensuse-security-scanner/`) containing:

```
fillup-<uuid>/
  metadata.json          # backends, timestamps, package info
  progress.jsonl         # one line per scanned file (tail -f friendly)
  triage/
    SRC/parser.c.json    # raw output + parsed findings per file
    SRC/services.c.json
  reasoning/
    SRC/parser.c.json    # independent deep analysis
    SRC/services.c.json
  verdict/
    SRC/services.c.<hash>.json   # per-finding verdict with reasoning
```

All raw model outputs are preserved for debugging, comparison,
and reproducibility.

The scanner can also resume a persisted session:

```bash
python3 scan.py \
  --resume-session /tmp/opensuse-security-scanner/permissions-<uuid> \
  --triage openai/gpt-oss-20b@http://localhost:8404 \
  --reasoning openai/gemma-4-31b@http://localhost:8405
```

When resuming, already-written stage records are reused and only missing
files are scanned.

## Example session

Real session layout from a local-model run on `openSUSE:Factory/permissions`:

```text
/tmp/opensuse-security-scanner/permissions-a0974a27-85a1-43f0-83a5-415f8215dd65/
  metadata.json
  progress.jsonl
  triage/src/varexp.cpp.json
  reasoning/src/varexp.cpp.json
```

Example progress funnel from that run:

```text
triage: 15 completed, 1 file flagged, 1 total finding
reasoning: 1 completed, 0 surviving findings
verdict: disabled
```

The per-file JSON artifacts preserve both the raw model output and the parsed
finding structure, so you can inspect why a file was flagged or cleared without
re-running the scan.

## Model comparison results

These notes are early directional observations from local testing, not a
benchmark suite and not a publishable claim set. Treat them as operator
guidance only.

Tested on open-iscsi (confirmed strlen vulnerability) and
transactional-update (confirmed popen injection). Same prompt,
same files:

| Model | dhcpv6 strlen (subtle) | popen injection (obvious) | FP noise |
|-------|------------------------|--------------------------|----------|
| GPT-OSS 20B (3.6B active) | Found | Found | Low |
| Gemma 4 31B | Strong — traced full chain | Found + novel extras | Medium |
| GPT-OSS 120B (5.1B active) | Found | Found | Medium |
| Qwen3 32B | Partial — missed root cause | Found | Medium |
| Devstral Small 2 24B | Partial — wrong root cause | Found | **Very high** (100 FP on 4 clean files) |

## Requirements

- Python 3.8+
- `requests` (`pip install requests`)
- `osc` (for `--obs-package` mode)
- At least one backend: ollama, a llama.cpp server, or a CLI
  (claude/gemini/codex)

## License

Apache-2.0
