# openSUSE Security Scanner — Findings Report

**Date:** 2026-05-02
**Scanner:** opensuse-security-scanner (three-stage pipeline)
**Triage model:** GPT-OSS 20B / Nemotron Nano 30B
**Reasoning model:** Nemotron Super 49B / Gemma 4 31B
**Verdict model:** Mistral Large 675B / Gemma 4 31B
**All findings source-verified by human + AI review**

---

## Executive Summary

Six packages scanned. One new vulnerability discovered and reported
upstream (cockpit path traversal). Several low-severity issues and
defense-in-depth observations documented. No remotely exploitable
bugs found in zypper or libzypp.

| Package | Files scanned | Scanner findings | After verification |
|---------|--------------|-----------------|-------------------|
| Linux-PAM | ~200 | 118 verdicts | 5 known bugs confirmed |
| cockpit 360 | 398 | 373 findings | **1 new bug** (reported) |
| account-utils | ~80 | 27 verdicts, 12 REPORT | 0 real (all FP) |
| zypper 1.14.96 | 211 | 136 findings, 93 High/Critical | 0 real (all FP) |
| libzypp 17.38.7 | 1032 | 200 CONFIRMED | 0 remote, 2 low-local, 4 defense-in-depth |
| dracut 110 | 352 | in progress | — |

**False positive rate after verdict stage:** ~95-99% depending on package.
**Value:** the scanner surfaces findings that warrant human review;
source verification is essential before reporting.

---

## Findings requiring action

### 1. cockpit: cockpit_Machines.Update path traversal [NEW, REPORTED]

**Severity:** Medium (authenticated, bounded by user permissions)
**File:** `src/cockpit/internal_endpoints.py:84-99`
**Status:** Reported to cockpit team 2026-05-01

The `cockpit.Machines.Update` D-Bus method on cockpit-bridge's internal
bus accepts an unsanitized `filename` parameter joined to the `machines.d`
config directory via `Path.joinpath()`. Python's `joinpath()` does not
sanitize `..` components.

**Impact:**
- Without superuser: authenticated cockpit user can create/overwrite files
  writable by their UID at arbitrary paths. Content is structured JSON.
- With superuser: the normal UI call uses `superuser: "require"`, so the
  standard code path runs as **root**. Can write JSON to any path on the
  filesystem.
- File creation: if target doesn't exist, creates new file with
  attacker-controlled JSON.
- File overwrite: if target exists and is valid JSON, merges attacker's
  key-value pairs. Invalid JSON targets are not modified.

**Reproducer (browser console, any authenticated cockpit session):**
```javascript
cockpit.dbus(null, { bus: "internal" }).call(
    "/machines", "cockpit.Machines", "Update",
    ["../../tmp/cockpit-traversal-poc.json",
     "traversal-proof",
     { note: cockpit.variant("s", "path traversal via Machines.Update") }],
    { type: "ssa{sv}" }
).then(() => console.log("SUCCESS — check /tmp/cockpit-traversal-poc.json"))
 .catch(e => console.error("FAILED:", e));
```

**Suggested fix:**
```python
import re
if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
    raise bus.BusError('cockpit.Machines.Error', f'Invalid filename: {filename}')
```

---

## Findings for defense-in-depth consideration

These are not directly exploitable under normal conditions but represent
areas where hardening would improve resilience against sophisticated
attackers (e.g., compromised repo servers, MITM attacks on repo metadata).

### 2. libzypp: readChecksumsIndex path traversal in checksum map

**Severity:** Low (requires MITM + signature bypass)
**File:** `zypp/zypp/Fetcher.cc:~680`

Filenames within a CHECKSUMS index file are used as-is in
`basedir / buffer` path construction. A `../` sequence in the filename
creates traversed keys in the checksum map. If an attacker can strip
the `.asc` signature file (MITM) and provide a crafted CHECKSUMS, they
could inject wrong checksums for packages, potentially bypassing
integrity checking for a specific file.

**Mitigation already present:** CHECKSUMS files are signature-verified
when `.asc` is available. Missing `.asc` is not treated as fatal.

**Recommendation:** Reject filenames containing `..` in CHECKSUMS parsing,
or make missing `.asc` for CHECKSUMS a hard error.

### 3. libzypp: NetworkProvider cache path escape

**Severity:** Low (requires crafted internal IPC message)
**File:** `zyppng/tools/zypp-media-http/networkprovider.cc:~424`

`localPath = Pathname(_attachPoint) / "cache" / fPath` where if `fPath`
(from URL's `getPathName()`) is absolute, `Pathname::cat()` discards the
`_attachPoint/cache` prefix entirely. Could allow writing cache files
outside the intended directory.

**Recommendation:** Reject or strip absolute paths from `fPath` before
constructing `localPath`.

### 4. libzypp: ContentFileReader DESCRDIR path escape

**Severity:** Low (requires compromised or malicious repo)
**File:** `zypp/zypp/parser/susetags/ContentFileReader.cc`

`DESCRDIR` and `DATADIR` values from a repo's `content` file are stored
verbatim without `..` sanitization. Downstream use constructs file paths
that could escape the cache directory.

**Recommendation:** Validate DESCRDIR/DATADIR for path traversal
sequences during parsing.

### 5. libzypp: wrtcallback unbounded multipart buffer

**Severity:** Low (DoS, requires malicious repo)
**File:** `zypp-logic/zypp-curl/ng/network/curlmultiparthandler.cc:~204`

The `_rangePrefaceBuffer` accumulates multipart HTTP header data without
a size limit while waiting for `\r\n\r\n`. A malicious server can send
an endless stream causing OOM.

**Recommendation:** Cap `_rangePrefaceBuffer` to a reasonable size (e.g.,
64KB — multipart headers should never be that large).

### 6. libzypp: PluginFrame classic IPC unbounded body

**Severity:** Low (local only, requires malicious plugin)
**File:** `zypp-logic/zypp-core/rpc/PluginFrame.cc:~324-340`

The classic `PluginScript` IPC path has no size cap on message body
(`_body.resize(content_length+1)` with no upper bound). A malicious
plugin can cause OOM. The newer async path (stompframestream.cc) already
has a 1MB guard (`MAX_BODYLEN`).

**Recommendation:** Apply the same 1MB cap to the classic path.

---

## Previously known findings (PAM)

These were previously reported and are included for completeness.

| Finding | Label | Notes |
|---------|-------|-------|
| `_strbuf_reserve` heap overflow | REPORT_IF_CONFIGURED | Requires user_readenv=1 |
| `PAM_BP_RENEW` int overflow | UPSTREAM_HARDENING | libpamc has 0 consumers |
| `pam_xauth` unbounded getline | REPORT_IF_CONFIGURED | Requires pam_xauth in stack |
| `pam_namespace secure_opendir` | NEEDS_REPRODUCER | — |
| `pam_timestamp` HMAC key confusion | UPSTREAM_HARDENING | — |

---

## Packages with no findings

- **account-utils 1.1.0+**: 12 REPORT findings from scanner, all verified
  as false positives. Key patterns: hallucinated code (snprintf that
  doesn't exist), misread safe patterns (fstat-on-fd as TOCTOU),
  misunderstood APIs (sd_json_dispatch_string strdup).

- **zypper 1.14.96**: 93 High/Critical findings, all verified as false
  positives. Key patterns: `str::Format` args misidentified as format
  strings, PAGER env injection (standard UNIX, not a boundary violation),
  signal handler code quality issues (not security).

---

## Scanner methodology

The scanner uses a three-stage pipeline:

1. **Triage** (paranoid pattern matching): local model scans every source
   file for potential vulnerabilities. High sensitivity, low specificity.
   Best model: GPT-OSS 20B.

2. **Reasoning** (independent chain analysis): different model re-analyzes
   flagged functions with full file context and cross-file caller
   references. Different prompt than triage to reduce confirmation bias.

3. **Verdict** (final call): sees both prior stages, package hints,
   contract annotations, and config-default analysis. Assigns actionability
   labels: REPORT / REPORT_IF_CONFIGURED / UPSTREAM_HARDENING /
   NEEDS_REPRODUCER / NOISE.

All scanner findings are then **source-verified** by reading actual code,
tracing data flows, and checking whether untrusted input can reach
dangerous sinks. Package-specific hints files document verified facts
and dismiss patterns to reduce false positives on future scans.

---

## Tooling

- Scanner: https://github.com/anicka-net/opensuse-security-scanner
- Hints files: `hints/*.scanner-hints.toml` in the scanner repo
- Infrastructure: deepthought GB10 128GB (GPT-OSS triage), NVIDIA NIM
  cloud (reasoning + verdict), mavis Ryzen AI 30GB (backup triage)

---

*Report generated by opensuse-security-scanner + manual verification.*
*Contact: anicka (umelec@ucw.cz)*
