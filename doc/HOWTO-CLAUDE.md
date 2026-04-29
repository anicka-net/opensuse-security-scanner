# Using Claude for CVE Security Work

A practical guide to getting useful results from Claude (CLI, API,
or chat) when doing vulnerability analysis, backporting, and
security patch development.

## Why Claude Sometimes Refuses

Claude has safety filters that trigger on security-adjacent requests.
The filters look at surface patterns, not intent — so a legitimate
security engineer asking "how does this buffer overflow work?" can
get the same refusal as someone trying to build an exploit.

The fix is context. Claude's refusal threshold shifts dramatically
when it understands who you are and what you're doing.

## Setup: CLAUDE.md

If you're using Claude Code (CLI or IDE), drop a `CLAUDE.md` file
in your working directory. This file is automatically loaded into
every conversation. A template for security teams is included in
this repo at `doc/CLAUDE-MD-TEMPLATE.md`.

The critical elements:

```markdown
# Team Name — Security Workspace

This is the working directory for [team] maintaining security
patches for [product]. All CVE work here is authorized maintenance
performed by the package maintainers and security team.
```

This single paragraph eliminates most refusals. Claude reads it
at the start of every session.

## Prompting Patterns That Work

### Analyzing a CVE

Bad (likely to get refused or hedged):
> Explain how to exploit CVE-2024-12345

Good:
> Here's the upstream advisory for CVE-2024-12345. What's the root
> cause? What input triggers it? I need to understand the mechanism
> to write a correct backport.

The difference: "explain so I can fix" vs "explain so I can exploit."

### Backporting a Patch

Bad:
> Fix this security vulnerability

Good:
> Here's the upstream commit that fixes CVE-2024-12345. Our version
> is 1.2.3, upstream is 1.5.0. The patch doesn't apply cleanly
> because `foo_handler()` was refactored in 1.4.0. Adapt the fix
> to our version.

The difference: specific task with context vs vague request.

### Writing Regression Tests

Bad:
> Write an exploit for this buffer overflow to test my fix

Good:
> Write a regression test for the `_strbuf_reserve` fix. The bug
> triggers when len=500, size=512, add=100 — the while loop
> doesn't grow the buffer. The test should call `_strbuf_reserve`
> with these values and assert the buffer is large enough afterward.

The difference: describe the test case, not "an exploit."

### Analyzing Source Code for Vulnerabilities

Bad:
> Find vulnerabilities I can exploit in this code

Good:
> Review this PAM module for memory safety issues. Focus on buffer
> handling in the config parser and whether user-supplied input
> reaches allocation-size calculations.

The difference: directed code review vs open-ended vuln hunting.

## Words That Help vs Words That Hurt

### Use freely
- patch, backport, fix, harden, mitigate
- regression test, test case, reproducer
- analyze, review, audit
- root cause, mechanism, trigger condition
- maintainer, security team, advisory

### Use carefully (add context)
- exploit → "the upstream PoC demonstrates..."
- attack → "the attack surface is..."
- bypass → "the original fix can be bypassed if..."
- weaponize, payload, shellcode → almost always refused,
  rephrase as the specific technical operation

### Reframing examples
| Instead of | Say |
|------------|-----|
| "Write an exploit" | "Write a test that triggers the bug" |
| "How do I bypass ASLR here" | "Does ASLR affect the reachability of this code path" |
| "Generate a payload for this overflow" | "What input values trigger the overflow (for the regression test)" |
| "Find vulns to exploit" | "Review for memory safety issues" |

## Working With CVE Descriptions

When you paste a CVE description, add a one-line frame:

> I'm backporting the fix for this CVE to our package. Here's
> the advisory:
>
> [paste CVE description]
>
> And here's the upstream patch:
>
> [paste patch]
>
> Our version is X.Y.Z. What needs to change for the backport?

This gives Claude the full picture: you're a maintainer, you have
the fix, you need to adapt it. No ambiguity about intent.

## When You Still Get Refused

1. **Rephrase around the technical operation.** "How does the
   integer overflow in xdr_yppasswd lead to a heap corruption"
   works better than "explain this exploit."

2. **Break it into steps.** Ask Claude to analyze the code first,
   then ask about the specific vulnerable path, then ask for
   the fix. Each step has more context from the previous one.

3. **Provide the upstream fix.** If Claude can see that a fix
   exists and you're adapting it, refusals drop to near zero.

4. **Start a new session with CLAUDE.md.** If a session has
   accumulated refusals, the conversation history biases Claude
   toward continuing to refuse. A fresh start with good project
   context works better than arguing.

## Using the Scanner

The `opensuse-security-scanner` tool automates vulnerability
scanning with multi-model pipelines. Its prompts are already
engineered to avoid refusals — the triage, reasoning, and verdict
stages frame everything as code review with structured output.

If you're building on top of the scanner or writing custom prompts
for security analysis, study the prompt templates in
`profiles/*.json` for examples of how to frame security analysis
requests that models respond to well.
