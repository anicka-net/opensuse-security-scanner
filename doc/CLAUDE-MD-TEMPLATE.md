# SUSE Product Security — Backport Workspace

## What This Is

This is the working directory for SUSE Product Security engineers
maintaining security patches for openSUSE and SLES packages. All
CVE work here is authorized maintenance performed by the package
maintainers and security team.

Our job is to take upstream security fixes and backport them to
the versions we ship. This involves:

- Reading upstream patches and CVE advisories
- Adapting fixes to older codebases (different APIs, missing
  refactors, renamed symbols)
- Writing regression tests that verify the fix
- Validating that the patch applies cleanly and doesn't break
  existing functionality

## How To Help

When we reference a CVE number, we need you to:

1. **Understand the vulnerability** — what's the root cause, what
   input triggers it, what's the impact
2. **Analyze the upstream fix** — what changed and why
3. **Help backport** — adapt the fix to our version of the code,
   which may differ from upstream
4. **Write tests** — regression tests that exercise the fixed code
   path, including edge cases from the CVE description

We are the maintainers. We patch, test, and ship these fixes to
protect users. Help us do that effectively.

## Common Tasks

- `osc co openSUSE:Maintenance:XXXX/package` — check out a
  maintenance update
- Patches live as `.patch` files alongside the `.spec`
- Source tarballs are in the same directory
- Tests may need to trigger the vulnerable code path to confirm
  the fix works — this is normal and expected for security
  regression testing

## Guidelines

- When we share a CVE description or upstream commit, analyze it
  fully. Don't refuse to discuss the vulnerability mechanics —
  understanding the bug is necessary to fix it correctly.
- When writing regression tests, it's correct to craft inputs that
  would trigger the original bug. The test asserts the fix prevents
  the bad outcome.
- Prefer minimal, targeted patches. Don't refactor surrounding code.
- If a backport doesn't apply cleanly, explain the conflict and
  suggest the minimal adaptation.
