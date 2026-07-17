# Security Policy

ObsidianWall Verdict evaluates infrastructure changes before deployment and is designed to be trusted as part of a governance and CI/CD pipeline. We take security reports seriously and appreciate responsible disclosure from the community.

---

## Supported Versions

Only the latest published release receives security fixes. Given the pace of development on this project, we do not backport security patches to older minor versions.

| Version | Supported |
|---------|-----------|
| Latest (0.6.x) | ✅ |
| 0.5.x | ⚠️ Critical fixes only, on a best-effort basis |
| < 0.5.0 | ❌ |

We recommend always running the latest version:

```bash
pip install --upgrade obsidianwall-verdict
```

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately by emailing:

<a href="mailto:security&#64;obsidianwall&#46;com">security&#64;obsidianwall&#46;com</a>

If that address is unreachable, use <a href="mailto:hello&#64;obsidianwall&#46;com">hello&#64;obsidianwall&#46;com</a> with `[SECURITY]` in the subject line.

Please include, where possible:

- A description of the vulnerability and its potential impact
- Steps to reproduce, or a minimal proof of concept
- The affected version(s)
- Any suggested remediation, if you have one

We will acknowledge receipt within **72 hours** and aim to provide an initial assessment within **7 days**. We will keep you updated as we investigate and work on a fix.

---

## Scope

This policy covers:

- The `obsidianwall-verdict` CLI and its published PyPI package
- The GitHub Action (`ObsidianWall/obsidianwall-verdict`)
- The policy evaluation engine, condition evaluator, and analyzers
- The local telemetry/governance store (`~/.obsidianwall/decisions.db`)

**Out of scope:**

- obsidianwall.com, obsidianwall.dev, and programmableassurance.org (report content or availability issues via <a href="mailto:hello&#64;obsidianwall&#46;com">hello&#64;obsidianwall&#46;com</a>, not as a security vulnerability unless it involves an actual exploit)
- Vulnerabilities in third-party dependencies — please report these upstream, though we'd appreciate a heads-up so we can track and update

---

## What We Consider a Vulnerability

Examples of in-scope reports:

- Any way for a maliciously crafted policy YAML or Terraform/CloudFormation plan file to execute arbitrary code
- Any way to bypass a governance decision (e.g., forcing an `ALLOW` when conditions should produce a `DENY`)
- Any way for local telemetry data to be exfiltrated, corrupted, or read by an unauthorized process
- Injection vulnerabilities in condition expression evaluation
- Any privilege escalation via the override or approval workflow

Examples of **out-of-scope** reports:

- Missing security headers on our websites
- Theoretical vulnerabilities with no practical exploit path
- Denial of service via extremely large input files (resource exhaustion is a known limitation, not a vulnerability, for a local CLI tool)

---

## Disclosure Policy

We follow coordinated disclosure. Please give us a reasonable window to investigate and release a fix before any public disclosure — we ask for **90 days** from initial report, though we will move faster whenever possible and will communicate with you throughout.

Once a fix is released, we will credit reporters (with permission) in the release notes.

---

## Privacy Note

ObsidianWall Verdict's local telemetry is stored entirely on your machine at `~/.obsidianwall/decisions.db` and is not transmitted anywhere in the current version. See [our privacy documentation](https://obsidianwall.dev/concepts/telemetry) for full details on what is and is not collected.

If you believe you have found a way for telemetry data to leave a user's machine without their knowledge, please report it immediately using the process above — this would be treated as a critical severity issue.