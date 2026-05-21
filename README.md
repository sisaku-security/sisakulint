<div align="center">

<img src="https://github.com/sisaku-security/homebrew-sisakulint/assets/67861004/e9801cbb-fbe1-4822-a5cd-d1daac33e90f" alt="sisakulint logo" width="160" height="160"/>

# sisakulint

**A fast, security-first static analyzer with heuristic auto-fix for GitHub Actions workflows.**

Find injection, credential leakage, supply-chain, and pipeline-poisoning bugs in `.github/workflows/` — and let `-fix` repair most of them for you.

[![Go Reference](https://pkg.go.dev/badge/github.com/sisaku-security/sisakulint.svg)](https://pkg.go.dev/github.com/sisaku-security/sisakulint)
[![Go Report Card](https://goreportcard.com/badge/github.com/sisaku-security/sisakulint)](https://goreportcard.com/report/github.com/sisaku-security/sisakulint)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/sisaku-security/sisakulint)](https://github.com/sisaku-security/sisakulint/releases/latest)
[![GitHub stars](https://img.shields.io/github/stars/sisaku-security/sisakulint?style=social)](https://github.com/sisaku-security/sisakulint/stargazers)
[![BlackHat Arsenal 2025](https://img.shields.io/badge/BlackHat%20Arsenal-2025-black)](https://speakerdeck.com/4su_para/sisakulint-ci-friendly-static-linter-with-sast-semantic-analysis-for-github-actions)

</div>

---

## Why sisakulint

- **Security-first by design.** Full coverage of the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/) — code/env/path/output injection, untrusted checkouts, artifact & cache poisoning, ref confusion, impostor commits, and more.
- **Semantic, not regex.** A real AST + expression parser + shell taint analyzer (`mvdan.cc/sh`) — not string matching. Cross-step and cross-file taint propagation through `$GITHUB_ENV`, reusable workflow boundaries, and shell function arguments.
- **Auto-fix that ships PRs.** 27+ rules carry an auto-fixer. `sisakulint -fix on` rewrites the YAML in place; `-fix dry-run` previews the diff first.
- **Built for CI.** SARIF output drops straight into [reviewdog](https://github.com/reviewdog/reviewdog) for inline PR review comments.
- **AI-agent aware.** Detects prompt injection, dangerous tool exposure, unsafe sandbox flags, and execution-order issues in claude-code-action and similar AI agent integrations (the *Clinejection* attack class).

### How it compares

|                                                | sisakulint  | actionlint | zizmor  | StepSecurity   | CodeQL  |
| ---------------------------------------------- | :---------: | :--------: | :-----: | :------------: | :-----: |
| Workflow syntax / shell linting                | ✅          | ✅         | partial | —              | —       |
| OWASP CI/CD Top-10 coverage                    | full        | —          | partial | runtime only   | partial |
| Cross-file taint for reusable workflows        | ✅          | —          | —       | —              | ✅      |
| Cross-step / cross-job taint via `$GITHUB_ENV` | ✅          | —          | —       | runtime        | ✅      |
| Shell-aware taint (incl. function args)        | ✅          | —          | —       | —              | partial |
| AI agent action rules (Clinejection)           | ✅          | —          | —       | —              | —       |
| Auto-fix                                       | 27+ rules   | —          | —       | N/A            | ⚠️      |
| SARIF + reviewdog                              | ✅          | —          | ✅      | ✅             | ✅      |

Static-analysis tools sit upstream of runtime tools — sisakulint catches bugs at PR review time, before any workflow runs.

---

## Table of contents

- [Quick start](#quick-start)
- [Installation](#installation)
- [What it detects](#what-it-detects)
- [Rule reference](#rule-reference)
- [Example: detecting real vulnerabilities](#example-detecting-real-vulnerabilities)
- [Auto-fix](#auto-fix)
- [SARIF + reviewdog integration](#sarif--reviewdog-integration)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [BlackHat Arsenal 2025](#blackhat-arsenal-2025)
- [Contributing](#contributing)
- [License](#license)
- [Citation](#citation)

---

## Quick start

```bash
# macOS
brew tap sisaku-security/homebrew-sisakulint
brew install sisakulint

# Run in any repo with a .github/workflows/ directory
sisakulint
```

Other ways to run:

```bash
sisakulint .github/workflows/release.yml   # one file
sisakulint -fix dry-run                    # preview auto-fixes
sisakulint -fix on                         # apply auto-fixes
sisakulint -format "{{sarif .}}"           # SARIF for CI
sisakulint -enable-rule missing-timeout-minutes   # opt-in rule
```

Exit codes: `0` = clean, `1` = findings, `2` = bad CLI args, `3` = fatal error.

---

## Installation

### Homebrew (macOS / Linuxbrew)

```bash
brew tap sisaku-security/homebrew-sisakulint
brew install sisakulint
```

### `go install`

```bash
go install github.com/sisaku-security/sisakulint/cmd/sisakulint@latest
```

Requires Go 1.25 or newer.

### Pre-built binary (Linux / Windows)

Download from the [releases page](https://github.com/sisaku-security/sisakulint/releases/latest) and place it on `$PATH`:

```bash
# Linux example
curl -sSL -o sisakulint https://github.com/sisaku-security/sisakulint/releases/latest/download/sisakulint-linux-amd64
chmod +x sisakulint
sudo mv sisakulint /usr/local/bin/
```

### Build from source

```bash
git clone https://github.com/sisaku-security/sisakulint.git
cd sisakulint
go build ./cmd/sisakulint
```

### As a GitHub Action

The easiest way to wire sisakulint into CI is the official [`sisaku-security/sisakulint-action`](https://github.com/sisaku-security/sisakulint-action). It installs the binary, runs the scan, renders findings as inline PR annotations, and (optionally) uploads SARIF to GitHub Code Scanning.

```yaml
name: sisakulint
on:
  pull_request:
    paths: [".github/workflows/**"]
  push:
    branches: [main]
    paths: [".github/workflows/**"]

permissions:
  contents: read
  pull-requests: write    # inline PR annotations
  security-events: write  # only if upload-sarif: true

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4
        with:
          persist-credentials: false

      - uses: sisaku-security/sisakulint-action@596af4ab15e8c5b232c74aa97525a0302e7b7af4 # v1.0.0
        with:
          fail-on: high        # none | low | medium | high | critical
          upload-sarif: true   # send SARIF to GitHub Code Scanning
```

Useful inputs: `version`, `working-directory`, `args`, `config-file`, `autofix` (`off` / `on` / `dry-run`), `fail-on`, `upload-sarif`, `sarif-file`. See the action's [README](https://github.com/sisaku-security/sisakulint-action) for the full list.

<details>
<summary><b>Alternative: pipe SARIF into reviewdog</b></summary>

If you'd rather use reviewdog for inline PR review comments instead of GitHub annotations:

```yaml
- uses: reviewdog/action-setup@v1

- name: sisakulint + reviewdog
  env:
    REVIEWDOG_GITHUB_API_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    curl -sSL -o sisakulint \
      https://github.com/sisaku-security/sisakulint/releases/latest/download/sisakulint-linux-amd64
    chmod +x sisakulint
    ./sisakulint -format "{{sarif .}}" \
      | reviewdog -f=sarif -reporter=github-pr-review -filter-mode=nofilter
```

</details>

---

## What it detects

### OWASP Top 10 CI/CD Security Risks coverage

| OWASP Risk | Description | sisakulint Rules |
|:-----------|:------------|:-----------------|
| [CICD-SEC-01][owasp-01] | Insufficient Flow Control Mechanisms | [improper-access-control][r-iac], [bot-conditions][r-bot], [unsound-contains][r-uc], [ai-action-unrestricted-trigger][r-aaut] |
| [CICD-SEC-02][owasp-02] | Inadequate Identity and Access Management | [permissions][r-perm] |
| [CICD-SEC-03][owasp-03] | Dependency Chain Abuse | [known-vulnerable-actions][r-kva], [archived-uses][r-au], [impostor-commit][r-ic], [ref-confusion][r-rc], [reusable-workflow-taint][r-rwt] |
| [CICD-SEC-04][owasp-04] | Poisoned Pipeline Execution (PPE) | [dangerous-triggers-*][r-dt-c], [code-injection-*][r-ci], [envvar-injection-*][r-evi], [envpath-injection-*][r-epi], [output-clobbering-*][r-oc], [argument-injection-*][r-ai], [untrusted-checkout-*][r-uco], [request-forgery-*][r-rf], [ai-action-prompt-injection][r-aapi] |
| [CICD-SEC-05][owasp-05] | Insufficient PBAC | [self-hosted-runners][r-shr], [ai-action-excessive-tools][r-aaet], [ai-action-unsafe-sandbox][r-aaus], [ai-action-execution-order][r-aaeo] |
| [CICD-SEC-06][owasp-06] | Insufficient Credential Hygiene | [credentials][r-cred], [artipacked][r-ap], [secrets-in-artifacts][r-sia], [secret-exfiltration][r-sef], [secret-exposure][r-se], [unmasked-secret-exposure][r-use], [secrets-inherit][r-si], [secret-in-log][r-sil] |
| [CICD-SEC-07][owasp-07] | Insecure System Configuration | [timeout-minutes][r-tm], [deprecated-commands][r-dc], [cache-bloat][r-cb] |
| [CICD-SEC-08][owasp-08] | Ungoverned Usage of 3rd Party Services | [action-list][r-al], [commit-sha][r-sha], [unpinned-images][r-ui], [dependabot-github-actions][r-dga] |
| [CICD-SEC-09][owasp-09] | Improper Artifact Integrity Validation | [artifact-poisoning-*][r-apc], [cache-poisoning-*][r-cp] |
| [CICD-SEC-10][owasp-10] | Insufficient Logging and Visibility | [obfuscation][r-ob] |

**Full documentation:** <https://sisaku-security.github.io/lint/>

---

## Rule reference

50+ rules across syntax, configuration, credentials, injection, checkout, supply chain, poisoning, access control, and AI-agent action security.

<details>
<summary><b>Click to expand the full rule list</b></summary>

| Category | Rule | Severity | Description | Fix | Docs |
|:---------|:-----|:--------:|:------------|:---:|:----:|
| **Syntax** | id | Low | ID collision detection for jobs/env vars | | [docs][r-id] |
| | env-var | Low | Environment variable name validation | | [docs][r-env] |
| | permissions | High | Permission scopes and values validation | Yes | [docs][r-perm] |
| | workflow-call | Medium | Reusable workflow call validation | | [docs][r-wc] |
| | job-needs | Low | Job dependency validation | | [docs][r-jn] |
| | expression | Medium | Expression syntax validation | | [docs][r-expr] |
| | cond | Medium | Conditional expression validation | Yes | [docs][r-cond] |
| | deprecated-commands | High | Deprecated workflow commands detection | | [docs][r-dc] |
| **Config** | timeout-minutes | Low | Ensures timeout-minutes is set (opt-in) | Yes | [docs][r-tm] |
| | cache-bloat | Low | Cache bloat with restore/save pair | Yes | [docs][r-cb] |
| **Credentials** | credentials | High | Hardcoded credentials detection | Yes | [docs][r-cred] |
| | secret-exposure | High | Excessive secrets exposure detection | Yes | [docs][r-se] |
| | unmasked-secret-exposure | High | Unmasked derived secrets detection | Yes | [docs][r-use] |
| | artipacked | Critical | Credential leakage via persisted checkout | Yes | [docs][r-ap] |
| | secrets-in-artifacts | High | Sensitive data in artifact uploads | Yes | [docs][r-sia] |
| | secrets-inherit | High | Excessive secrets inheritance | Yes | [docs][r-si] |
| | secret-exfiltration | Critical | Secret exfiltration via network commands | | [docs][r-sef] |
| | secret-in-log | Critical | Secret values printed to build logs (taint-tracked) | Yes | [docs][r-sil] |
| **Injection** | code-injection-critical | Critical | Untrusted input in privileged triggers | Yes | [docs][r-ci] |
| | code-injection-medium | Medium | Untrusted input in normal triggers | Yes | [docs][r-cim] |
| | envvar-injection-critical | Critical | Untrusted input to $GITHUB_ENV (privileged) | Yes | [docs][r-evi] |
| | envvar-injection-medium | Medium | Untrusted input to $GITHUB_ENV (normal) | Yes | [docs][r-evim] |
| | envpath-injection-critical | Critical | Untrusted input to $GITHUB_PATH (privileged) | Yes | [docs][r-epi] |
| | envpath-injection-medium | Medium | Untrusted input to $GITHUB_PATH (normal) | Yes | [docs][r-epim] |
| | output-clobbering-critical | Critical | Untrusted input to $GITHUB_OUTPUT (privileged) | Yes | [docs][r-oc] |
| | output-clobbering-medium | Medium | Untrusted input to $GITHUB_OUTPUT (normal) | Yes | [docs][r-oc] |
| | argument-injection-critical | Critical | Command-line argument injection (privileged) | Yes | [docs][r-ai] |
| | argument-injection-medium | Medium | Command-line argument injection (normal) | Yes | [docs][r-ai] |
| **Checkout** | untrusted-checkout | Critical | Untrusted PR code in privileged contexts | Yes | [docs][r-uco] |
| | untrusted-checkout-toctou-critical | Critical | TOCTOU with labeled events | Yes | [docs][r-toctou-c] |
| | untrusted-checkout-toctou-high | High | TOCTOU with deployment environment | Yes | [docs][r-toctou-h] |
| **Supply Chain** | commit-sha | High | Action version pinning validation | Yes | [docs][r-sha] |
| | action-list | Low | Organization allowlist/blocklist enforcement | | [docs][r-al] |
| | impostor-commit | Critical | Fork network impostor commit detection | Yes | [docs][r-ic] |
| | ref-confusion | High | Branch/tag name collision detection | Yes | [docs][r-rc] |
| | known-vulnerable-actions | Varies | Known CVE detection via GitHub Advisories | Yes | [docs][r-kva] |
| | archived-uses | Medium | Archived action/workflow detection | | [docs][r-au] |
| | unpinned-images | Medium | Container image digest pinning | | [docs][r-ui] |
| | dependabot-github-actions | Medium | Missing github-actions ecosystem in dependabot.yaml | Yes | [docs][r-dga] |
| | reusable-workflow-taint | Critical | Untrusted inputs in reusable workflow calls | Yes | [docs][r-rwt] |
| **Poisoning** | artifact-poisoning-critical | Critical | Artifact poisoning and path traversal | Yes | [docs][r-apc] |
| | artifact-poisoning-medium | Medium | Third-party artifact download in untrusted triggers | Yes | [docs][r-apm] |
| | cache-poisoning | High | Unsafe cache patterns with untrusted inputs | Yes | [docs][r-cp] |
| | cache-poisoning-poisonable-step | High | Untrusted code execution after unsafe checkout | Yes | [docs][r-cpp] |
| **Access Control** | improper-access-control | High | Label-based approval and synchronize events | Yes | [docs][r-iac] |
| | bot-conditions | High | Spoofable bot detection conditions | Yes | [docs][r-bot] |
| | unsound-contains | Medium | Bypassable contains() in conditions | Yes | [docs][r-uc] |
| | dangerous-triggers-critical | Critical | Privileged triggers without mitigations | Yes | [docs][r-dt-c] |
| | dangerous-triggers-medium | Medium | Privileged triggers with partial mitigations | Yes | [docs][r-dt-m] |
| **Other** | obfuscation | High | Obfuscated workflow pattern detection | Yes | [docs][r-ob] |
| | self-hosted-runners | High | Self-hosted runner security risks | | [docs][r-shr] |
| | request-forgery-critical | Critical | SSRF vulnerabilities (privileged) | Yes | [docs][r-rf] |
| | request-forgery-medium | Medium | SSRF vulnerabilities (normal) | Yes | [docs][r-rf] |
| **AI Actions** | ai-action-unrestricted-trigger | High | AI agent actions with `allowed_non_write_users: "*"` | | [docs][r-aaut] |
| | ai-action-excessive-tools | High | Dangerous tools (Bash/Write/Edit) under untrusted triggers | | [docs][r-aaet] |
| | ai-action-prompt-injection | High | Untrusted input interpolated into AI agent prompts | | [docs][r-aapi] |
| | ai-action-unsafe-sandbox | High | Unsafe sandbox / safety-strategy settings | | [docs][r-aaus] |
| | ai-action-execution-order | Medium | AI agent action not the last step in a job | | [docs][r-aaeo] |

</details>

---

## Example: detecting real vulnerabilities

Given a workflow with several common security mistakes:

```yaml
name: PR Comment Handler

on:
  pull_request_target:
    types: [opened, synchronize]
  issue_comment:
    types: [created]

jobs:
  process-pr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - name: Echo PR title
        run: |
          echo "Processing PR: ${{ github.event.pull_request.title }}"

      - name: Run build
        run: npm install && npm run build
```

`sisakulint -enable-rule missing-timeout-minutes` flags every line that matters, with a code snippet and a link to the rule docs:

```text
.github/workflows/demo.yaml:1:1: workflow does not have explicit 'permissions' block.
Follow the principle of least privilege.
See https://sisaku-security.github.io/lint/docs/rules/permissions/ [permissions]
   1 👈| name: PR Comment Handler

.github/workflows/demo.yaml:4:3: dangerous trigger (critical): pull_request_target +
issue_comment without any security mitigations.
See https://sisaku-security.github.io/lint/docs/rules/dangeroustriggersrulecritical/ [dangerous-triggers-critical]
   4 👈|   pull_request_target:

.github/workflows/demo.yaml:13:9: the action ref should be a full length commit SHA. [commit-sha]
  13 👈|       - uses: actions/checkout@v4

.github/workflows/demo.yaml:15:16: untrusted PR code checked out in pull_request_target context.
See https://sisaku-security.github.io/lint/docs/rules/untrustedcheckout/ [untrusted-checkout]
  15 👈|           ref: ${{ github.event.pull_request.head.sha }}

.github/workflows/demo.yaml:19:35: code injection (critical): github.event.pull_request.title
is interpolated into an inline script.
See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
  19 👈|           echo "Processing PR: ${{ github.event.pull_request.title }}"

[sisaku:🤔] Detected 7 errors in 1 file checked
```

| Finding | OWASP | Severity | Auto-fix |
|:--------|:------|:---------|:--------:|
| Missing permissions block | CICD-SEC-02 | High | Yes |
| Dangerous privileged triggers | CICD-SEC-01 | Critical | Yes |
| Action not pinned to SHA | CICD-SEC-08 | High | Yes |
| Credential exposure (persist-credentials) | CICD-SEC-06 | Critical | Yes |
| Untrusted checkout | CICD-SEC-04 | Critical | Yes |
| Code injection | CICD-SEC-04 | Critical | Yes |
| Cache poisoning | CICD-SEC-09 | High | Yes |

Run `sisakulint -fix on` and most of these are repaired in place.

---

## Auto-fix

27+ rules ship with an auto-fixer. Two modes:

```bash
sisakulint -fix dry-run   # show diff, don't write
sisakulint -fix on        # apply changes to YAML files
```

Auto-fix-capable rules currently include: `timeout-minutes`, `commit-sha`, `credentials`, `code-injection-*`, `envvar-injection-*`, `envpath-injection-*`, `output-clobbering-*`, `argument-injection-*`, `request-forgery-*`, `untrusted-checkout`, `untrusted-checkout-toctou-*`, `artifact-poisoning-*`, `cache-poisoning`, `cache-poisoning-poisonable-step`, `cache-bloat`, `artipacked`, `secrets-in-artifacts`, `secrets-inherit`, `secret-in-log`, `secret-exposure`, `unmasked-secret-exposure`, `improper-access-control`, `bot-conditions`, `unsound-contains`, `obfuscation`, `ref-confusion`, `impostor-commit`, `known-vulnerable-actions`, `dangerous-triggers-*`, `cond`, `permissions`, `dependabot-github-actions`, `reusable-workflow-taint` (cross-file `ChainFixer` lifts callee `${{ inputs.X }}` into a step-level `env:`).

A few representative fixes:

<details>
<summary><b>Code injection — move untrusted input into <code>env:</code></b></summary>

Before:

```yaml
- run: echo "Processing PR: ${{ github.event.pull_request.title }}"
```

After:

```yaml
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "Processing PR: $PR_TITLE"
```

</details>

<details>
<summary><b>commit-sha — pin action tags to full SHA, preserve original tag as comment</b></summary>

Before:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v3
```

After:

```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4
- uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8 # v3
```

</details>

<details>
<summary><b>untrusted-checkout — add explicit ref in privileged contexts</b></summary>

Before:

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
```

After:

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.base.ref }}
```

</details>

> **Notes**
> - Always review the diff (or use `-fix dry-run`) before committing.
> - `commit-sha` calls the GitHub API to resolve tags; unauthenticated requests are limited to 60/hr.
> - A handful of rules (e.g. `expression`, `secret-exfiltration`, `self-hosted-runners`, `action-list`, AI-action rules) are warning-only because the right fix depends on the user's policy.

---

## SARIF + reviewdog integration

```bash
sisakulint -format "{{sarif .}}"                  # stdout
sisakulint -format "{{sarif .}}" > results.sarif  # to file
sisakulint -format "{{sarif .}}" | reviewdog -f=sarif -reporter=github-pr-review
```

<div align="center">
  <img width="700" alt="reviewdog showing sisakulint findings inline on a GitHub PR" src="https://github.com/user-attachments/assets/66e34b76-63f9-4d30-95b5-206bec0f7d41" />
  <p><i>sisakulint findings rendered inline on a GitHub PR via reviewdog</i></p>
</div>

A complete GitHub Actions recipe is in [Installation → As a GitHub Action](#as-a-github-action-with-reviewdog).

---

## Configuration

Generate a starter config:

```bash
sisakulint -init   # writes .github/action.yaml
```

The config file lets you set per-repo allowlists, block lists, and rule overrides. Useful flags:

```bash
sisakulint -ignore "permissions" -ignore "SC2086"   # mute specific rules / patterns
sisakulint -enable-rule missing-timeout-minutes     # enable an opt-in rule
sisakulint -boilerplate                             # print a hardened workflow skeleton
sisakulint -debug                                   # dump AST traversal + rule decisions
```

### JSON schema for editor autocompletion

Add to your VS Code `settings.json`:

```json
"yaml.schemas": {
  "https://github.com/sisaku-security/homebrew-sisakulint/raw/main/settings.json": "/.github/workflows/*.{yml,yaml}"
}
```

---

- **Always review changes**: Even though autofix is automated, always review the changes made to your workflow files before committing them
- **Commit SHA fixes require internet**: The `commit-sha` rule needs to fetch commit information from GitHub, so it requires an active internet connection
- **Rate limiting**: The commit SHA autofix makes GitHub API calls, which are subject to rate limiting. Unauthenticated requests are capped at **60 requests per hour**. Set a token to lift the limit to 5,000 req/h:
   - `SISAKULINT_GITHUB_TOKEN` (preferred — scoped to this tool)
   - `GITHUB_TOKEN` (read from the process environment; inside a GitHub Actions step you must map it explicitly, e.g. `env: GITHUB_TOKEN: ${{ github.token }}` — the runner does not export `secrets.GITHUB_TOKEN` to `run:` steps automatically)
   - `GH_TOKEN` (set by `gh auth login`)
   - `-github-token "$(gh auth token)"` (CLI flag, highest priority)

   A fine-grained PAT with `public_repo` (or just `Metadata: Read-only` on the targets you pin) is sufficient. When sisakulint detects no token at startup, it now prints a warning. If the rate limit is exhausted mid-run, sisakulint aborts with a non-zero exit and skips writing partial output for the affected file rather than leaving a mix of pinned and unpinned actions on disk.
- **Backup your files**: Consider committing your changes or backing up your workflow files before running autofix
- **Not all rules support autofix**: Some rules like `expression`, `permissions`, `issue-injection`, `cache-poisoning`, and `deprecated-commands` require manual fixes as they depend on your specific use case
- **Auto-fix capabilities**: Currently, `timeout-minutes`, `commit-sha`, `credentials`, `untrusted-checkout`, and `artifact-poisoning` rules support auto-fix. More rules will support auto-fix in future releases

## Architecture


<div align="center">
  <img src="https://github.com/user-attachments/assets/4c6fa378-5878-48af-b95f-8b987b3cf7ef" alt="sisakulint architecture diagram" width="600"/>
</div>

```
.github/workflows/*.yml
        │
        ▼
[ AST parser ]  ──► [ Expression parser (${{ }}) ]
        │                       │
        ▼                       ▼
[ Shell parser (mvdan.cc/sh) ]  [ Taint propagator ]
        │                       │
        └───────────► [ Rule engine ] ◄───── 50+ rules
                              │
                ┌─────────────┴─────────────┐
                ▼                           ▼
        [ Error formatter ]          [ Auto-fixer ]
                │                           │
                ▼                           ▼
        SARIF / pretty text         in-place YAML rewrite
```

- **AST parser** — `pkg/ast`, `pkg/core/parse_*.go`
- **Expression parser** — `pkg/expressions` (full GitHub Actions `${{ }}` grammar)
- **Shell parser & taint** — `pkg/shell` (scope-aware bash semantics, function-arg propagation)
- **Rule engine** — `pkg/core/*rule.go` implementing the visitor pattern
- **Auto-fixer** — `pkg/core/autofixer.go`

---

## BlackHat Arsenal 2025

<div align="center">
  <a href="https://speakerdeck.com/4su_para/sisakulint-ci-friendly-static-linter-with-sast-semantic-analysis-for-github-actions">
    <img src="https://files.speakerdeck.com/presentations/8047bdafc1db4bdb9a5dbc0a5825e5e2/preview_slide_0.jpg?34808843" alt="sisakulint at BlackHat Arsenal 2025" width="600"/>
  </a>

  **[▶️ Slides](https://speakerdeck.com/4su_para/sisakulint-ci-friendly-static-linter-with-sast-semantic-analysis-for-github-actions)** · **[📥 PDF](https://files.speakerdeck.com/presentations/8047bdafc1db4bdb9a5dbc0a5825e5e2/BlackHatArsenal2025.pdf)** · **[📄 SecHack365 poster](https://sechack365.nict.go.jp/achievement/2023/pdf/14C.pdf)** · **[📺 Talk recording](https://www.youtube.com/watch?v=DhgqKOmzLSk)**

  <a href="https://www.youtube.com/watch?v=DhgqKOmzLSk">
    <img src="https://img.youtube.com/vi/DhgqKOmzLSk/hqdefault.jpg" alt="Watch the sisakulint talk on YouTube" width="480"/>
  </a>
</div>

sisakulint was showcased at **BlackHat Asia 2025 Arsenal**. The talk covers the SAST design, the semantic-analysis approach to GitHub Actions security, the auto-fix pipeline, and real-world OWASP CI/CD Top-10 case studies. Originally built as a [SecHack365](https://sechack365.nict.go.jp/) 2023 project under NICT.

---

## Contributing

Bug reports, rule proposals, and PRs are very welcome.

- File issues at <https://github.com/sisaku-security/sisakulint/issues>
- Adding a new rule: see [`docs/RULES_GUIDE.md`](docs/RULES_GUIDE.md) and the example workflows under [`script/actions/`](script/actions/)
- Run the test suite: `go test ./...`
- Run against the bundled examples: `sisakulint script/actions/`

If sisakulint helps you keep a workflow safe, please ⭐️ the repo — it makes it much easier for other security teams to find.

---

## License

[Apache License 2.0](LICENSE) © sisaku-security contributors.

## Citation

If you reference sisakulint in academic or industry work:

```bibtex
@software{sisakulint,
  title  = {sisakulint: CI-friendly static linter with SAST semantic analysis for GitHub Actions},
  author = {sisaku-security contributors},
  year   = {2025},
  url    = {https://github.com/sisaku-security/sisakulint}
}
```

---

<!-- OWASP Links -->
[owasp-01]: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-01-Insufficient-Flow-Control-Mechanisms
[owasp-02]: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-02-Inadequate-Identity-and-Access-Management
[owasp-03]: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse
[owasp-04]: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution
[owasp-05]: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-05-Insufficient-PBAC
[owasp-06]: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-06-Insufficient-Credential-Hygiene
[owasp-07]: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-07-Insecure-System-Configuration
[owasp-08]: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-08-Ungoverned-Usage-of-Third-Party-Services
[owasp-09]: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation
[owasp-10]: https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-10-Insufficient-Logging-and-Visibility

<!-- sisakulint Docs Links -->
[r-id]: https://sisaku-security.github.io/lint/docs/rules/idrule/
[r-env]: https://sisaku-security.github.io/lint/docs/rules/environmentvariablerule/
[r-perm]: https://sisaku-security.github.io/lint/docs/rules/permissions/
[r-wc]: https://sisaku-security.github.io/lint/docs/rules/workflowcall/
[r-jn]: https://sisaku-security.github.io/lint/docs/rules/jobneeds/
[r-expr]: https://sisaku-security.github.io/lint/docs/rules/expressionrule/
[r-cond]: https://sisaku-security.github.io/lint/docs/rules/conditionalrule/
[r-dc]: https://sisaku-security.github.io/lint/docs/rules/deprecatedcommandsrule/
[r-tm]: https://sisaku-security.github.io/lint/docs/rules/timeoutminutesrule/
[r-cb]: https://sisaku-security.github.io/lint/docs/rules/cachebloatrule/
[r-cred]: https://sisaku-security.github.io/lint/docs/rules/credentialrules/
[r-se]: https://sisaku-security.github.io/lint/docs/rules/secretexposure/
[r-use]: https://sisaku-security.github.io/lint/docs/rules/unmaskedsecretexposure/
[r-ap]: https://sisaku-security.github.io/lint/docs/rules/artipacked/
[r-sia]: https://sisaku-security.github.io/lint/docs/rules/secretsinartifacts/
[r-si]: https://sisaku-security.github.io/lint/docs/rules/secretsinherit/
[r-sef]: https://sisaku-security.github.io/lint/docs/rules/secretexfiltration/
[r-sil]: https://sisaku-security.github.io/lint/docs/rules/secretinlogrule/
[r-ci]: https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/
[r-cim]: https://sisaku-security.github.io/lint/docs/rules/codeinjectionmedium/
[r-evi]: https://sisaku-security.github.io/lint/docs/rules/envvarinjectioncritical/
[r-evim]: https://sisaku-security.github.io/lint/docs/rules/envvarinjectionmedium/
[r-epi]: https://sisaku-security.github.io/lint/docs/rules/envpathinjectioncritical/
[r-epim]: https://sisaku-security.github.io/lint/docs/rules/envpathinjectionmedium/
[r-oc]: https://sisaku-security.github.io/lint/docs/rules/outputclobbering/
[r-ai]: https://sisaku-security.github.io/lint/docs/rules/argumentinjection/
[r-uco]: https://sisaku-security.github.io/lint/docs/rules/untrustedcheckout/
[r-toctou-c]: https://sisaku-security.github.io/lint/docs/rules/untrustedcheckouttoctoucritical/
[r-toctou-h]: https://sisaku-security.github.io/lint/docs/rules/untrustedcheckouttoctouhigh/
[r-sha]: https://sisaku-security.github.io/lint/docs/rules/commitsharule/
[r-al]: https://sisaku-security.github.io/lint/docs/rules/actionlist/
[r-ic]: https://sisaku-security.github.io/lint/docs/rules/impostorcommit/
[r-rc]: https://sisaku-security.github.io/lint/docs/rules/refconfusion/
[r-kva]: https://sisaku-security.github.io/lint/docs/rules/knownvulnerableactions/
[r-au]: https://sisaku-security.github.io/lint/docs/rules/archiveduses/
[r-ui]: https://sisaku-security.github.io/lint/docs/rules/unpinnedimages/
[r-dga]: https://sisaku-security.github.io/lint/docs/rules/dependabotgithubactions/
[r-rwt]: https://sisaku-security.github.io/lint/docs/rules/reusableworkflowtaint/
[r-apc]: https://sisaku-security.github.io/lint/docs/rules/artifactpoisoningcritical/
[r-apm]: https://sisaku-security.github.io/lint/docs/rules/artifactpoisoningmedium/
[r-cp]: https://sisaku-security.github.io/lint/docs/rules/cachepoisoningrule/
[r-cpp]: https://sisaku-security.github.io/lint/docs/rules/cachepoisoningpoisonablesteprule/
[r-iac]: https://sisaku-security.github.io/lint/docs/rules/improperaccesscontrol/
[r-bot]: https://sisaku-security.github.io/lint/docs/rules/botconditions/
[r-uc]: https://sisaku-security.github.io/lint/docs/rules/unsoundcontains/
[r-dt-c]: https://sisaku-security.github.io/lint/docs/rules/dangeroustriggersrulecritical/
[r-dt-m]: https://sisaku-security.github.io/lint/docs/rules/dangeroustriggersrulemedium/
[r-ob]: https://sisaku-security.github.io/lint/docs/rules/obfuscation/
[r-shr]: https://sisaku-security.github.io/lint/docs/rules/selfhostedrunners/
[r-rf]: https://sisaku-security.github.io/lint/docs/rules/requestforgery/
[r-aaut]: https://sisaku-security.github.io/lint/docs/rules/aiactionunrestrictedtrigger/
[r-aaet]: https://sisaku-security.github.io/lint/docs/rules/aiactionexcessivetools/
[r-aapi]: https://sisaku-security.github.io/lint/docs/rules/aiactionpromptinjection/
[r-aaus]: https://sisaku-security.github.io/lint/docs/rules/aiactionunsafesandbox/
[r-aaeo]: https://sisaku-security.github.io/lint/docs/rules/aiactionexecutionorder/
