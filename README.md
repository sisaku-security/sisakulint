# sisakulint

Before moving on, please consider giving us a GitHub star ⭐️. Thank you!

<img src="https://github.com/sisaku-security/homebrew-sisakulint/assets/67861004/e9801cbb-fbe1-4822-a5cd-d1daac33e90f" alt="sisakulint logo" width="160" height="160"/> 

## what is this?

In recent years, attacks targeting the Web Application Platform have been increasing rapidly.
sisakulint is **a static and fast SAST for GitHub Actions**. 

This great tool can automatically validate yaml files according to the guidelines in the security-related documentation provided by GitHub!

It also includes functionality as a static analysis tool that can check the policies of the guidelines that should be set for use in each organization.

These checks also comply with [the Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/) provided by OWASP.

It implements most of the functions that can automatically check whether a workflow that meets the [security features](https://docs.github.com/ja/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions) supported by github has been built to reduce the risk of malicious code being injected into the CI/CD pipeline or credentials such as tokens being stolen.

It does not support inspections that cannot be expressed in YAML and "repository level settings" that can be set by GitHub organization administrators.

It is intended to be used mainly by software developers and security personnel at user companies who work in blue teams. 

It is easy to introduce because it can be installed from brew.

It also implements an autofix function for errors related to security features as a lint.

It supports the SARIF format, which is the output format for static analysis. This allows [reviewdog](https://github.com/reviewdog/reviewdog?tab=readme-ov-file#sarif-format) to provide a rich UI for error triage on GitHub.

---

## 🎤 Featured at BlackHat Arsenal

<div align="center">
  <a href="https://speakerdeck.com/4su_para/sisakulint-ci-friendly-static-linter-with-sast-semantic-analysis-for-github-actions">
    <img src="https://files.speakerdeck.com/presentations/8047bdafc1db4bdb9a5dbc0a5825e5e2/preview_slide_0.jpg?34808843" alt="sisakulint BlackHat Arsenal 2025 presentation slides" width="600"/>
  </a>

  **[▶️ View Presentation](https://speakerdeck.com/4su_para/sisakulint-ci-friendly-static-linter-with-sast-semantic-analysis-for-github-actions)** | **[📥 Download PDF](https://files.speakerdeck.com/presentations/8047bdafc1db4bdb9a5dbc0a5825e5e2/BlackHatArsenal2025.pdf)** | **[📄 Poster](https://sechack365.nict.go.jp/achievement/2023/pdf/14C.pdf)**
</div>

<details>
<summary><b>📖 About the Presentation</b></summary>

<br>

sisakulint was showcased at **BlackHat Asia 2025 Arsenal**, one of the world's leading information security conferences. The presentation demonstrates how sisakulint addresses real-world CI/CD security challenges and helps development teams build more secure GitHub Actions workflows.

**Key topics covered:**
- 🔒 Security challenges in GitHub Actions workflows
- 🔍 SAST approach and semantic analysis techniques
- ⚙️ Practical rule implementations with real-world examples
- 🤖 Automated security testing and auto-fix capabilities
- 🛡️ Defense strategies against OWASP Top 10 CI/CD Security Risks

</details>

---

## Tool features

**Full Documentation**: https://sisaku-security.github.io/lint/

### OWASP Top 10 CI/CD Security Risks Coverage

| OWASP Risk | Description | sisakulint Rules |
|:-----------|:------------|:-----------------|
| [CICD-SEC-01][owasp-01] | Insufficient Flow Control Mechanisms | [improper-access-control][r-iac], [bot-conditions][r-bot], [unsound-contains][r-uc] |
| [CICD-SEC-02][owasp-02] | Inadequate Identity and Access Management | [permissions][r-perm], [secret-exposure][r-se], [unmasked-secret-exposure][r-use] |
| [CICD-SEC-03][owasp-03] | Dependency Chain Abuse | [known-vulnerable-actions][r-kva], [archived-uses][r-au], [impostor-commit][r-ic], [ref-confusion][r-rc] |
| [CICD-SEC-04][owasp-04] | Poisoned Pipeline Execution (PPE) | [code-injection-*][r-ci], [envvar-injection-*][r-evi], [envpath-injection-*][r-epi], [untrusted-checkout-*][r-uco] |
| [CICD-SEC-05][owasp-05] | Insufficient PBAC | [self-hosted-runners][r-shr] |
| [CICD-SEC-06][owasp-06] | Insufficient Credential Hygiene | [credentials][r-cred], [artipacked][r-ap] |
| [CICD-SEC-07][owasp-07] | Insecure System Configuration | [timeout-minutes][r-tm], [deprecated-commands][r-dc] |
| [CICD-SEC-08][owasp-08] | Ungoverned Usage of 3rd Party Services | [action-list][r-al], [commit-sha][r-sha], [unpinned-images][r-ui] |
| [CICD-SEC-09][owasp-09] | Improper Artifact Integrity Validation | [artifact-poisoning-*][r-apc], [cache-poisoning-*][r-cp] |
| [CICD-SEC-10][owasp-10] | Insufficient Logging and Visibility | [obfuscation][r-ob] |

### Complete Rule Reference

| Category | Rule | Description | Fix | Docs | GitHub Ref |
|:---------|:-----|:------------|:---:|:----:|:----------:|
| **Syntax** | id | ID collision detection for jobs/env vars | | [docs][r-id] | [ref][gh-shell] |
| | env-var | Environment variable name validation | | | |
| | permissions | Permission scopes and values validation | | [docs][r-perm] | [ref][gh-perm] |
| | workflow-call | Reusable workflow call validation | | [docs][r-wc] | [ref][gh-reuse] |
| | job-needs | Job dependency validation | | [docs][r-jn] | |
| | expression | Expression syntax validation | | | |
| | cond | Conditional expression validation | | | |
| | deprecated-commands | Deprecated workflow commands detection | | | [ref][gh-cmd] |
| **Config** | timeout-minutes | Ensures timeout-minutes is set | Yes | [docs][r-tm] | [ref][gh-timeout] |
| **Credentials** | credentials | Hardcoded credentials detection | Yes | [docs][r-cred] | |
| | secret-exposure | Excessive secrets exposure detection | Yes | [docs][r-se] | |
| | unmasked-secret-exposure | Unmasked derived secrets detection | Yes | [docs][r-use] | |
| | artipacked | Credential leakage via persisted checkout | Yes | [docs][r-ap] | |
| **Injection** | code-injection-critical | Untrusted input in privileged triggers | Yes | [docs][r-ci] | [ref][gh-inject] |
| | code-injection-medium | Untrusted input in normal triggers | Yes | [docs][r-cim] | |
| | envvar-injection-critical | Untrusted input to $GITHUB_ENV (privileged) | Yes | [docs][r-evi] | |
| | envvar-injection-medium | Untrusted input to $GITHUB_ENV (normal) | Yes | | |
| | envpath-injection-critical | Untrusted input to $GITHUB_PATH (privileged) | Yes | [docs][r-epi] | |
| | envpath-injection-medium | Untrusted input to $GITHUB_PATH (normal) | Yes | | |
| **Checkout** | untrusted-checkout | Untrusted PR code in privileged contexts | Yes | [docs][r-uco] | [ref][gh-pwn] |
| | untrusted-checkout-toctou-critical | TOCTOU with labeled events | Yes | | |
| | untrusted-checkout-toctou-high | TOCTOU with deployment environment | Yes | | |
| **Supply Chain** | commit-sha | Action version pinning validation | Yes | [docs][r-sha] | [ref][gh-3p] |
| | action-list | Organization allowlist/blocklist enforcement | | [docs][r-al] | |
| | impostor-commit | Fork network impostor commit detection | Yes | [docs][r-ic] | |
| | ref-confusion | Branch/tag name collision detection | Yes | [docs][r-rc] | |
| | known-vulnerable-actions | Known CVE detection via GitHub Advisories | Yes | [docs][r-kva] | |
| | archived-uses | Archived action/workflow detection | | [docs][r-au] | |
| | unpinned-images | Container image digest pinning | | [docs][r-ui] | |
| **Poisoning** | artifact-poisoning-critical | Artifact poisoning and path traversal | Yes | [docs][r-apc] | |
| | artifact-poisoning-medium | Third-party artifact download in untrusted triggers | Yes | [docs][r-apm] | |
| | cache-poisoning | Unsafe cache patterns with untrusted inputs | Yes | [docs][r-cp] | |
| | cache-poisoning-poisonable-step | Untrusted code execution after unsafe checkout | Yes | | |
| **Access Control** | improper-access-control | Label-based approval and synchronize events | Yes | [docs][r-iac] | |
| | bot-conditions | Spoofable bot detection conditions | Yes | [docs][r-bot] | |
| | unsound-contains | Bypassable contains() in conditions | Yes | [docs][r-uc] | |
| **Other** | obfuscation | Obfuscated workflow pattern detection | Yes | [docs][r-ob] | |
| | self-hosted-runners | Self-hosted runner security risks | | [docs][r-shr] | |

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
[r-perm]: https://sisaku-security.github.io/lint/docs/rules/permissions/
[r-wc]: https://sisaku-security.github.io/lint/docs/rules/workflowcall/
[r-jn]: https://sisaku-security.github.io/lint/docs/rules/jobneeds/
[r-tm]: https://sisaku-security.github.io/lint/docs/rules/timeoutminutesrule/
[r-cred]: https://sisaku-security.github.io/lint/docs/rules/credentialrules/
[r-se]: https://sisaku-security.github.io/lint/docs/rules/secretexposure/
[r-use]: https://sisaku-security.github.io/lint/docs/rules/unmaskedsecretexposure/
[r-ap]: https://sisaku-security.github.io/lint/docs/rules/artipacked/
[r-ci]: https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/
[r-cim]: https://sisaku-security.github.io/lint/docs/rules/codeinjectionmedium/
[r-evi]: https://sisaku-security.github.io/lint/docs/rules/envvarinjectioncritical/
[r-epi]: https://sisaku-security.github.io/lint/docs/rules/envpathinjectioncritical/
[r-uco]: https://sisaku-security.github.io/lint/docs/rules/untrustedcheckout/
[r-sha]: https://sisaku-security.github.io/lint/docs/rules/commitsharule/
[r-al]: https://sisaku-security.github.io/lint/docs/rules/actionlist/
[r-ic]: https://sisaku-security.github.io/lint/docs/rules/impostorcommit/
[r-rc]: https://sisaku-security.github.io/lint/docs/rules/refconfusion/
[r-kva]: https://sisaku-security.github.io/lint/docs/rules/knownvulnerableactions/
[r-au]: https://sisaku-security.github.io/lint/docs/rules/archiveduses/
[r-ui]: https://sisaku-security.github.io/lint/docs/rules/unpinnedimages/
[r-apc]: https://sisaku-security.github.io/lint/docs/rules/artifactpoisoningcritical/
[r-apm]: https://sisaku-security.github.io/lint/docs/rules/artifactpoisoningmedium/
[r-cp]: https://sisaku-security.github.io/lint/docs/rules/cachepoisoningrule/
[r-iac]: https://sisaku-security.github.io/lint/docs/rules/improperaccesscontrol/
[r-bot]: https://sisaku-security.github.io/lint/docs/rules/botconditions/
[r-uc]: https://sisaku-security.github.io/lint/docs/rules/unsoundcontains/
[r-ob]: https://sisaku-security.github.io/lint/docs/rules/obfuscation/
[r-shr]: https://sisaku-security.github.io/lint/docs/rules/selfhostedrunners/
[r-dc]: https://sisaku-security.github.io/lint/docs/rules/deprecatedcommands/

<!-- GitHub Reference Links -->
[gh-shell]: https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#using-a-specific-shell
[gh-perm]: https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#permissions
[gh-reuse]: https://docs.github.com/en/actions/sharing-automations/reusing-workflows
[gh-cmd]: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions
[gh-timeout]: https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes
[gh-inject]: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections
[gh-pwn]: https://docs.github.com/en/actions/security-for-github-actions/security-guides/keeping-your-github-actions-and-workflows-secure-preventing-pwn-requests
[gh-3p]: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-third-party-actions

## install for macOS user

```bash
$ brew tap sisaku-security/homebrew-sisakulint
$ brew install sisakulint
```

## install from release page for Linux user

```bash
# visit release page of this repository and download for yours.
$ cd <directory where sisakulint binary is located>
$ mv ./sisakulint /usr/local/bin/sisakulint
```

## Architecture

<div align="center">
  <img src="https://github.com/user-attachments/assets/4c6fa378-5878-48af-b95f-8b987b3cf7ef" alt="sisakulint architecture diagram" width="600"/>
</div>

sisakulint automatically searches for YAML files in the `.github/workflows` directory. The parser builds an Abstract Syntax Tree (AST) and traverses it to apply various security and best practice rules. Results are output using a custom error formatter, with support for SARIF format for integration with tools like reviewdog.

**Key components:**
- 📁 **Workflow Discovery** - Automatic detection of GitHub Actions workflow files
- 🔍 **AST Parser** - Converts YAML into a structured tree representation
- ⚖️ **Rule Engine** - Applies security and best practice validation rules
- 📊 **Output Formatters** - Custom error format and SARIF support for CI/CD integration

## Quick Start

```bash
# Run in your repository (auto-detects .github/workflows/)
$ sisakulint

# Analyze specific file
$ sisakulint .github/workflows/ci.yaml

# Preview auto-fixes without modifying files
$ sisakulint -fix dry-run

# Apply auto-fixes
$ sisakulint -fix on

# Output in SARIF format for CI/CD integration
$ sisakulint -format "{{sarif .}}"
```

## Example: Detecting Security Vulnerabilities

Given a workflow file with common security issues:

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

Running `sisakulint` detects multiple security issues:

```
.github/workflows/test.yaml:1:1: workflow does not have explicit 'permissions' block.
  Add a 'permissions:' block to follow the principle of least privilege. [permissions]

.github/workflows/test.yaml:10:3: timeout-minutes is not set for job process-pr [missing-timeout-minutes]

.github/workflows/test.yaml:13:9: the action ref should be a full length commit SHA
  for immutability and security. [commit-sha]

.github/workflows/test.yaml:13:9: [Medium] actions/checkout without 'persist-credentials: false'.
  Consider adding it to prevent credential exposure. [artipacked]

.github/workflows/test.yaml:15:16: checking out untrusted code from pull request
  in workflow with privileged trigger 'issue_comment'. This allows potentially
  malicious code to execute with access to repository secrets. [untrusted-checkout]

.github/workflows/test.yaml:19:35: code injection (critical): "github.event.pull_request.title"
  is potentially untrusted. Avoid using it directly in inline scripts.
  Instead, pass it through an environment variable. [code-injection-critical]

.github/workflows/test.yaml:21:9: cache poisoning risk via build command: 'Run build'
  runs untrusted code after checking out PR head. [cache-poisoning-poisonable-step]
```

### What sisakulint detected

| Finding | OWASP Risk | Severity | Auto-fix |
|:--------|:-----------|:---------|:--------:|
| Missing permissions block | CICD-SEC-02 | Medium | |
| Missing timeout-minutes | CICD-SEC-07 | Low | Yes |
| Action not pinned to SHA | CICD-SEC-08 | Medium | Yes |
| Credential exposure risk | CICD-SEC-06 | Medium | Yes |
| Untrusted checkout | CICD-SEC-04 | Critical | Yes |
| Code injection | CICD-SEC-04 | Critical | Yes |
| Cache poisoning | CICD-SEC-09 | High | Yes |

## SARIF Output & Integration with reviewdog

sisakulint supports SARIF (Static Analysis Results Interchange Format) output, which enables seamless integration with [reviewdog](https://github.com/reviewdog/reviewdog) for enhanced code review workflows on GitHub.

### Why SARIF + reviewdog?

SARIF format allows sisakulint to provide:
- **Rich GitHub UI integration** - Errors appear directly in pull request reviews
- **Inline annotations** - Issues are shown at the exact file location
- **Automatic triage** - Easy filtering and management of findings
- **CI/CD pipeline integration** - Automated security checks in your workflow

### Visual Example

<div align="center">
  <img width="926" height="482" alt="reviewdog integration showing sisakulint findings in GitHub PR" src="https://github.com/user-attachments/assets/66e34b76-63f9-4d30-95b5-206bec0f7d41" />
  <p><i>sisakulint findings displayed directly in GitHub pull request using reviewdog</i></p>
</div>

### How to integrate

Add the following step to your GitHub Actions workflow:

```yaml
name: Lint GitHub Actions Workflows
on: [pull_request]

jobs:
  sisakulint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install sisakulint
        run: |
          # Download from release page or install via brew
          # Example: wget https://github.com/sisaku-security/sisakulint/releases/latest/download/sisakulint-linux-amd64

      - name: Run sisakulint with reviewdog
        env:
          REVIEWDOG_GITHUB_API_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          sisakulint -format "{{sarif .}}" | \
          reviewdog -f=sarif -reporter=github-pr-review -filter-mode=nofilter
```

### SARIF format usage

To output results in SARIF format

```bash
# Output to stdout
$ sisakulint -format "{{sarif .}}"

# Save to file
$ sisakulint -format "{{sarif .}}" > results.sarif

# Pipe to reviewdog
$ sisakulint -format "{{sarif .}}" | reviewdog -f=sarif -reporter=github-pr-review
```

### Benefits in CI/CD

- ✅ **Automated security reviews** - Every PR is automatically checked
- ✅ **Early detection** - Find issues before merging
- ✅ **Clear feedback** - Developers see exactly what needs to be fixed
- ✅ **Consistent standards** - Enforce security policies across all workflows
- ✅ **Integration with existing tools** - Works with your current GitHub workflow

## Using autofix features

sisakulint provides an automated fix feature that can automatically resolve certain types of security issues and best practice violations. This feature saves time and ensures consistent fixes across your workflow files.

### Available modes

- **`-fix dry-run`**: Show what changes would be made without actually modifying files
- **`-fix on`**: Automatically fix issues and save changes to files

### Rules that support autofix

The following rules support automatic fixes:

#### 1. missing-timeout-minutes (timeout-minutes)
Automatically adds `timeout-minutes: 5` to jobs and steps that don't have it set.

**Before:**
```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
```

**After:**
```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
```

#### 2. commit-sha (commitsha)
Converts action references from tags to full-length commit SHAs for enhanced security. The original tag is preserved as a comment.

**Before:**
```yaml
steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-node@v3
```

**After:**
```yaml
steps:
  - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4
  - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8 # v3
```

#### 3. credentials
Removes hardcoded passwords from container configurations.

**Before:**
```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: myregistry/myimage
      credentials:
        username: ${{ secrets.REGISTRY_USERNAME }}
        password: my-hardcoded-password
```

**After:**
```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: myregistry/myimage
      credentials:
        username: ${{ secrets.REGISTRY_USERNAME }}
```

#### 4. untrusted-checkout
Adds explicit ref specifications to checkout actions in privileged workflow contexts to prevent checking out untrusted PR code.

**Before:**
```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm install
```

**After:**
```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.base.ref }}
      - run: npm install
```

#### 5. artifact-poisoning
Adds validation steps to artifact download operations to prevent path traversal and poisoning attacks.

**Before:**
```yaml
steps:
  - uses: actions/download-artifact@v4
    with:
      name: build-output
  - run: bash ./scripts/deploy.sh
```

**After:**
```yaml
steps:
  - uses: actions/download-artifact@v4
    with:
      name: build-output
  - name: Validate artifact paths
    run: |
      # Validate no path traversal attempts
      find . -name ".." -o -name "../*" | grep . && exit 1 || true
  - run: bash ./scripts/deploy.sh
```

### Usage examples

#### 1. Check what would be fixed (dry-run mode)
```bash
$ sisakulint -fix dry-run
```
This will show all the changes that would be made without actually modifying your files. Use this to preview changes before applying them.

#### 2. Automatically fix issues
```bash
$ sisakulint -fix on
```
This will automatically fix all supported issues and save the changes to your workflow files.

#### 3. Typical workflow
```bash
# First, run without fix to see all issues
$ sisakulint

# Preview what autofix would change
$ sisakulint -fix dry-run

# Apply the fixes
$ sisakulint -fix on

# Verify the changes
$ git diff .github/workflows/
```

### Important notes

- **Always review changes**: Even though autofix is automated, always review the changes made to your workflow files before committing them
- **Commit SHA fixes require internet**: The `commit-sha` rule needs to fetch commit information from GitHub, so it requires an active internet connection
- **Rate limiting**: The commit SHA autofix makes GitHub API calls, which are subject to rate limiting. For unauthenticated requests, the limit is 60 requests per hour
- **Backup your files**: Consider committing your changes or backing up your workflow files before running autofix
- **Not all rules support autofix**: Some rules like `expression`, `permissions`, `issue-injection`, `cache-poisoning`, and `deprecated-commands` require manual fixes as they depend on your specific use case
- **Auto-fix capabilities**: Currently, `timeout-minutes`, `commit-sha`, `credentials`, `untrusted-checkout`, and `artifact-poisoning` rules support auto-fix. More rules will support auto-fix in future releases

## JSON schema for GitHub Actions syntax
paste into your `settings.json`:

```json
 "yaml.schemas": {
     "https://github.com/sisaku-security/homebrew-sisakulint/raw/main/settings.json": "/.github/workflows/*.{yml,yaml}"
 }
```
