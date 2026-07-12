---
title: "Artifact Poisoning Rule（Critical）"
weight: 8
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### Artifact Poisoning Rule （Critical） Overview

This rule detects unsafe artifact download practices that may allow artifact poisoning attacks. Artifact poisoning occurs when malicious artifacts from untrusted sources overwrite existing files in the runner workspace, potentially leading to code execution in privileged contexts.

#### Key Features:

- **Artifact Download Detection**: Identifies uses of `actions/download-artifact` without proper path isolation
- **Extraction Path Validation**: Ensures artifacts are extracted to safe, isolated locations
- **Auto-fix Support**: Automatically configures safe extraction paths using `${{ runner.temp }}/artifacts`
- **Supply Chain Protection**: Prevents malicious artifacts from compromising the build environment

### Security Impact

**Severity: Critical (9/10)**

Artifact poisoning represents a critical security vulnerability in CI/CD pipelines:

1. **File Overwriting**: Malicious artifacts can replace legitimate files in the workspace
2. **Code Execution**: Overwritten scripts or binaries may be executed by subsequent steps
3. **Credential Theft**: Modified code can exfiltrate secrets or access tokens
4. **Build Contamination**: Compromised builds can propagate malicious code to production

This vulnerability is classified as **CWE-829: Inclusion of Functionality from Untrusted Control Sphere** and aligns with OWASP CI/CD Security Risk **CICD-SEC-4: Poisoned Pipeline Execution (PPE)**.

### Example Workflow

Consider the following vulnerable workflow that downloads artifacts unsafely:

```yaml
name: Deploy Application

on:
  workflow_run:
    workflows: ["Build"]
    types: [completed]

jobs:
  deploy:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      # VULNERABLE: No path specified, downloads to current directory
      - name: Download build artifacts
        uses: actions/download-artifact@v4
        with:
          name: application-bundle

      # DANGEROUS: Executes scripts from downloaded artifacts
      - name: Deploy to production
        run: |
          chmod +x ./deploy.sh
          ./deploy.sh
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
```

### Attack Scenario

**How Artifact Poisoning Works:**

1. **Attacker Creates Malicious PR**: Opens a pull request with seemingly innocent changes
2. **Build Workflow Runs**: CI workflow builds the PR and uploads artifacts
3. **Malicious Artifact Created**: Attacker includes a malicious `deploy.sh` in the artifact
4. **Deploy Workflow Triggered**: Downstream workflow downloads the artifact
5. **Files Overwritten**: Malicious `deploy.sh` overwrites the legitimate deployment script
6. **Code Execution**: Deploy workflow executes the malicious script with production credentials
7. **Compromise**: Attacker gains access to production environment and secrets

This attack is particularly dangerous because:
- The deploy workflow may run with write permissions or production access
- Artifacts appear to come from the same repository (trusted source)
- Traditional security scanners don't inspect artifact contents
- The malicious code executes in a privileged context

### Example Output

Running sisakulint will detect unsafe artifact downloads:

```bash
$ sisakulint

.github/workflows/deploy.yaml:12:9: artifact is downloaded without specifying a safe extraction path at step "Download build artifacts". This may allow artifact poisoning where malicious files overwrite existing files. Consider extracting to a temporary folder like '${{ runner.temp }}/artifacts' to prevent overwriting existing files. See https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-critical/ [artifact-poisoning]
     12 👈|      - name: Download build artifacts
```

### Auto-fix Support

The artifact-poisoning rule supports auto-fixing by adding safe extraction paths:

```bash
# Preview changes without applying
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

After auto-fix, artifacts are extracted to an isolated temporary directory:

```yaml
name: Deploy Application

on:
  workflow_run:
    workflows: ["Build"]
    types: [completed]

jobs:
  deploy:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      # SECURE: Artifacts isolated in temporary directory
      - name: Download build artifacts
        uses: actions/download-artifact@v4
        with:
          name: application-bundle
          path: ${{ runner.temp }}/artifacts

      # SECURE: Reference files from isolated location
      - name: Verify artifact contents
        run: |
          # Validate artifact integrity before use
          sha256sum -c ${{ runner.temp }}/artifacts/checksums.txt

      - name: Deploy to production
        run: |
          # Copy only verified files to workspace
          cp ${{ runner.temp }}/artifacts/app.tar.gz .
          tar -xzf app.tar.gz
          chmod +x ./deploy.sh
          ./deploy.sh
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
```

### Best Practices

#### 1. Always Specify Extraction Path

Use `runner.temp` to isolate artifacts from the workspace:

```yaml
- uses: actions/download-artifact@v4
  with:
    name: my-artifact
    path: ${{ runner.temp }}/artifacts  # Isolated directory
```

#### 2. Treat Artifacts as Untrusted

Never execute artifact contents directly. Always validate first:

```yaml
- name: Validate artifact
  run: |
    # Check file signatures
    gpg --verify ${{ runner.temp }}/artifacts/app.sig ${{ runner.temp }}/artifacts/app

    # Verify checksums
    sha256sum -c ${{ runner.temp }}/artifacts/checksums.txt

    # Scan for malicious content
    clamav-scan ${{ runner.temp }}/artifacts/
```

#### 3. Limit Artifact Scope

Minimize what artifacts can contain and where they're used:

```yaml
# Good: Specific artifact with limited scope
- uses: actions/download-artifact@v4
  with:
    name: test-results
    path: ${{ runner.temp }}/test-results

# Bad: Downloading all artifacts to workspace
- uses: actions/download-artifact@v4
  # No path specified - downloads all artifacts to current directory!
```

#### 4. Use Separate Workflows for Privileged Operations

Isolate workflows with production access from untrusted inputs:

```yaml
# Build workflow (runs on PR, untrusted)
name: Build
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run build
      - uses: actions/upload-artifact@v4
        with:
          name: build-output
          path: dist/

---

# Deploy workflow (runs on main only, trusted)
name: Deploy
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write  # For OIDC
    steps:
      - uses: actions/checkout@v4  # Get trusted code
      - run: npm run build  # Build from trusted source
      # Don't download artifacts from PRs
      - run: ./deploy.sh
```

#### 5. Implement Content Security Policies

Restrict what can be executed from downloaded artifacts:

```yaml
- name: Configure security policy
  run: |
    # Disable execution of downloaded files
    find ${{ runner.temp }}/artifacts -type f -exec chmod -x {} \;

- name: Selectively enable execution
  run: |
    # Only enable execution after validation
    if verify-signature ${{ runner.temp }}/artifacts/deploy.sh; then
      chmod +x ${{ runner.temp }}/artifacts/deploy.sh
    fi
```

### Real-World Attack Vectors

#### Attack Vector 1: Pull Request Poisoning

**Scenario**: Attacker creates PR with malicious artifact that gets executed in privileged workflow

```yaml
# Vulnerable: PR builds upload artifacts, deploy workflow downloads them
on:
  workflow_run:
    workflows: ["PR Build"]
    types: [completed]
```

**Mitigation**: Separate build and deploy, only deploy from trusted branches

#### Attack Vector 2: Dependency Chain Poisoning

**Scenario**: Compromised dependency uploads malicious artifacts during build

```yaml
# Vulnerable: Build process controlled by dependencies
steps:
  - run: npm install  # Compromised package
  - run: npm run build  # Malicious build script uploads poisoned artifact
```

**Mitigation**: Use dependency pinning, verify artifact integrity, scan for malware

#### Attack Vector 3: Cross-Workflow Contamination

**Scenario**: Multiple workflows share artifact namespace, attacker poisons shared artifact

```yaml
# Workflow A uploads "config" artifact
- uses: actions/upload-artifact@v4
  with:
    name: config

# Workflow B downloads "config" artifact (could be poisoned)
- uses: actions/download-artifact@v4
  with:
    name: config
```

**Mitigation**: Use unique artifact names with workflow/run IDs, validate sources

### Detection Scope

`actions/download-artifact` defaults to the artifacts uploaded earlier in the **current run**. It only
reaches into a different, potentially less-trusted run when the workflow itself has a privileged trigger
(`workflow_run`, `pull_request_target`, `issue_comment`, `issues`, `discussion_comment`,
`pull_request_review`, `workflow_call`) or the step explicitly sets `run-id`/`repository`. Without one of
those, every artifact in the run was uploaded by an equally-trusted sibling job (e.g. a matrix build
fanning into a packaging/publish job via `needs:`), so this rule does not fire — there is no untrusted
producer for the download to poison.

### Detection Patterns

The artifact-poisoning rule detects the following unsafe patterns, in jobs where the workflow can be
reached from one of the privileged triggers above:

1. **Missing path parameter**:
   ```yaml
   - uses: actions/download-artifact@v4
     with:
       name: my-artifact
       # Missing: path parameter
   ```

2. **Empty path parameter**:
   ```yaml
   - uses: actions/download-artifact@v4
     with:
       name: my-artifact
       path: ""  # Empty path
   ```

3. **Workspace path parameter**:
   ```yaml
   - uses: actions/download-artifact@v4
     with:
       name: my-artifact
       path: .  # Current directory - unsafe
   ```

### Safe Patterns

The rule recognizes these patterns as safe:

1. **Temporary directory isolation**:
   ```yaml
   - uses: actions/download-artifact@v4
     with:
       name: my-artifact
       path: ${{ runner.temp }}/artifacts
   ```

2. **Custom temporary path**:
   ```yaml
   - uses: actions/download-artifact@v4
     with:
       name: my-artifact
       path: ${{ runner.temp }}/my-safe-location
   ```

### Integration with GitHub Security Features

This rule complements GitHub's native security features:

- **CODEOWNERS**: Require review for workflow changes
- **Branch Protection**: Prevent direct pushes to protected branches
- **Required Status Checks**: Ensure sisakulint passes before merge
- **Deployment Protection Rules**: Require approval for production deployments
- **OpenID Connect (OIDC)**: Use short-lived tokens instead of long-lived secrets

### CodeQL Integration

This rule is inspired by CodeQL's artifact-poisoning query:
- [CodeQL Query: Artifact Poisoning (Critical)](https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-critical/)

sisakulint provides:
- Faster feedback during development
- Auto-fix capabilities
- Integration with CI/CD pipelines
- No GitHub Advanced Security license required

### OWASP CI/CD Security Alignment

This rule addresses multiple OWASP CI/CD Security Risks:

**CICD-SEC-4: Poisoned Pipeline Execution (PPE)**
- Prevents malicious artifacts from executing in privileged contexts
- Isolates untrusted content from execution environment

### Complementary Rules

Use these rules together for comprehensive protection:

1. **permissions rule**: Limit workflow permissions
   ```yaml
   permissions:
     contents: read  # Don't allow write access
   ```

2. **timeout-minutes rule**: Prevent resource exhaustion
   ```yaml
   timeout-minutes: 10  # Limit execution time
   ```

3. **issue-injection rule**: Prevent command injection from artifacts
   ```yaml
   # Use environment variables, not direct interpolation
   env:
     ARTIFACT_NAME: ${{ github.event.inputs.name }}
   ```

4. **commit-sha rule**: Pin actions to prevent supply chain attacks
   ```yaml
   - uses: actions/download-artifact@6b208ae046db98c579e8a3aa621ab581ff575935
   ```

### Configuration

To customize the artifact-poisoning rule behavior, configure `.github/action.yaml`:

```yaml
# Currently no configuration options available
# Rule always enforces safe artifact extraction paths
```

### Performance Considerations

This rule has minimal performance impact:
- **Detection**: O(n) where n is the number of steps
- **Auto-fix**: Modifies YAML structure in-place
- **No Network Calls**: Purely static analysis

### See Also

**Industry References:**
- [CodeQL: Artifact Poisoning (Critical)](https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-critical/) - CodeQL's artifact poisoning detection
- [GitHub: Security Hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions) - Official GitHub security guidance
- [OWASP: CICD-SEC-04 - Poisoned Pipeline Execution](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution) - PPE attack patterns
- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html) - Vulnerability classification
- [GitHub Docs: Storing Workflow Data as Artifacts](https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts) - Artifact usage guidelines

{{< popup_link2 href="https://codeql.github.com/codeql-query-help/actions/actions-artifact-poisoning-critical/" >}}

{{< popup_link2 href="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions" >}}

{{< popup_link2 href="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution" >}}

{{< popup_link2 href="https://cwe.mitre.org/data/definitions/829.html" >}}

{{< popup_link2 href="https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts" >}}
