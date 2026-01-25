# Argument Injection Rule

## Overview

The `argument-injection-critical` and `argument-injection-medium` rules detect command-line argument injection vulnerabilities in GitHub Actions workflows. These vulnerabilities occur when untrusted user input is passed directly as command-line arguments to shell commands, allowing attackers to inject malicious options.

## Attack Vector

Attackers can craft malicious branch names, PR titles, or other user-controlled inputs that contain command-line options. For example:

```
Branch name: --output=/etc/passwd
PR title: -o /root/.ssh/authorized_keys
Issue body: --config=malicious.conf
```

When these values are used directly in shell commands without proper sanitization, the injected options are interpreted as legitimate command arguments:

```yaml
# Vulnerable: Attacker can inject options via branch name
- run: git diff ${{ github.event.pull_request.head.ref }}

# Attack payload: branch named "--output=/etc/passwd"
# Executed as: git diff --output=/etc/passwd
```

## Severity Levels

### Critical (`argument-injection-critical`)

Detects argument injection in **privileged workflow triggers**:
- `pull_request_target`
- `workflow_run`
- `issue_comment`
- `issues`
- `discussion_comment`

These triggers have write access to the repository and access to secrets, making exploitation more severe.

### Medium (`argument-injection-medium`)

Detects argument injection in **normal workflow triggers**:
- `pull_request`
- `push`
- `schedule`
- `workflow_dispatch`

These triggers have limited permissions, but argument injection can still lead to information disclosure or workflow manipulation.

## Dangerous Commands

The rule monitors the following commands known to be susceptible to argument injection:

| Category | Commands |
|----------|----------|
| **Version Control** | `git`, `gh` |
| **Network** | `curl`, `wget`, `rsync`, `scp`, `ssh` |
| **Archives** | `tar`, `zip`, `unzip` |
| **Package Managers** | `npm`, `yarn`, `pip`, `cargo` |
| **Languages** | `python`, `python3`, `node`, `ruby`, `perl`, `php`, `go` |
| **Containers** | `docker`, `kubectl`, `helm` |
| **Cloud CLIs** | `aws`, `az`, `gcloud` |
| **Build Tools** | `make`, `cmake`, `mvn`, `gradle`, `ant` |
| **Text Processing** | `jq`, `sed`, `awk`, `grep`, `find`, `xargs` |
| **Shell** | `bash`, `sh`, `zsh`, `pwsh`, `env` |

## Examples

### Vulnerable Patterns

```yaml
# VULNERABLE: git with untrusted branch ref
- run: git diff ${{ github.event.pull_request.head.ref }}
# Attack: branch named "--output=/etc/passwd" writes diff to /etc/passwd

# VULNERABLE: curl with untrusted URL component
- run: curl https://api.example.com/${{ github.event.pull_request.title }}
# Attack: title "--output /etc/passwd" writes response to /etc/passwd

# VULNERABLE: tar with untrusted extraction path
- run: tar -xf archive.tar -C ${{ github.event.pull_request.head.ref }}
# Attack: ref "--to-command=malicious_script" executes arbitrary commands

# VULNERABLE: npm with untrusted package name
- run: npm install ${{ github.event.issue.title }}
# Attack: title "--scripts-prepend-node-path=/tmp/evil" injects malicious scripts

# VULNERABLE: docker with untrusted tag
- run: docker run myimage:${{ github.event.pull_request.head.ref }}
# Attack: ref "--privileged" runs container with elevated privileges

# VULNERABLE: kubectl with untrusted namespace
- run: kubectl get pods -n ${{ github.event.pull_request.title }}
# Attack: title "--kubeconfig=/sensitive/path" reads arbitrary kubeconfig
```

### Safe Patterns

```yaml
# SAFE: Using end-of-options marker (--)
- run: git diff -- "$PR_REF"
  env:
    PR_REF: ${{ github.event.pull_request.head.ref }}
# The -- marker tells git that everything after it is a file path, not an option

# SAFE: Using environment variable with quotes
- run: git fetch origin "$HEAD_REF"
  env:
    HEAD_REF: ${{ github.head_ref }}
# Environment variables prevent expression expansion in shell

# SAFE: Input validation before use
- run: |
    if [[ "$NAMESPACE" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]]; then
      kubectl get pods -n "$NAMESPACE"
    else
      echo "Invalid namespace"
      exit 1
    fi
  env:
    NAMESPACE: ${{ github.event.pull_request.title }}
# Validate input format before using in commands

# SAFE: Using trusted inputs
- run: git checkout ${{ github.sha }}
# github.sha is a trusted input (commit hash), not user-controlled
```

## Auto-Fix

The rule provides automatic fixes that:

1. **Create environment variables** for untrusted inputs
2. **Add end-of-options marker (`--`)** before untrusted arguments
3. **Quote the environment variable** to prevent word splitting

### Before Auto-Fix

```yaml
- run: git diff ${{ github.event.pull_request.head.ref }}
```

### After Auto-Fix

```yaml
- run: git diff -- "$PR_REF"
  env:
    PR_REF: ${{ github.event.pull_request.head.ref }}
```

## Why End-of-Options (`--`) Matters

Most Unix commands support `--` as a delimiter that marks the end of command options:

```bash
# Without --: "-rf" is interpreted as options
rm -rf

# With --: "-rf" is treated as a filename
rm -- -rf
# This safely attempts to delete a file literally named "-rf"
```

Common commands supporting `--`:
- `git` - All subcommands
- `curl` - URL arguments
- `tar` - File arguments
- Most GNU/BSD utilities

## Untrusted Inputs

The following GitHub Actions contexts are considered untrusted:

| Context | Description |
|---------|-------------|
| `github.event.pull_request.title` | PR title |
| `github.event.pull_request.body` | PR body |
| `github.event.pull_request.head.ref` | PR source branch name |
| `github.event.pull_request.head.label` | PR source label |
| `github.event.issue.title` | Issue title |
| `github.event.issue.body` | Issue body |
| `github.event.comment.body` | Comment body |
| `github.event.review.body` | Review body |
| `github.event.head_commit.message` | Commit message |
| `github.event.commits.*.message` | Commit messages |
| `github.head_ref` | Head branch reference |

## Best Practices

1. **Always use environment variables** instead of inline expressions
2. **Add `--` marker** before arguments derived from user input
3. **Validate input format** with regular expressions when possible
4. **Use allowlists** for expected values (e.g., predefined branch names)
5. **Quote all variables** to prevent word splitting
6. **Avoid using user input** in security-sensitive commands when possible

## References

- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [Git Argument Injection](https://git-scm.com/docs/git#Documentation/git.txt---end-of-options)
- [Unix End-of-Options Convention](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap12.html)
