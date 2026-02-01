# Request Forgery Rule (SSRF Detection)

## Overview

The Request Forgery rule detects Server-Side Request Forgery (SSRF) vulnerabilities in GitHub Actions workflows. SSRF occurs when an attacker can influence a server to make requests to unintended locations, potentially accessing internal services, cloud metadata endpoints, or pivoting to internal networks.

## Rule Variants

- **request-forgery-critical**: Detects SSRF vulnerabilities in workflows with privileged triggers (`pull_request_target`, `workflow_run`, `issue_comment`)
- **request-forgery-medium**: Detects SSRF vulnerabilities in workflows with normal triggers (`pull_request`, `push`, `schedule`)

## What It Detects

### 1. Network Request Commands with Untrusted Input

The rule detects when untrusted user input is used in network request commands:

- Shell commands: `curl`, `wget`, `nc`/`netcat`
- PowerShell: `Invoke-WebRequest`, `Invoke-RestMethod`, `iwr`, `irm`
- JavaScript: `fetch()`, `axios`, `request`, `got`
- Python: `requests.get/post`, `urllib.urlopen`

### 2. Severity Levels Based on Input Position

| Severity | Position | Example | Risk |
|----------|----------|---------|------|
| High | Full URL | `curl ${{ input }}` | Attacker controls entire destination |
| High | Host/Domain | `curl https://${{ input }}/api` | Attacker controls target server |
| Medium | Path/Query | `curl https://api.example.com/${{ input }}` | Limited to specific server |

### 3. Cloud Metadata URL References

Direct references to cloud metadata service URLs are flagged:

- `169.254.169.254` - AWS/GCP/Azure metadata
- `metadata.google.internal` - GCP metadata
- `169.254.170.2` - AWS ECS metadata
- `100.100.100.200` - Alibaba Cloud metadata
- `192.0.0.192` - Oracle Cloud metadata

## Vulnerable Patterns

### Curl with Untrusted URL

```yaml
# Vulnerable: Full URL from user input
- name: Fetch data
  run: |
    curl "${{ github.event.issue.body }}"
```

### Wget with Untrusted Host

```yaml
# Vulnerable: Host from PR title
- name: Download
  run: |
    wget "https://${{ github.event.pull_request.title }}/data.json"
```

### GitHub Script with Fetch

```yaml
# Vulnerable: fetch() with untrusted URL
- uses: actions/github-script@v6
  with:
    script: |
      const response = await fetch('${{ github.event.comment.body }}');
```

## Safe Patterns

### 1. Use Environment Variables with Validation

```yaml
- name: Safe curl
  env:
    INPUT_URL: ${{ github.event.issue.body }}
  run: |
    # Validate URL against allowlist
    ALLOWED_DOMAINS="api.github.com api.example.com"
    DOMAIN=$(echo "$INPUT_URL" | sed -E 's|^https?://([^/]+).*|\1|')

    if echo "$ALLOWED_DOMAINS" | grep -qw "$DOMAIN"; then
      curl "$INPUT_URL"
    else
      echo "Domain not allowed: $DOMAIN"
      exit 1
    fi
```

### 2. Use Hardcoded Trusted URLs

```yaml
- name: Safe API call
  run: |
    # Only use trusted, hardcoded URLs
    curl "https://api.github.com/repos/${{ github.repository }}"
```

### 3. Use Octokit for GitHub API

```yaml
- uses: actions/github-script@v6
  with:
    script: |
      // Use octokit instead of raw fetch for GitHub API
      const { data } = await github.rest.issues.listForRepo({
        owner: context.repo.owner,
        repo: context.repo.repo
      });
```

### 4. Block Internal IP Ranges

```yaml
- name: Safe request with IP validation
  env:
    INPUT_URL: ${{ github.event.comment.body }}
  run: |
    # Block internal/metadata IPs
    BLOCKED="169.254. 127. 10. 192.168. 172.16. localhost metadata.google"

    for pattern in $BLOCKED; do
      if echo "$INPUT_URL" | grep -q "$pattern"; then
        echo "Blocked: Internal address detected"
        exit 1
      fi
    done

    curl "$INPUT_URL"
```

## Auto-Fix

The rule provides auto-fix that moves untrusted expressions to environment variables:

**Before:**
```yaml
- name: Vulnerable
  run: |
    curl "${{ github.event.issue.body }}"
```

**After:**
```yaml
- name: Vulnerable
  env:
    ISSUE_BODY: ${{ github.event.issue.body }}
  run: |
    curl "$ISSUE_BODY"
```

Note: The auto-fix moves the expression to an environment variable, which prevents shell injection. However, additional validation (URL allowlist, IP blocking) is still recommended to fully mitigate SSRF risks.

## Attack Scenarios

### 1. Cloud Metadata Access

An attacker provides `http://169.254.169.254/latest/meta-data/iam/security-credentials/` to access AWS instance credentials.

### 2. Internal Service Scanning

An attacker provides `http://internal-api.company.com/admin` to access internal services not exposed to the internet.

### 3. Port Scanning

An attacker uses SSRF to scan internal network ports: `http://192.168.1.1:22`, `http://192.168.1.1:3306`

### 4. DNS Rebinding

An attacker uses DNS rebinding to bypass IP-based allowlists and access internal services.

## References

- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [AWS IMDSv2 (Mitigates some SSRF)](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)

## Configuration

Errors from this rule can be suppressed with the `-ignore` flag:

```bash
sisakulint -ignore request-forgery-critical
sisakulint -ignore request-forgery-medium
```

If you have a legitimate use case for network requests with dynamic URLs, ensure proper validation:

1. Implement URL allowlist validation
2. Block internal IP ranges and metadata URLs
3. Use environment variables instead of direct expression interpolation
4. Consider using dedicated API clients (octokit, etc.) instead of raw HTTP requests
