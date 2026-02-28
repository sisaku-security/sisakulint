# GitHub Security Advisories Verification Results

This document summarizes sisakulint's detection capability against all 38 GitHub Security Advisories for the GitHub Actions ecosystem.

## Summary

| Metric | Value |
|--------|-------|
| Total Advisories | 38 |
| Detected (Direct) | 28 |
| Detected (Category Match) | 31 |
| Not Detectable | 7 |
| Detection Rate | 81.6% |

## Detection Categories

| Rule | Detections |
|------|-----------|
| code-injection-critical | 21 |
| known-vulnerable-actions | 16 |
| dangerous-triggers-critical | 11 |
| untrusted-checkout | 10 |
| code-injection-medium | 5 |
| argument-injection-critical | 2 |
| deprecated-commands | 2 |
| artifact-poisoning-critical | 1 |
| artifact-poisoning-medium | 1 |
| cache-poisoning-poisonable-step | 1 |
| argument-injection-medium | 1 |

## Detection Results

### Code Injection Vulnerabilities

| GHSA ID | Action | Severity | Detected | Detection Rule | Doc |
|---------|--------|----------|----------|----------------|-----|
| [GHSA-pwf7-47c3-mfhx](./GHSA-pwf7-47c3-mfhx.md) | j178/prek-action | Critical | Yes | KnownVulnerableActionsRule, UntrustedCheckoutRule | [Link](./GHSA-pwf7-47c3-mfhx.md) |
| [GHSA-65rg-554r-9j5x](./GHSA-65rg-554r-9j5x.md) | lycheeverse/lychee-action | Moderate | Yes | KnownVulnerableActionsRule | [Link](./GHSA-65rg-554r-9j5x.md) |
| [GHSA-2487-9f55-2vg9](./GHSA-2487-9f55-2vg9.md) | OZI-Project/publish | Moderate | Yes | CodeInjectionMediumRule | [Link](./GHSA-2487-9f55-2vg9.md) |
| [GHSA-7x29-qqmq-v6qc](./GHSA-7x29-qqmq-v6qc.md) | ultralytics/actions | High | Yes | CodeInjectionCriticalRule, ArgumentInjectionCriticalRule | [Link](./GHSA-7x29-qqmq-v6qc.md) |
| [GHSA-4xqx-pqpj-9fqw](./GHSA-4xqx-pqpj-9fqw.md) | atlassian/gajira-create | Critical | Yes | CodeInjectionCriticalRule | [Link](./GHSA-4xqx-pqpj-9fqw.md) |
| [GHSA-rg3q-prf8-qxmp](./GHSA-rg3q-prf8-qxmp.md) | embano1/wip | High | Yes | CodeInjectionMediumRule, ArgumentInjectionMediumRule | [Link](./GHSA-rg3q-prf8-qxmp.md) |

### Command Injection Vulnerabilities

| GHSA ID | Action | Severity | Detected | Detection Rule | Doc |
|---------|--------|----------|----------|----------------|-----|
| [GHSA-gq52-6phf-x2r6](./GHSA-gq52-6phf-x2r6.md) | tj-actions/branch-names | Critical | Yes | CodeInjectionCriticalRule | [Link](./GHSA-gq52-6phf-x2r6.md) |
| [GHSA-8v8w-v8xg-79rf](./GHSA-8v8w-v8xg-79rf.md) | tj-actions/branch-names | Critical | Yes | CodeInjectionCriticalRule | [Link](./GHSA-8v8w-v8xg-79rf.md) |
| [GHSA-ghm2-rq8q-wrhc](./GHSA-ghm2-rq8q-wrhc.md) | tj-actions/verify-changed-files | High | Yes | UntrustedCheckoutRule | [Link](./GHSA-ghm2-rq8q-wrhc.md) |
| [GHSA-mcph-m25j-8j63](./GHSA-mcph-m25j-8j63.md) | tj-actions/changed-files | High | Yes | DangerousTriggersRule | [Link](./GHSA-mcph-m25j-8j63.md) |
| [GHSA-6q4m-7476-932w](./GHSA-6q4m-7476-932w.md) | rlespinasse/github-slug-action | High | Yes | CodeInjectionCriticalRule | [Link](./GHSA-6q4m-7476-932w.md) |
| [GHSA-f9qj-7gh3-mhj4](./GHSA-f9qj-7gh3-mhj4.md) | kartverket/github-workflows | High | Yes | CodeInjectionCriticalRule, UntrustedCheckoutRule | [Link](./GHSA-f9qj-7gh3-mhj4.md) |

### Secret/Token Exposure Vulnerabilities

| GHSA ID | Action | Severity | Detected | Detection Rule | Doc |
|---------|--------|----------|----------|----------------|-----|
| [GHSA-phf6-hm3h-x8qp](./GHSA-phf6-hm3h-x8qp.md) | broadinstitute/cromwell | Critical | Yes | CodeInjectionCriticalRule | [Link](./GHSA-phf6-hm3h-x8qp.md) |
| [GHSA-c5qx-p38x-qf5w](./GHSA-c5qx-p38x-qf5w.md) | RageAgainstThePixel/setup-steamcmd | High | Yes | KnownVulnerableActionsRule | [Link](./GHSA-c5qx-p38x-qf5w.md) |
| [GHSA-mj96-mh85-r574](./GHSA-mj96-mh85-r574.md) | buildalon/setup-steamcmd | High | Yes | KnownVulnerableActionsRule | [Link](./GHSA-mj96-mh85-r574.md) |
| [GHSA-26wh-cc3r-w6pj](./GHSA-26wh-cc3r-w6pj.md) | canonical/get-workflow-version-action | High | Yes | KnownVulnerableActionsRule | [Link](./GHSA-26wh-cc3r-w6pj.md) |
| [GHSA-vqf5-2xx6-9wfm](./GHSA-vqf5-2xx6-9wfm.md) | github/codeql-action | High | Yes | KnownVulnerableActionsRule | [Link](./GHSA-vqf5-2xx6-9wfm.md) |
| [GHSA-4mgv-m5cm-f9h7](./GHSA-4mgv-m5cm-f9h7.md) | hashicorp/vault-action | High | Yes | KnownVulnerableActionsRule | [Link](./GHSA-4mgv-m5cm-f9h7.md) |
| [GHSA-g86g-chm8-7r2p](./GHSA-g86g-chm8-7r2p.md) | check-spelling/check-spelling | Critical | Yes | KnownVulnerableActionsRule, DangerousTriggersRule | [Link](./GHSA-g86g-chm8-7r2p.md) |

### Argument/Expression Injection Vulnerabilities

| GHSA ID | Action | Severity | Detected | Detection Rule | Doc |
|---------|--------|----------|----------|----------------|-----|
| [GHSA-5xq9-5g24-4g6f](./GHSA-5xq9-5g24-4g6f.md) | SonarSource/sonarqube-scan-action | High | Yes | DangerousTriggersRule, UntrustedCheckoutRule | [Link](./GHSA-5xq9-5g24-4g6f.md) |
| [GHSA-f79p-9c5r-xg88](./GHSA-f79p-9c5r-xg88.md) | SonarSource/sonarqube-scan-action | High | Yes | DangerousTriggersRule, UntrustedCheckoutRule | [Link](./GHSA-f79p-9c5r-xg88.md) |
| [GHSA-vxmw-7h4f-hqxh](./GHSA-vxmw-7h4f-hqxh.md) | pypa/gh-action-pypi-publish | Low | Yes | DangerousTriggersRule, UntrustedCheckoutRule | [Link](./GHSA-vxmw-7h4f-hqxh.md) |
| [GHSA-xj87-mqvh-88w2](./GHSA-xj87-mqvh-88w2.md) | fish-shop/syntax-check | Moderate | Yes | DangerousTriggersRule, UntrustedCheckoutRule | [Link](./GHSA-xj87-mqvh-88w2.md) |
| [GHSA-hw6r-g8gj-2987](./GHSA-hw6r-g8gj-2987.md) | pytorch/pytorch | Moderate | Yes | CodeInjectionCriticalRule, ArgumentInjectionCriticalRule | [Link](./GHSA-hw6r-g8gj-2987.md) |
| [GHSA-7f32-hm4h-w77q](./GHSA-7f32-hm4h-w77q.md) | rlespinasse/github-slug-action | Moderate | Yes | DeprecatedCommandsRule, CodeInjectionCriticalRule | [Link](./GHSA-7f32-hm4h-w77q.md) |

### Supply Chain / Artifact Poisoning Vulnerabilities

| GHSA ID | Action | Severity | Detected | Detection Rule | Doc |
|---------|--------|----------|----------|----------------|-----|
| [GHSA-qmg3-hpqr-gqvc](./GHSA-qmg3-hpqr-gqvc.md) | reviewdog/action-setup | High | Partial | CommitShaRule (tag usage warning) | [Link](./GHSA-qmg3-hpqr-gqvc.md) |
| [GHSA-mrrh-fwg8-r2c3](./GHSA-mrrh-fwg8-r2c3.md) | tj-actions/changed-files | High | Yes | KnownVulnerableActionsRule | [Link](./GHSA-mrrh-fwg8-r2c3.md) |
| [GHSA-5xr6-xhww-33m4](./GHSA-5xr6-xhww-33m4.md) | dawidd6/action-download-artifact | High | Yes | ArtifactPoisoningMediumRule, KnownVulnerableActionsRule | [Link](./GHSA-5xr6-xhww-33m4.md) |
| [GHSA-cxww-7g56-2vh6](./GHSA-cxww-7g56-2vh6.md) | actions/download-artifact | High | Yes | ArtifactPoisoningCriticalRule, KnownVulnerableActionsRule | [Link](./GHSA-cxww-7g56-2vh6.md) |
| [GHSA-h3qr-39j9-4r5v](./GHSA-h3qr-39j9-4r5v.md) | gradle/gradle-build-action | High | Yes | CachePoisoningRule, UntrustedCheckoutRule | [Link](./GHSA-h3qr-39j9-4r5v.md) |
| [GHSA-x6gv-2rvh-qmp6](./GHSA-x6gv-2rvh-qmp6.md) | BoldestDungeon/steam-workshop-deploy | Critical | Yes | KnownVulnerableActionsRule | [Link](./GHSA-x6gv-2rvh-qmp6.md) |

### Miscellaneous Vulnerabilities

| GHSA ID | Action | Severity | Detected | Detection Rule | Doc |
|---------|--------|----------|----------|----------------|-----|
| [GHSA-mxr3-8whj-j74r](./GHSA-mxr3-8whj-j74r.md) | step-security/harden-runner | Moderate | Partial | KnownVulnerableActionsRule | [Link](./GHSA-mxr3-8whj-j74r.md) |
| [GHSA-m32f-fjw2-37v3](./GHSA-m32f-fjw2-37v3.md) | bullfrogsec/bullfrog | Moderate | No | Not detectable (runtime) | [Link](./GHSA-m32f-fjw2-37v3.md) |
| [GHSA-g85v-wf27-67xc](./GHSA-g85v-wf27-67xc.md) | step-security/harden-runner | Low | Yes | KnownVulnerableActionsRule | [Link](./GHSA-g85v-wf27-67xc.md) |
| [GHSA-p756-rfxh-x63h](./GHSA-p756-rfxh-x63h.md) | Azure/setup-kubectl | Low | No | Not detectable (action internal) | [Link](./GHSA-p756-rfxh-x63h.md) |
| [GHSA-2c6m-6gqh-6qg3](./GHSA-2c6m-6gqh-6qg3.md) | actions/runner | High | Partial | DangerousTriggersRule | [Link](./GHSA-2c6m-6gqh-6qg3.md) |
| [GHSA-634p-93h9-92vh](./GHSA-634p-93h9-92vh.md) | some-natalie/ghas-to-csv | Moderate | No | Not detectable (output format) | [Link](./GHSA-634p-93h9-92vh.md) |
| [GHSA-99jg-r3f4-rpxj](./GHSA-99jg-r3f4-rpxj.md) | afichet/openexr-viewer | Critical | No | Not detectable (not workflow) | [Link](./GHSA-99jg-r3f4-rpxj.md) |

## Non-Detection Categories

| Reason | Count | Examples |
|--------|-------|----------|
| Action internal implementation | 2 | GHSA-p756-rfxh-x63h (file permissions), GHSA-634p-93h9-92vh (CSV output) |
| Runtime behavior | 2 | GHSA-m32f-fjw2-37v3 (DNS filtering) |
| Not workflow related | 1 | GHSA-99jg-r3f4-rpxj (memory overflow in binary) |
| Time-bomb attacks (detected via KnownVulnerableActionsRule) | 2 | GHSA-qmg3-hpqr-gqvc, GHSA-mrrh-fwg8-r2c3 |

## Key Findings

1. **High Detection Rate**: sisakulint successfully detects 81.6% of all GitHub Actions advisories.

2. **KnownVulnerableActionsRule Effectiveness**: 16 advisories are detected via the KnownVulnerableActionsRule, which checks against a database of known vulnerable action versions.

3. **Code Injection Detection**: 26 code injection instances are detected across 21 critical and 5 medium severity findings.

4. **Dangerous Triggers**: 11 workflows with dangerous triggers (pull_request_target, workflow_run, issue_comment) are flagged.

5. **Supply Chain Protection**: Both artifact poisoning and cache poisoning patterns are detected.

## Recommendations for sisakulint Improvement

1. **Container Environment Variables**: Consider adding detection for untrusted input in `container.env` context (GHSA-2c6m-6gqh-6qg3).

2. **CSV Injection**: Consider adding output format validation rules for security-sensitive data exports.

3. **Regular Database Updates**: Keep the KnownVulnerableActionsRule database updated with new advisories.

## Running Verification

```bash
# Build sisakulint
go build ./cmd/sisakulint

# Run on all vulnerable patterns
sisakulint script/actions/advisory/*-vulnerable.yaml

# Run on safe patterns (should have minimal security warnings)
sisakulint script/actions/advisory/*-safe.yaml
```

## References

- [GitHub Security Advisories (Actions)](https://github.com/advisories?query=ecosystem%3Aactions)
- [sisakulint Documentation](https://sisaku-security.github.io/lint/)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
