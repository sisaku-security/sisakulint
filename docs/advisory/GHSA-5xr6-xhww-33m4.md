# GHSA-5xr6-xhww-33m4

## Summary
| Field | Value |
|-------|-------|
| CVE | N/A |
| Affected Action | dawidd6/action-download-artifact |
| Severity | High |
| CVSS Score | 8.7/10 (CVSS:4.0) |
| Vulnerability Type | Artifact Poisoning (CWE-349) |
| Published | 2024 |

## Vulnerability Description

This is an artifact poisoning vulnerability in `dawidd6/action-download-artifact` versions before v6. The action searches repository forks by default when finding artifacts, allowing unprivileged attackers to inject malicious artifacts into privileged workflows.

**Attack Scenario:**
- Repository `alice/foo` runs `build.yml` producing `build.exe`
- Repository `alice/foo` runs `publish.yml` using `action-download-artifact@v5` to retrieve latest `build.exe`
- Attacker forks `alice/foo` to `mallory/foo` and modifies `build.yml` to produce compromised `build.exe`
- Attacker repeatedly triggers their workflow to ensure malicious artifact is "latest"
- Alice's `publish.yml` retrieves the compromised artifact

The root cause is that "GitHub's artifact storage for workflows does not natively distinguish between artifacts created by a repository and artifacts created by forks."

This is particularly dangerous when the downloaded artifact contains executable code (scripts, binaries, etc.) that is executed with access to secrets or write permissions in `pull_request_target` or other privileged contexts.

**Affected versions:** All versions < 6 (v5 and earlier)
**Patched versions:** Version 6 and newer
**Mitigation for users unable to upgrade:** Set `allow_forks: false` explicitly to disable fork artifact searches.

## Vulnerable Pattern

```yaml
name: Vulnerable Pattern
on:
  pull_request_target:

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Vulnerable: allow_forks defaults to true
      # Attacker can upload malicious artifact from fork
      - uses: dawidd6/action-download-artifact@v5
        with:
          workflow: build.yml
          name: dist
          path: ./dist

      - name: Execute downloaded code
        run: |
          chmod +x ./dist/deploy.sh
          ./dist/deploy.sh
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
```

**Why this is vulnerable:**
- `allow_forks` defaults to `true` in v5 and earlier
- Attacker can create fork and upload malicious artifact
- Downloaded artifact executes with privileged context
- No validation of artifact source or integrity

**Attack Scenario:**
1. Attacker forks repository `victim/repo`
2. Attacker creates workflow that uploads malicious `dist` artifact
3. Attacker opens PR from `attacker/repo` to `victim/repo`
4. PR triggers `pull_request_target` workflow in `victim/repo`
5. `action-download-artifact` finds malicious artifact from `attacker/repo`
6. Malicious `deploy.sh` executes with `DEPLOY_TOKEN` secret

## Safe Pattern

```yaml
name: Safe Pattern
on:
  pull_request_target:

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Safe: Explicitly disable fork search
      - uses: dawidd6/action-download-artifact@v5
        with:
          workflow: build.yml
          name: dist
          path: ./dist
          allow_forks: false  # Prevent downloading from forks

      - name: Validate artifact integrity
        run: |
          # Verify checksums before execution
          sha256sum -c ./dist/checksums.txt

      - name: Execute downloaded code
        run: |
          chmod +x ./dist/deploy.sh
          ./dist/deploy.sh
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
```

**Why this is safe:**
- `allow_forks: false` prevents searching fork repositories
- Artifact integrity validation with checksums
- Only artifacts from trusted source are downloaded

## sisakulint Detection Result

```
script/actions/advisory/GHSA-5xr6-xhww-33m4-vulnerable.yaml:9:3: dangerous trigger (critical): workflow uses privileged trigger(s) [pull_request_target] without any security mitigations. These triggers grant write access and secrets access to potentially untrusted code. Add at least one mitigation: restrict permissions (permissions: read-all or permissions: {}), use environment protection, add label conditions, or check github.actor. See https://sisaku-security.github.io/lint/docs/rules/dangeroustriggersrulecritical/ [dangerous-triggers-critical]
script/actions/advisory/GHSA-5xr6-xhww-33m4-vulnerable.yaml:20:9: artifact poisoning risk: third-party action "dawidd6/action-download-artifact@v5" downloads artifacts in workflow with untrusted triggers (pull_request_target) without safe extraction path. This may allow malicious artifacts to overwrite existing files. Extract to '${{ runner.temp }}/artifacts' and validate content before use. See https://sisaku-security.github.io/lint/docs/rules/artifactpoisoningmedium/ [artifact-poisoning-medium]
script/actions/advisory/GHSA-5xr6-xhww-33m4-vulnerable.yaml:20:9: Action 'dawidd6/action-download-artifact@v5' has a known high severity vulnerability (GHSA-5xr6-xhww-33m4): Artifact poisoning vulnerability in action-download-artifact v5 and earlier. Upgrade to version 6 or later. See: https://github.com/advisories/GHSA-5xr6-xhww-33m4 [known-vulnerable-actions]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | KnownVulnerableActionsRule | Yes - Exact match |
| Yes | ArtifactPoisoningMediumRule | Yes |
| Yes | CommitShaRule | Yes (for version pinning) |

**Detection Details:**
- `KnownVulnerableActionsRule` **directly detects this specific vulnerability** (GHSA-5xr6-xhww-33m4) and warns about the vulnerable action version
- `ArtifactPoisoningMediumRule` detects third-party artifact download actions in untrusted triggers
- `CommitShaRule` detects use of mutable version tags
- `DangerousTriggersRuleCritical` detects unsafe use of privileged triggers
- Auto-fix available: Updates to safe version and adds validation steps

## Reason for Partial Detection

Static analysis limitations:
- Difficult to detect missing configuration options with default values
- Action-specific behavior (default `allow_forks: true`) requires action metadata
- Rule focuses on detecting third-party artifact downloads in general

**Improvement Opportunity:**
Add action-specific configuration checks to detect dangerous default values.

## Mitigation Recommendations

1. **Set `allow_forks: false`**: Explicitly disable fork search for all artifact downloads
2. **Validate artifact integrity**: Use checksums or signatures before execution
3. **Pin to commit SHA**: Use `dawidd6/action-download-artifact@<commit-sha>`
4. **Limit workflow permissions**: Restrict `GITHUB_TOKEN` permissions
5. **Use `workflow_run` carefully**: Download artifacts only from trusted workflow runs
6. **Consider official action**: Use `actions/download-artifact` for same-repository artifacts
7. **Add artifact validation step**: Verify artifact source and contents before use

## References
- [GitHub Advisory: GHSA-5xr6-xhww-33m4](https://github.com/advisories/GHSA-5xr6-xhww-33m4)
- [dawidd6 Security Advisory](https://github.com/dawidd6/action-download-artifact/security/advisories/GHSA-5xr6-xhww-33m4)
- [Patch Commit](https://github.com/dawidd6/action-download-artifact/commit/bf251b5aa9c2f7eeb574a96ee720e24f801b7c11)
- [sisakulint: ArtifactPoisoningMediumRule](../artifactpoisoningmedium.md)
- [sisakulint: KnownVulnerableActionsRule](../known_vulnerable_actions.md)
- [sisakulint: CommitShaRule](../commitsha.md)
- [GitHub: Artifact Poisoning](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)
