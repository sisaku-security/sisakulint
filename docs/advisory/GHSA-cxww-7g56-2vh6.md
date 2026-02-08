# GHSA-cxww-7g56-2vh6

## Summary
| Field | Value |
|-------|-------|
| CVE | CVE-2024-42471 |
| Affected Action | actions/download-artifact |
| Severity | High |
| CVSS Score | 8.6/10 (CVSS:4.0) |
| Vulnerability Type | Path Traversal / Zip-Slip (CWE-22) |
| Published | 2024-08-12 |

## Vulnerability Description

The official `actions/download-artifact` action versions 4.0.0 to 4.1.2 contain an **Arbitrary File Write via Artifact Extraction** vulnerability (Zip Slip). When downloading and extracting a specially crafted artifact containing path traversal filenames, the action is vulnerable to arbitrary file write.

This is a "Zip Slip" vulnerability where malicious actors can exploit path traversal sequences in archived files to write files outside the intended extraction directory during artifact extraction. Malicious artifacts can contain files with paths like `../../../../etc/passwd` or `../../../.github/workflows/malicious.yml`, allowing attackers to write files outside the intended extraction directory.

**Impact:** Attackers with low-level privileges can remotely exploit this vulnerability over a network without user interaction, resulting in high confidentiality and integrity impacts on the vulnerable system.

This vulnerability enables attackers to:
- Overwrite critical files (workflows, scripts, configuration)
- Inject malicious code into the repository
- Escalate privileges by modifying workflow files
- Compromise the CI/CD pipeline

**Credits:** Justin Taft from Google

**Affected versions:** >= 4.0.0, < 4.1.3
**Patched versions:** 4.1.3 and higher (users can also use the 'v4' tag which points to the latest secure version)

## Vulnerable Pattern

```yaml
name: Vulnerable Pattern
on:
  pull_request:

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Vulnerable: v4.1.2 and earlier have zip-slip vulnerability
      # Malicious artifact can write to ../../../../.github/workflows/
      - uses: actions/download-artifact@v4.1.2
        with:
          name: build-output
          path: ./artifacts

      - name: Process artifacts
        run: |
          ls -R ./artifacts
          # If artifact contains ../../../.github/workflows/backdoor.yml
          # it overwrites workflow files with malicious code
```

**Why this is vulnerable:**
- No validation of file paths during extraction
- Attacker can craft artifact with `../` path traversal
- Can overwrite arbitrary files in workspace
- Particularly dangerous for overwriting workflow files

**Attack Scenario:**
1. Attacker creates malicious artifact with file: `../../../.github/workflows/backdoor.yml`
2. Uploads artifact in pull request build
3. Victim workflow downloads artifact with v4.1.2
4. Extraction writes `backdoor.yml` to workflow directory
5. Next workflow run executes attacker's code with secrets

## Safe Pattern

```yaml
name: Safe Pattern
on:
  pull_request:

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Safe: v4.1.8+ includes path validation and zip-slip protection
      - uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16 # v4.1.8
        with:
          name: build-output
          path: ./artifacts

      - name: Process artifacts
        run: |
          ls -R ./artifacts
          # Path traversal attempts are blocked
          # Files are extracted only within ./artifacts
```

**Why this is safe:**
- v4.1.8+ validates and normalizes all file paths
- Paths with `..` components are rejected
- Files are confined to extraction directory
- Protection against zip-slip and path traversal attacks

## sisakulint Detection Result

```
script/actions/advisory/GHSA-cxww-7g56-2vh6-vulnerable.yaml:20:9: artifact is downloaded to an unsafe path "./artifacts" at step "<unnamed>". Workspace-relative paths allow malicious artifacts to overwrite source code, scripts, or dependencies, creating a critical supply chain vulnerability. Extract to '${{ runner.temp }}/artifacts' instead. See https://sisaku-security.github.io/lint/docs/rules/artifactpoisoningcritical/ [artifact-poisoning-critical]
script/actions/advisory/GHSA-cxww-7g56-2vh6-vulnerable.yaml:20:9: Action 'actions/download-artifact@v4.1.2' has a known high severity vulnerability (GHSA-cxww-7g56-2vh6): @actions/download-artifact has an Arbitrary File Write via artifact extraction. Upgrade to version 4.1.3 or later. See: https://github.com/advisories/GHSA-cxww-7g56-2vh6 [known-vulnerable-actions]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | KnownVulnerableActionsRule | Yes |
| Yes | ArtifactPoisoningCriticalRule | Yes |

**Detection Details:**
- `KnownVulnerableActionsRule` successfully detects `actions/download-artifact@v4.1.2` with CVE-2024-42471
- `ArtifactPoisoningCriticalRule` detects unsafe extraction path `./artifacts` (workspace-relative)
- Provides specific remediation: Upgrade to version 4.1.3 or later
- Auto-fix available: Updates to patched version and safe extraction path

## Mitigation Recommendations

1. **Update immediately**: Upgrade to v4.1.8 or later (pin to commit SHA)
2. **Pin to safe SHA**: Use `actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16`
3. **Audit past runs**: Check if malicious artifacts were used in previous runs
4. **Review workspace**: Verify no unauthorized files were written
5. **Limit artifact trust**: Download artifacts only from trusted sources
6. **Add validation**: Verify artifact contents before processing
7. **Use protected branches**: Prevent workflow file modifications without review

## Technical Details

**Vulnerable Code Pattern:**
```python
# Vulnerable extraction (conceptual)
with zipfile.ZipFile(artifact_path) as zf:
    for member in zf.namelist():
        # No path validation - dangerous!
        zf.extract(member, destination)
```

**Safe Code Pattern:**
```python
# Safe extraction with validation
with zipfile.ZipFile(artifact_path) as zf:
    for member in zf.namelist():
        # Validate and normalize path
        target = os.path.normpath(os.path.join(destination, member))
        if not target.startswith(destination):
            raise SecurityError("Path traversal detected")
        zf.extract(member, destination)
```

## References
- [GitHub Advisory: GHSA-cxww-7g56-2vh6](https://github.com/advisories/GHSA-cxww-7g56-2vh6)
- [actions/download-artifact Security Advisory](https://github.com/actions/download-artifact/security/advisories/GHSA-cxww-7g56-2vh6)
- [Related Advisory GHSA-6q32-hq47-5qq3](https://github.com/advisories/GHSA-6q32-hq47-5qq3)
- [Fix Pull Request #299](https://github.com/actions/download-artifact/pull/299)
- [Release v4.1.3](https://github.com/actions/download-artifact/releases/tag/v4.1.3)
- [CVE-2024-42471](https://nvd.nist.gov/vuln/detail/CVE-2024-42471)
- [sisakulint: KnownVulnerableActionsRule](../known_vulnerable_actions.md)
- [sisakulint: ArtifactPoisoningCriticalRule](../artifactpoisoningcritical.md)
- [sisakulint: CommitShaRule](../commitsha.md)
- [OWASP: Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Zip Slip Vulnerability](https://security.snyk.io/research/zip-slip-vulnerability)
