# GitHub Security Advisories Verification Design

## Overview

Verify sisakulint's detection capability against all 38 GitHub Security Advisories for the GitHub Actions ecosystem. Document detection results and create sample workflow files for each advisory.

## Scope

- **Total Advisories**: 38
- **Verification Criteria**: Category-based matching (not exact rule matching)
- **Output**: Sample files + individual documentation for each advisory

## Directory Structure

```
script/actions/advisory/
├── GHSA-pwf7-47c3-mfhx-vulnerable.yaml
├── GHSA-pwf7-47c3-mfhx-safe.yaml
├── GHSA-5xq9-5g24-4g6f-vulnerable.yaml
├── GHSA-5xq9-5g24-4g6f-safe.yaml
... (38 advisories x 2 = 76 files)

docs/advisory/
├── README.md                    # Summary matrix
├── GHSA-pwf7-47c3-mfhx.md       # Individual analysis
├── GHSA-5xq9-5g24-4g6f.md
... (38 files)
```

## Individual Documentation Format

Each `docs/advisory/GHSA-xxx.md` file:

```markdown
# GHSA-xxxx-xxxx-xxxx

## Summary
| Field | Value |
|-------|-------|
| CVE | CVE-2025-xxxxx |
| Affected Action | owner/action-name |
| Severity | Critical/High/Moderate/Low |
| Vulnerability Type | Code Injection |
| Published | YYYY-MM-DD |

## Vulnerability Description
[Summary of the advisory]

## Vulnerable Pattern
[Code example and explanation]

## sisakulint Detection Result
| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes/No | RuleName | Yes/No |

## Reason for Non-Detection (if applicable)
[Static analysis limitations, action-specific issues, etc.]

## References
- [GitHub Advisory](https://github.com/advisories/GHSA-xxx)
- [sisakulint: RuleName](../rulename.md)
```

## Sample YAML File Format

Each `script/actions/advisory/GHSA-xxx-vulnerable.yaml`:

```yaml
# GHSA-xxxx-xxxx-xxxx: [Title]
# Advisory: https://github.com/advisories/GHSA-xxxx-xxxx-xxxx
# Affected Action: owner/action-name
# Vulnerability Type: Code Injection
# Expected Detection Rule: CodeInjectionCriticalRule

name: GHSA-xxxx-xxxx-xxxx Vulnerable Pattern
on:
  pull_request_target:

jobs:
  vulnerable:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
```

## Summary Matrix Format (docs/advisory/README.md)

```markdown
# GitHub Security Advisories Verification Results

## Summary
| Metric | Value |
|--------|-------|
| Total Advisories | 38 |
| Detected | XX |
| Category Match | XX |
| Not Detectable | XX |
| Detection Rate | XX% |

## Detection Results

| GHSA ID | Affected Action | Vulnerability Type | Severity | Detected | Rule |
|---------|-----------------|-------------------|----------|----------|------|
| [GHSA-xxx](./GHSA-xxx.md) | owner/action | Code Injection | Critical | Yes | CodeInjectionCriticalRule |
...

## Non-Detection Categories

| Reason | Count | Examples |
|--------|-------|----------|
| Action internal implementation | X | Memory overflow |
| Time-bomb attacks | X | Supply chain compromise |
| Requires dynamic analysis | X | Runtime behavior |
```

## Implementation Phases

### Phase 1: Advisory Information Collection (Updated 2026-02-08)

**Deep Link Resolution Strategy:**
For each advisory, resolve internal links to depth 2:

```
1. Main advisory page (github.com/advisories/GHSA-xxx)
   ↓
2. Extract links from description:
   - Repository security advisory (/owner/repo/security/advisories/GHSA-xxx)
   - Patch commit (/owner/repo/commit/xxx)
   - Related issue/PR (if present)
   ↓
3. WebFetch each internal link
   ↓
4. Integrate into documentation
```

**Information Collection Priority:**
| Priority | Link Type | Content to Collect |
|----------|-----------|-------------------|
| Required | Patch commit | Changed files, fix summary |
| Required | Security advisory detail | Detailed description, impact, reproduction steps |
| Optional | Issue/PR | Report context, discussion points (brief) |

### Phase 2: Sample File Creation
- Reproduce vulnerable patterns for each advisory
- Create corresponding safe patterns
- Use parallel subagents for efficiency

### Phase 3: Verification Execution
- Run `sisakulint script/actions/advisory/`
- Record detection results for each file

### Phase 4: Documentation Creation
- Create 38 individual documentation files (in English)
- Create summary matrix
- Analyze detection rate and improvement areas

### Phase 5: Document Enhancement (Added 2026-02-08)

**Sections to Update:**
```markdown
## Vulnerability Description
[Before: advisory page summary only]
→ [After: integrated security advisory detail + patch commit content]

## Vulnerable Pattern
[Before: inference-based pattern]
→ [After: accurate pattern based on actual patch commit]

## References
[Before: main advisory link only]
→ [After: all internal links included]
```

## Expected Deliverables

- Sample files: 76 files
- Documentation: 39 files (including README)
- Verification runs: 38 times

## Success Criteria

- Category-based detection matching
- Complete documentation for all 38 advisories
- Clear identification of detection gaps
