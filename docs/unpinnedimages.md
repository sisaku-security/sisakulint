---
title: "Unpinned Images Rule"
weight: 1
---

### Unpinned Images Rule Overview

This rule detects **container images that are not pinned by SHA256 digest**. Using mutable tags like `latest` or version tags without digests poses supply chain risks as the image content can change without warning.

**Vulnerable Example:**

```yaml
name: Build
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    container: node:18  # DANGEROUS: Tag can be overwritten!
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test

  deploy:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:latest  # DANGEROUS: 'latest' is mutable!
```

**Detection Output:**

```bash
vulnerable.yaml:7:5: container image 'node:18' in container of job 'build' is using a tag without SHA256 digest. Tags are mutable and can be overwritten. Consider pinning with SHA256 digest (e.g., node:18@sha256:...). [unpinned-images]
      7 |    container: node:18

vulnerable.yaml:15:9: container image 'postgres:latest' in service postgres of job 'deploy' is using 'latest' tag or no tag, which is mutable and poses a supply chain risk. Pin the image using SHA256 digest (e.g., image:tag@sha256:...). [unpinned-images]
     15 |        image: postgres:latest
```

### Security Background

#### What is Image Pinning?

Container images can be referenced by:

| Reference Type | Example | Mutable? |
|----------------|---------|----------|
| Latest tag | `node:latest` | Yes |
| Version tag | `node:18` | Yes |
| SHA256 digest | `node@sha256:abc123...` | No |
| Tag + digest | `node:18@sha256:abc123...` | No |

Only SHA256 digests are truly immutable.

#### Why is this dangerous?

| Risk Factor | Impact |
|-------------|--------|
| **Tag Mutation** | Image content changes without version change |
| **Supply Chain Attack** | Attacker pushes malicious image to same tag |
| **Non-reproducible Builds** | Different runs use different images |
| **Silent Compromise** | No indication of image change |

#### Attack Scenario

```
1. Workflow uses node:18
2. Build succeeds with known-good image
3. Attacker compromises image registry or uses typosquatting
4. Attacker pushes malicious node:18 image
5. Next workflow run pulls malicious image
6. Malicious code executes in CI/CD pipeline
```

#### OWASP and CWE Mapping

- **CWE-829**: Inclusion of Functionality from Untrusted Control Sphere
- **CWE-494**: Download of Code Without Integrity Check
- **OWASP Top 10 CI/CD Security Risks:**
  - **CICD-SEC-3:** Dependency Chain Abuse

### Detection Logic

#### What Gets Detected

1. **Container images with 'latest' tag**
   ```yaml
   container: node:latest
   container: node  # Implicit latest
   ```

2. **Container images with version tag only**
   ```yaml
   container: node:18
   container: postgres:15.3
   ```

3. **Service images without digest**
   ```yaml
   services:
     redis:
       image: redis:7
   ```

#### Safe Patterns (NOT Detected)

Image with SHA256 digest:
```yaml
container: node:18@sha256:abc123def456...
```

Expression-based images (handled separately):
```yaml
container: ${{ inputs.image }}
```

### Remediation Steps

1. **Pin images by SHA256 digest**
   ```yaml
   container: node:18@sha256:a7c7e2dc8a4c4d2d7b5f7e4c6a8b0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4
   ```

2. **Find the digest for an image**
   ```bash
   # Using docker
   docker pull node:18
   docker inspect --format='{{index .RepoDigests 0}}' node:18

   # Using crane
   crane digest node:18

   # Using skopeo
   skopeo inspect docker://node:18 | jq -r '.Digest'
   ```

3. **Use digest in workflow**
   ```yaml
   container: node@sha256:abc123...
   # Or with tag for readability
   container: node:18@sha256:abc123...
   ```

### Best Practices

1. **Always use SHA256 digests**
   ```yaml
   container: node:18@sha256:abc123def456...
   services:
     postgres:
       image: postgres:15@sha256:def789abc012...
   ```

2. **Add comments for readability**
   ```yaml
   # node:18.19.0 (LTS)
   container: node@sha256:abc123def456...
   ```

3. **Use Dependabot for updates**
   ```yaml
   # .github/dependabot.yml
   version: 2
   updates:
     - package-ecosystem: "docker"
       directory: "/"
       schedule:
         interval: "weekly"
   ```

4. **Implement image scanning**
   - Use Trivy, Snyk, or similar tools
   - Scan images before use
   - Block vulnerable images

5. **Use trusted registries**
   - Prefer official images
   - Use verified publishers
   - Consider private registries with controlled content

### Finding Image Digests

#### Using Docker

```bash
# Pull and inspect
docker pull node:18
docker inspect node:18 --format='{{index .RepoDigests 0}}'
# Output: node@sha256:abc123...
```

#### Using crane (recommended)

```bash
# Install crane
go install github.com/google/go-containerregistry/cmd/crane@latest

# Get digest
crane digest node:18
# Output: sha256:abc123...
```

#### Using GitHub Container Registry

```bash
# For ghcr.io images
crane digest ghcr.io/owner/image:tag
```

### Example Migration

Before:
```yaml
jobs:
  test:
    container: node:18
    services:
      db:
        image: postgres:15
      cache:
        image: redis:7
```

After:
```yaml
jobs:
  test:
    # node:18.19.0 LTS
    container: node:18@sha256:a7c7e2dc8a4c4d2d7b5f7e4c6a8b0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4
    services:
      db:
        # postgres:15.5
        image: postgres:15@sha256:b8c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8
      cache:
        # redis:7.2.3
        image: redis:7@sha256:c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0
```

### References

- [Docker: Image digests](https://docs.docker.com/engine/reference/commandline/pull/#pull-an-image-by-digest-immutable-identifier)
- [GitHub: Container jobs](https://docs.github.com/en/actions/using-jobs/running-jobs-in-a-container)
- [Sigstore: Container signing](https://www.sigstore.dev/)
- [SLSA: Supply chain security](https://slsa.dev/)
