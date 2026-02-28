# GHSA-99jg-r3f4-rpxj

## Summary
| Field | Value |
|-------|-------|
| CVE | CVE-2023-50245 |
| Affected Action | afichet/openexr-viewer |
| Severity | Critical (CVSS 9.8) |
| Vulnerability Type | Classic Buffer Overflow (CWE-120) |
| Published | December 10, 2023 |

## Vulnerability Description

This advisory describes a memory overflow (classic buffer overflow) vulnerability in the OpenEXR-viewer application triggered when opening malicious EXR image files. The vulnerability exists in the C++ code that parses OpenEXR image file headers, where insufficient bounds checking can lead to heap buffer overflows when processing maliciously crafted image files.

**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
- Attack Vector: Network (AV:N) - Can be exploited remotely
- Attack Complexity: Low (AC:L) - No special conditions required
- Privileges Required: None (PR:N) - No authentication needed
- User Interaction: None (UI:N) - Automatic exploitation possible
- Confidentiality Impact: High (C:H)
- Integrity Impact: High (I:H)
- Availability Impact: High (A:H)

**Affected Versions:** All versions < 0.6.1

**Patched Version:** 0.6.1

**Important: This is NOT a GitHub Actions workflow security vulnerability.** This is a traditional software vulnerability in an image parsing library. It affects applications that use the OpenEXR library to process image files, regardless of whether they run in GitHub Actions or elsewhere.

**Technical Details:**

Two proof-of-concept files demonstrated write attempts to invalid memory addresses:

**POC 1:**
- Access violation attempting to write to address: `0x29CB371600C`
- Instruction: `mov dword ptr [rax+rcx*4+0Ch],3F800000h`

**POC 2:**
- Access violation attempting to write to address: `0x20A3AC8000C`
- Same instruction pattern attempting to write float value 1.0 (`3F800000h`)

The vulnerability occurs at offset `openexr_viewer+0x27be4`, indicating a buffer copy operation that doesn't validate input size against the destination buffer capacity.

The vulnerability could allow an attacker who can provide a malicious OpenEXR file to:
1. Cause application crashes (denial of service) - "Access violation - code c0000005"
2. Potentially achieve arbitrary code execution
3. Read or write memory outside allocated buffers

**Credits:**
Discovered by Team ZeroPointer members:
- Lee Dong Ha (GAP-dev)
- Jeong Jimin
- Park Woojin
- Jeon Woojin

## Vulnerable Pattern

There is **no vulnerable workflow pattern** because this is not a workflow security issue. The vulnerability is in the software that processes OpenEXR files, not in how GitHub Actions workflows are configured.

```yaml
# This workflow does not demonstrate a workflow vulnerability
# The vulnerability is in the openexr-viewer application itself
- name: Process image file
  run: openexr-viewer malicious.exr  # The app may crash or be exploited
```

## sisakulint Detection Result

```
(No workflow-specific vulnerabilities detected - this is not a workflow security issue)
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| No | N/A | No |

## Reason for Non-Detection

This vulnerability **cannot and should not be detected** by workflow static analysis because:

1. **Not a workflow vulnerability**: This is a traditional software vulnerability (buffer overflow in C++ code), not a CI/CD security issue
2. **Wrong domain**: sisakulint analyzes workflow configurations, not the internal implementation of applications that run in workflows
3. **Binary-level issue**: Buffer overflows occur at the binary/memory level, completely outside the scope of YAML workflow analysis
4. **Incorrect categorization**: This advisory should not have been included in the GitHub Actions workflow security assessment

**Detection category**: Not workflow-related

## Why This Advisory is Irrelevant

This advisory was likely incorrectly associated with GitHub Actions workflow security because:

1. The affected repository (`afichet/openexr-viewer`) might have GitHub Actions workflows
2. The vulnerability affects software that *could* be used in workflows
3. However, the vulnerability is in the software itself, not in how it's used in workflows

**Analogy**: If a compiler has a bug, that doesn't make it a "workflow vulnerability" just because the compiler is invoked in a CI/CD workflow.

## Actual Mitigation

Since this is not a workflow security issue, the mitigation is:

1. **Update the software**: Use version 0.6.1 or later of OpenEXR-viewer that fixes the buffer overflow
2. **Input validation**: Don't process untrusted OpenEXR files
3. **Sandboxing**: Run image processing in isolated environments
4. **Security scanning**: Use tools like AddressSanitizer (ASan) to detect memory errors

**No workflow changes are needed** because the workflow itself is not vulnerable - only the application it runs is vulnerable.

**No workarounds available**: Users should upgrade to version 0.6.1 immediately.

## Technical Fix Details

**Version 0.6.1 Changes:**

**Files Modified:**
- `src/model/framebuffer/FramebufferModel.cpp` - Core framebuffer logic
- `src/model/framebuffer/FramebufferModel.h` - Header definitions
- `src/model/framebuffer/RGBFramebufferModel.cpp` - RGB framebuffer implementation
- `src/model/framebuffer/YFramebufferModel.cpp` - Y channel framebuffer implementation

**Root Cause:**
Width and height values are stored as 32-bit integers in OpenEXR. When multiplied together to allocate memory for 2D images, these calculations could overflow the integer type, particularly for RGBA images requiring 4 times the memory.

**The Fix Implemented Two Solutions:**

1. **Integer Overflow Detection:**
   - Added validation checks before memory allocation:
     - For Y (single channel) framebuffers: checks if `width * height > 0x7FFFFFFF`
     - For RGB(A) (4 channel) framebuffers: checks if `width * height > 0x1FFFFFFF`
   - Uses `uint64_t` for intermediate calculations to prevent overflow during the check itself
   - Throws `std::runtime_error` with message "The total image size is too large" if limits exceeded

2. **Memory Management Modernization:**
   - Replaced raw pointer allocations (`new float[]`) with `std::vector<float>`
   - Eliminated manual memory deallocation (`delete[]`) throughout the codebase
   - Removed the destructor from `FramebufferModel` as it's no longer needed
   - Updated buffer access to use `.data()` method when interfacing with OpenEXR API

**Before (Vulnerable):**
```cpp
// No overflow checking
float* buffer = new float[width * height];  // Could overflow
```

**After (Fixed):**
```cpp
// Overflow detection
if (static_cast<uint64_t>(width) * height > 0x7FFFFFFF) {
    throw std::runtime_error("The total image size is too large");
}
std::vector<float> buffer(width * height);  // Safe allocation with RAII
```

The changes prevent potential crashes or exploits from oversized images while improving memory safety through RAII (Resource Acquisition Is Initialization) principles.

## Lesson for Advisory Categorization

This advisory demonstrates the importance of distinguishing between:

1. **Workflow security vulnerabilities**: Issues in how workflows are configured (code injection, permission escalation, etc.)
2. **Action implementation vulnerabilities**: Issues in the code of GitHub Actions themselves
3. **Application vulnerabilities**: Issues in applications that happen to run in workflows (like this one)

Only categories 1 and 2 are relevant for workflow static analysis tools like sisakulint.

## References
- [GitHub Advisory: GHSA-99jg-r3f4-rpxj](https://github.com/advisories/GHSA-99jg-r3f4-rpxj)
- [afichet/openexr-viewer Security Advisory](https://github.com/afichet/openexr-viewer/security/advisories/GHSA-99jg-r3f4-rpxj)
- [Fix Commit](https://github.com/afichet/openexr-viewer/commit/d0a7e85dfeb519951fb8a8d70f73f30d41cdd3d9)
- [afichet/openexr-viewer Repository](https://github.com/afichet/openexr-viewer)
- [NVD: CVE-2023-50245](https://nvd.nist.gov/vuln/detail/CVE-2023-50245)
- [OpenEXR Project](https://www.openexr.com/)

**Note**: This advisory should be excluded from GitHub Actions workflow security verification efforts as it's not applicable to workflow security analysis.
