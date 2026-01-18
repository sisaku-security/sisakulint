package core

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	"github.com/google/go-github/v68/github"
	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// VulnerabilityInfo holds information about a detected vulnerability
type VulnerabilityInfo struct {
	GHSAID              string
	Severity            string
	Summary             string
	FirstPatchedVersion string
	VulnerableRange     string
	HTMLURL             string
}

// KnownVulnerableActionsRule detects actions with known security vulnerabilities
type KnownVulnerableActionsRule struct {
	BaseRule
	client        *github.Client
	clientOnce    sync.Once
	advisoryCache map[string][]*VulnerabilityInfo
	cacheMu       sync.RWMutex
}

// NewKnownVulnerableActionsRule creates a new instance of KnownVulnerableActionsRule
func NewKnownVulnerableActionsRule() *KnownVulnerableActionsRule {
	return &KnownVulnerableActionsRule{
		BaseRule: BaseRule{
			RuleName: "known-vulnerable-actions",
			RuleDesc: "Detects GitHub Actions with known security vulnerabilities using GitHub Security Advisories database.",
		},
		advisoryCache: make(map[string][]*VulnerabilityInfo),
	}
}

// getGitHubToken retrieves authentication token using a fallback chain
// Priority: environment variable → gh CLI → git credential
func getGitHubToken() string {
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		return token
	}
	if token := os.Getenv("GH_TOKEN"); token != "" {
		return token
	}
	if token, err := getTokenFromGhCLI(); err == nil && token != "" {
		return token
	}
	if token, err := getTokenFromGitCredential(); err == nil && token != "" {
		return token
	}
	return ""
}

func getTokenFromGhCLI() (string, error) {
	cmd := exec.CommandContext(context.Background(), "gh", "auth", "token")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func getTokenFromGitCredential() (string, error) {
	cmd := exec.CommandContext(context.Background(), "git", "credential", "fill")
	cmd.Stdin = strings.NewReader("protocol=https\nhost=github.com\n")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "password=") {
			return strings.TrimPrefix(line, "password="), nil
		}
	}
	return "", fmt.Errorf("credential not found")
}

// tokenTransport is a Transport that adds token to GitHub API requests
type tokenTransport struct {
	token string
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clonedReq := req.Clone(req.Context())
	clonedReq.Header.Set("Authorization", "Bearer "+t.token)
	return http.DefaultTransport.RoundTrip(clonedReq)
}

// getClient initializes the GitHub client with authentication
func (rule *KnownVulnerableActionsRule) getClient() *github.Client {
	rule.clientOnce.Do(func() {
		var httpClient *http.Client
		if token := getGitHubToken(); token != "" {
			httpClient = &http.Client{
				Transport: &tokenTransport{token: token},
			}
		}
		rule.client = github.NewClient(httpClient)
	})
	return rule.client
}

// parseActionRef parses an action reference like "owner/repo@ref" or "owner/repo/path@ref"
func parseActionRef(usesValue string) (owner, repo, ref string, ok bool) {
	atIdx := strings.LastIndex(usesValue, "@")
	if atIdx == -1 {
		return "", "", "", false
	}
	ref = usesValue[atIdx+1:]
	ownerRepoPath := usesValue[:atIdx]

	parts := strings.Split(ownerRepoPath, "/")
	if len(parts) < 2 {
		return "", "", "", false
	}
	owner = parts[0]
	repo = parts[1]
	return owner, repo, ref, true
}

// isLocalAction checks if the action is a local action (starts with ./)
func isLocalAction(usesValue string) bool {
	return strings.HasPrefix(usesValue, "./")
}

// isDockerAction checks if the action is a Docker action (docker:// prefix)
func isDockerAction(usesValue string) bool {
	return strings.HasPrefix(usesValue, "docker://")
}

// isFullLengthCommitSHA checks if the ref is a full-length commit SHA
func isFullLengthCommitSHA(ref string) bool {
	matched, _ := regexp.MatchString(`^[0-9a-f]{40}$`, ref)
	return matched
}

// resolveTagFromCommitSHA resolves a commit SHA to the best matching tag
func (rule *KnownVulnerableActionsRule) resolveTagFromCommitSHA(ctx context.Context, owner, repo, sha string) (string, error) {
	gh := rule.getClient()
	opts := &github.ListOptions{
		PerPage: 100,
	}

	var bestTag string
	for i := 0; i < 10; i++ {
		tags, resp, err := gh.Repositories.ListTags(ctx, owner, repo, opts)
		if err != nil {
			return "", fmt.Errorf("failed to list tags: %w", err)
		}

		for _, tag := range tags {
			if tag.GetCommit().GetSHA() == sha {
				tagName := tag.GetName()
				// Prefer longer version tags (e.g., v1.2.3 over v1)
				if len(tagName) > len(bestTag) {
					bestTag = tagName
				}
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return bestTag, nil
}

// resolveSymbolicRef resolves a symbolic reference (tag/branch) to a commit SHA
func (rule *KnownVulnerableActionsRule) resolveSymbolicRef(ctx context.Context, owner, repo, ref string) (sha string, err error) {
	gh := rule.getClient()
	commit, _, err := gh.Repositories.GetCommitSHA1(ctx, owner, repo, ref, "")
	if err != nil {
		return "", fmt.Errorf("failed to resolve ref %s: %w", ref, err)
	}
	return commit, nil
}

// getVersionFromRef extracts version information from the action reference
// For symbolic refs: resolves to commit SHA, then finds the longest matching tag
// For commit SHAs: finds the longest matching tag
func (rule *KnownVulnerableActionsRule) getVersionFromRef(ctx context.Context, owner, repo, ref string) (string, error) {
	var sha string
	var err error

	if isFullLengthCommitSHA(ref) {
		sha = ref
	} else {
		sha, err = rule.resolveSymbolicRef(ctx, owner, repo, ref)
		if err != nil {
			// If we can't resolve the ref, use it directly (it might be a valid version tag)
			return ref, nil
		}
	}

	// Find the longest matching tag for this commit
	tag, err := rule.resolveTagFromCommitSHA(ctx, owner, repo, sha)
	if err != nil {
		return "", err
	}

	if tag == "" {
		// No tag found, use the original ref
		return ref, nil
	}

	return tag, nil
}

// fetchAdvisories fetches security advisories for a specific action
func (rule *KnownVulnerableActionsRule) fetchAdvisories(ctx context.Context, owner, repo, version string) ([]*VulnerabilityInfo, error) {
	packageName := fmt.Sprintf("%s/%s", owner, repo)

	// Check cache first
	rule.cacheMu.RLock()
	cached, ok := rule.advisoryCache[packageName]
	rule.cacheMu.RUnlock()
	if ok {
		return rule.filterVulnerableVersions(cached, version), nil
	}

	gh := rule.getClient()
	ecosystem := "actions"
	opts := &github.ListGlobalSecurityAdvisoriesOptions{
		Ecosystem: &ecosystem,
		Affects:   &packageName,
	}

	advisories, _, err := gh.SecurityAdvisories.ListGlobalSecurityAdvisories(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch security advisories: %w", err)
	}

	var vulns []*VulnerabilityInfo
	for _, advisory := range advisories {
		for _, vuln := range advisory.Vulnerabilities {
			if vuln.Package == nil || vuln.Package.Name == nil {
				continue
			}
			if *vuln.Package.Name != packageName {
				continue
			}

			info := &VulnerabilityInfo{
				GHSAID:          advisory.GetGHSAID(),
				Severity:        advisory.GetSeverity(),
				Summary:         advisory.GetSummary(),
				VulnerableRange: vuln.GetVulnerableVersionRange(),
				HTMLURL:         fmt.Sprintf("https://github.com/advisories/%s", advisory.GetGHSAID()),
			}
			if vuln.FirstPatchedVersion != nil {
				info.FirstPatchedVersion = *vuln.FirstPatchedVersion
			}
			vulns = append(vulns, info)
		}
	}

	// Cache the results
	rule.cacheMu.Lock()
	rule.advisoryCache[packageName] = vulns
	rule.cacheMu.Unlock()

	return rule.filterVulnerableVersions(vulns, version), nil
}

// filterVulnerableVersions filters vulnerabilities that affect the given version
func (rule *KnownVulnerableActionsRule) filterVulnerableVersions(vulns []*VulnerabilityInfo, version string) []*VulnerabilityInfo {
	var affected []*VulnerabilityInfo
	for _, v := range vulns {
		if isVersionAffected(version, v.VulnerableRange) {
			affected = append(affected, v)
		}
	}
	return affected
}

// isVersionAffected checks if a version is affected by a vulnerability range
// Vulnerability ranges use npm-style semver ranges:
// e.g., "< 6.25.1", ">= 3.0.0, < 3.3.12", ">= 2.0.0, < 2.0.3"
func isVersionAffected(version, vulnRange string) bool {
	if vulnRange == "" {
		return false
	}

	// Strip 'v' prefix if present for comparison
	cleanVersion := strings.TrimPrefix(version, "v")

	// Parse the vulnerability range
	conditions := strings.Split(vulnRange, ",")
	for _, cond := range conditions {
		cond = strings.TrimSpace(cond)
		if !checkCondition(cleanVersion, cond) {
			return false
		}
	}
	return true
}

// checkCondition checks a single version condition
func checkCondition(version, condition string) bool {
	condition = strings.TrimSpace(condition)
	if condition == "" {
		return true
	}

	// Parse operator and version from condition
	var op, condVersion string
	if strings.HasPrefix(condition, ">=") {
		op = ">="
		condVersion = strings.TrimSpace(condition[2:])
	} else if strings.HasPrefix(condition, "<=") {
		op = "<="
		condVersion = strings.TrimSpace(condition[2:])
	} else if strings.HasPrefix(condition, ">") {
		op = ">"
		condVersion = strings.TrimSpace(condition[1:])
	} else if strings.HasPrefix(condition, "<") {
		op = "<"
		condVersion = strings.TrimSpace(condition[1:])
	} else if strings.HasPrefix(condition, "=") {
		op = "="
		condVersion = strings.TrimSpace(condition[1:])
	} else {
		// No operator, assume equality
		op = "="
		condVersion = condition
	}

	condVersion = strings.TrimPrefix(condVersion, "v")

	cmp := compareVersions(version, condVersion)
	switch op {
	case ">=":
		return cmp >= 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case "<":
		return cmp < 0
	case "=":
		return cmp == 0
	default:
		return false
	}
}

// compareVersions compares two semantic versions
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
// Handles pre-release versions: 1.0.0-beta.1 < 1.0.0
func compareVersions(v1, v2 string) int {
	// Split version and pre-release
	base1, pre1 := splitPreRelease(v1)
	base2, pre2 := splitPreRelease(v2)

	parts1 := parseVersionParts(base1)
	parts2 := parseVersionParts(base2)

	// Compare base version numbers
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1, p2 int
		if i < len(parts1) {
			p1 = parts1[i]
		}
		if i < len(parts2) {
			p2 = parts2[i]
		}

		if p1 < p2 {
			return -1
		}
		if p1 > p2 {
			return 1
		}
	}

	// Base versions are equal, compare pre-release
	// No pre-release (release version) > with pre-release
	// 1.0.0 > 1.0.0-beta.1
	if pre1 == "" && pre2 != "" {
		return 1 // v1 is release, v2 is pre-release
	}
	if pre1 != "" && pre2 == "" {
		return -1 // v1 is pre-release, v2 is release
	}
	if pre1 != "" && pre2 != "" {
		// Both are pre-releases, compare lexicographically
		if pre1 < pre2 {
			return -1
		}
		if pre1 > pre2 {
			return 1
		}
	}

	return 0
}

// splitPreRelease splits version into base version and pre-release
// e.g., "1.0.0-beta.1" -> ("1.0.0", "beta.1")
func splitPreRelease(version string) (base, preRelease string) {
	if idx := strings.Index(version, "-"); idx != -1 {
		return version[:idx], version[idx+1:]
	}
	return version, ""
}

// parseVersionParts parses a version string into numeric parts
func parseVersionParts(version string) []int {
	parts := strings.Split(version, ".")
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		var num int
		_, _ = fmt.Sscanf(p, "%d", &num)
		result = append(result, num)
	}
	return result
}

// severityToLevel converts severity string to a numeric level for comparison
func severityToLevel(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// VisitStep checks each step for actions with known vulnerabilities
func (rule *KnownVulnerableActionsRule) VisitStep(step *ast.Step) error {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return nil
	}

	usesValue := action.Uses.Value

	// Skip local and docker actions
	if isLocalAction(usesValue) || isDockerAction(usesValue) {
		return nil
	}

	owner, repo, ref, ok := parseActionRef(usesValue)
	if !ok {
		return nil
	}

	ctx := context.Background()

	// Resolve the version from the ref
	version, err := rule.getVersionFromRef(ctx, owner, repo, ref)
	if err != nil {
		// Log as debug and skip (similar to commitsha.go pattern)
		// This can happen for private repos, rate limiting, network errors, etc.
		rule.Debug("failed to resolve version for %s/%s@%s: %v", owner, repo, ref, err)
		return nil
	}

	rule.Debug("resolved version for %s/%s@%s -> %s", owner, repo, ref, version)

	// Fetch and check for vulnerabilities
	vulns, err := rule.fetchAdvisories(ctx, owner, repo, version)
	if err != nil {
		// Log as debug and skip (similar to commitsha.go pattern)
		// This can happen for rate limiting, network errors, etc.
		rule.Debug("failed to fetch advisories for %s/%s: %v", owner, repo, err)
		return nil
	}

	rule.Debug("found %d vulnerabilities for %s/%s@%s", len(vulns), owner, repo, version)

	if len(vulns) == 0 {
		return nil
	}

	// Track the highest patched version required across all vulnerabilities
	var highestPatchedVersion string

	// Report vulnerabilities
	for _, vuln := range vulns {
		var fixAdvice string
		if vuln.FirstPatchedVersion != "" {
			fixAdvice = fmt.Sprintf(" Upgrade to version %s or later.", vuln.FirstPatchedVersion)

			// Track the highest version requirement
			if highestPatchedVersion == "" ||
				compareVersions(vuln.FirstPatchedVersion, highestPatchedVersion) > 0 {
				highestPatchedVersion = vuln.FirstPatchedVersion
			}
		}

		rule.Errorf(step.Pos,
			"Action '%s' has a known %s severity vulnerability (%s): %s.%s See: %s",
			usesValue,
			vuln.Severity,
			vuln.GHSAID,
			vuln.Summary,
			fixAdvice,
			vuln.HTMLURL,
		)
	}

	// Add a single auto-fixer with the highest required version
	if highestPatchedVersion != "" {
		// Create a virtual vulnerability info with the highest version
		highestVuln := &VulnerabilityInfo{
			FirstPatchedVersion: highestPatchedVersion,
		}
		fixer := NewKnownVulnerableActionsFixer(step, rule, highestVuln)
		rule.AddAutoFixer(NewStepFixer(step, fixer))
	}

	return nil
}

func (rule *KnownVulnerableActionsRule) VisitJobPre(node *ast.Job) error {
	return nil
}

func (rule *KnownVulnerableActionsRule) VisitJobPost(node *ast.Job) error {
	return nil
}

func (rule *KnownVulnerableActionsRule) VisitWorkflowPre(node *ast.Workflow) error {
	return nil
}

func (rule *KnownVulnerableActionsRule) VisitWorkflowPost(node *ast.Workflow) error {
	return nil
}

type KnownVulnerableActionsFixer struct {
	step *ast.Step
	rule *KnownVulnerableActionsRule
	vuln *VulnerabilityInfo
}

func NewKnownVulnerableActionsFixer(step *ast.Step, rule *KnownVulnerableActionsRule, vuln *VulnerabilityInfo) *KnownVulnerableActionsFixer {
	return &KnownVulnerableActionsFixer{
		step: step,
		rule: rule,
		vuln: vuln,
	}
}

func (f *KnownVulnerableActionsFixer) RuleNames() string {
	return f.rule.RuleName
}

func (f *KnownVulnerableActionsFixer) FixStep(step *ast.Step) error {
	if step != f.step {
		return nil
	}

	action, ok := step.Exec.(*ast.ExecAction)
	if !ok {
		return nil
	}

	usesValue := action.Uses.Value
	owner, repo, originalRef, ok := parseActionRef(usesValue)
	if !ok {
		return nil
	}

	patchedVersion := f.vuln.FirstPatchedVersion
	if patchedVersion == "" {
		return nil
	}

	if isFullLengthCommitSHA(originalRef) {
		ctx := context.Background()
		// Try with "v" prefix first
		newSHA, err := f.rule.resolveSymbolicRef(ctx, owner, repo, "v"+patchedVersion)
		if err != nil {
			// Try without "v" prefix
			newSHA, err = f.rule.resolveSymbolicRef(ctx, owner, repo, patchedVersion)
			if err != nil {
				// If both fail, return error (similar to commitsha.go pattern)
				lintErr := FormattedError(step.Pos, f.rule.RuleName, "failed to resolve patched version %s to commit SHA: %s at step '%s'", patchedVersion, err.Error(), step.String())
				return lintErr
			}
		}
		action.Uses.BaseNode.Value = fmt.Sprintf("%s/%s@%s", owner, repo, newSHA)
		action.Uses.BaseNode.LineComment = "v" + patchedVersion
	} else {
		newRef := patchedVersion
		if strings.HasPrefix(originalRef, "v") && !strings.HasPrefix(patchedVersion, "v") {
			newRef = "v" + patchedVersion
		}
		action.Uses.BaseNode.Value = fmt.Sprintf("%s/%s@%s", owner, repo, newRef)
		action.Uses.BaseNode.LineComment = ""
	}

	return nil
}
