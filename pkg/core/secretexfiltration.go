package core

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/shell"
	"gopkg.in/yaml.v3"
)

// SecretExfiltrationRule detects patterns where secrets may be exfiltrated to external services.
// This rule identifies dangerous patterns such as:
// 1. Network commands (curl, wget, nc, etc.) with secrets in arguments
// 2. Secrets passed via environment variables to network commands
// 3. DNS exfiltration via dig/nslookup with secrets
//
// The rule suppresses known trusted network destinations while flagging
// untrusted or unresolved destinations that receive secret-bearing data.
type SecretExfiltrationRule struct {
	BaseRule
	currentStep *ast.Step
	workflow    *ast.Workflow

	// allowedHosts is the effective list of user-configured trusted hosts for
	// this workflow (merged: global config + per-workflow comment override).
	// Entries are normalized lowercased. Suffix wildcard form "*.example.com"
	// is preserved verbatim and interpreted by userHostAllowlistMatch.
	allowedHosts []string
	// allowedHostUsed tracks which allowedHosts entries actually matched a
	// detected network call destination during this workflow's visit. Entries
	// that remain false after VisitWorkflowPost are reported as "dead allow"
	// warnings so the allowlist does not silently rot.
	allowedHostUsed map[string]bool
	// allowedHostSources records where each entry originated:
	//   - "global"    : .github/sisakulint.yaml (repo-wide config)
	//   - "directive" : per-workflow YAML comment directive
	// Dead-allow warnings are emitted ONLY for "directive" entries because a
	// global allowlist is intentionally shared across many workflows and may
	// look "dead" from any single workflow's perspective.
	allowedHostSources map[string]string
	// allowedHostsPos points to a representative position used when emitting
	// dead-allow warnings (workflow root if none better is available).
	allowedHostsPos *ast.Position
	// hasUnresolvableDestination is set when at least one network command in
	// this workflow has a destination that cannot be statically resolved
	// (e.g. fully variable URL like `$URL`). In that case dead-allow detection
	// is suppressed because a legitimate allowlist entry may match a runtime
	// value the analyzer cannot see.
	hasUnresolvableDestination bool
	// invalidAllowedHostEntries collects allowlist entries that failed
	// validation in normalizeAllowedHost, together with the rejection reason
	// and the originating source. Reported once per workflow in
	// VisitWorkflowPost so users learn that an entry is silently inert.
	invalidAllowedHostEntries []invalidAllowedHostEntry
}

// invalidAllowedHostEntry captures a rejected allowlist entry for diagnostic
// reporting. raw is the original (pre-normalization) value, reason is the
// human-readable rejection cause, and source is "global" or "directive".
type invalidAllowedHostEntry struct {
	raw    string
	reason string
	source string
}

// perWorkflowAllowedHostsDirective is the YAML comment marker that allows a
// workflow file to add extra allowed-hosts on top of the repo-wide config.
// Format:
//
//	# sisakulint:secret-exfiltration.allowed-hosts: api.example.com, *.example.com
//
// The directive is only honored when attached to a top-level YAML node:
// the document itself, the root mapping, or one of the immediate top-level
// keys (`name:`, `on:`, `jobs:`, …). Comments on deeper nodes (e.g. a step's
// LineComment) are intentionally ignored — see walkYAMLComments — so the
// suppression surface remains auditable from the file header. Multiple
// directives at the top level are merged. The override is additive: it
// never removes globally configured entries but may add workflow-scoped
// entries, so the effective allowlist for that file is `global ∪ directive`.
const perWorkflowAllowedHostsDirective = "sisakulint:secret-exfiltration.allowed-hosts:"

// networkCommand represents a network-related command that could be used for exfiltration
type networkCommand struct {
	name          string
	dataFlags     []string // Flags that typically carry data (e.g., -d for curl)
	isHighRisk    bool     // True for commands like curl with POST, nc, telnet
	legitPatterns []string // Patterns that indicate legitimate use
}

var networkCommands = []networkCommand{
	{
		name:       "curl",
		dataFlags:  []string{"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-F", "--form", "-H", "--header"},
		isHighRisk: true,
		legitPatterns: []string{
			"api.github.com",
			"uploads.github.com",
			"registry.npmjs.org",
			"pypi.org",
			"upload.pypi.org",
			"hub.docker.com",
			"ghcr.io",
			"docker.io",
			"gcr.io",
			"ecr.aws",
			"azurecr.io",
			"nuget.org",
			"api.nuget.org",
			"rubygems.org",
			"packagist.org",
			"crates.io",
			"pkg.go.dev",
			"maven.org",
			"sonatype.org",
			"jfrog.io",
			"slack.com/api",
			"hooks.slack.com",
			"discord.com/api",
			"api.telegram.org",
			"codecov.io",
			"coveralls.io",
			"codeclimate.com",
			"sonarcloud.io",
			"snyk.io",
			"sentry.io",
			"datadoghq.com",
			"newrelic.com",
			"pagerduty.com",
			"opsgenie.com",
			"circleci.com",
			"travis-ci.com",
			"app.terraform.io",
			"hashicorp.com",
		},
	},
	{
		name:       "wget",
		dataFlags:  []string{"--post-data", "--post-file", "--header"},
		isHighRisk: true,
		legitPatterns: []string{
			"github.com",
			"githubusercontent.com",
		},
	},
	{
		name:       "http",
		dataFlags:  []string{},
		isHighRisk: true,
		legitPatterns: []string{
			"api.github.com",
			"uploads.github.com",
		},
	},
	{
		name:       "https",
		dataFlags:  []string{},
		isHighRisk: true,
		legitPatterns: []string{
			"api.github.com",
			"uploads.github.com",
		},
	},
	{
		name:          "nc",
		dataFlags:     []string{},
		isHighRisk:    true,
		legitPatterns: []string{},
	},
	{
		name:          "netcat",
		dataFlags:     []string{},
		isHighRisk:    true,
		legitPatterns: []string{},
	},
	{
		name:          "ncat",
		dataFlags:     []string{},
		isHighRisk:    true,
		legitPatterns: []string{},
	},
	{
		name:          "telnet",
		dataFlags:     []string{},
		isHighRisk:    true,
		legitPatterns: []string{},
	},
	{
		name:          "socat",
		dataFlags:     []string{},
		isHighRisk:    true,
		legitPatterns: []string{},
	},
	{
		name:       "dig",
		dataFlags:  []string{},
		isHighRisk: true, // DNS exfiltration
		legitPatterns: []string{
			"@8.8.8.8",
			"@1.1.1.1",
			"localhost",
		},
	},
	{
		name:       "nslookup",
		dataFlags:  []string{},
		isHighRisk: true, // DNS exfiltration
		legitPatterns: []string{
			"8.8.8.8",
			"1.1.1.1",
			"localhost",
		},
	},
	{
		name:       "host",
		dataFlags:  []string{},
		isHighRisk: true, // DNS exfiltration
		legitPatterns: []string{
			"8.8.8.8",
			"1.1.1.1",
		},
	},
}

// exfiltrationPattern represents a detected exfiltration pattern
type exfiltrationPattern struct {
	command      string
	secretRef    string
	envVarName   string // If secret is passed via env var
	isEnvVarLeak bool   // If secret is in env var passed to command
	position     *ast.Position
	severity     string // "critical" or "high"
}

// NewSecretExfiltrationRule creates a new SecretExfiltrationRule
func NewSecretExfiltrationRule() *SecretExfiltrationRule {
	return &SecretExfiltrationRule{
		BaseRule: BaseRule{
			RuleName: "secret-exfiltration",
			RuleDesc: "Detects patterns where secrets may be exfiltrated to external services via network commands (curl, wget, nc, etc.). " +
				"See https://sisaku-security.github.io/lint/docs/rules/secretexfiltration/",
		},
	}
}

// VisitWorkflowPre captures workflow context and builds the effective
// allowed-hosts list (global config + per-workflow comment override).
func (rule *SecretExfiltrationRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.workflow = node
	rule.allowedHosts = nil
	rule.allowedHostUsed = nil
	rule.allowedHostSources = nil
	rule.allowedHostsPos = nil
	rule.hasUnresolvableDestination = false
	rule.invalidAllowedHostEntries = nil

	merged := map[string]bool{}
	var ordered []string
	sources := map[string]string{}

	add := func(h, source string) {
		normalized, reason := normalizeAllowedHost(h)
		if reason != "" {
			rule.invalidAllowedHostEntries = append(rule.invalidAllowedHostEntries, invalidAllowedHostEntry{
				raw:    strings.TrimSpace(h),
				reason: reason,
				source: source,
			})
			return
		}
		if normalized == "" || merged[normalized] {
			return
		}
		merged[normalized] = true
		ordered = append(ordered, normalized)
		sources[normalized] = source
	}

	if rule.userConfig != nil {
		for _, h := range rule.userConfig.SecretExfiltration.AllowedHosts {
			add(h, "global")
		}
	}
	for _, h := range collectPerWorkflowAllowedHosts(node) {
		add(h, "directive")
	}

	if len(ordered) > 0 {
		rule.allowedHosts = ordered
		rule.allowedHostUsed = make(map[string]bool, len(ordered))
		rule.allowedHostSources = sources
		for _, h := range ordered {
			rule.allowedHostUsed[h] = false
		}
	}
	if node != nil && node.BaseNode != nil {
		rule.allowedHostsPos = &ast.Position{Line: node.BaseNode.Line, Col: node.BaseNode.Column}
	}
	if rule.allowedHostsPos == nil {
		rule.allowedHostsPos = &ast.Position{Line: 1, Col: 1}
	}
	return nil
}

// VisitWorkflowPost emits two classes of diagnostics:
//
//  1. "invalid entry" warnings for any allowed-hosts entry that failed
//     normalizeAllowedHost validation. These fire regardless of source —
//     a silently dropped entry is always a misconfiguration that the user
//     should learn about.
//
//  2. "dead allow" warnings for any per-workflow directive entry that did
//     not match a single network command destination in this workflow.
//     Global config entries are NEVER reported as dead from a single
//     workflow's perspective because a repo-wide allowlist is intentionally
//     shared and an entry used only by workflow A would otherwise be flagged
//     dead in workflows B, C, … . Likewise, dead-allow detection is skipped
//     for the whole workflow when at least one network command destination
//     could not be statically resolved (e.g. a fully variable URL like
//     `$URL`) — a legitimate allowlist entry could match the runtime value.
func (rule *SecretExfiltrationRule) VisitWorkflowPost(_ *ast.Workflow) error {
	pos := rule.allowedHostsPos
	if pos == nil {
		pos = &ast.Position{Line: 1, Col: 1}
	}

	// Report invalid entries first so users always learn about silently
	// dropped values, even when nothing else is configured.
	for _, entry := range rule.invalidAllowedHostEntries {
		rule.Errorf(
			pos,
			"secret-exfiltration allowed-hosts entry %q (from %s) is invalid and was ignored: %s. "+
				"Supported forms are exact hostnames (\"api.example.com\") or single leading-wildcard suffixes (\"*.example.com\"). "+
				"Schemes, paths, ports, and embedded wildcards are not accepted.",
			entry.raw, entry.source, entry.reason,
		)
	}

	if len(rule.allowedHosts) == 0 {
		return nil
	}
	if rule.hasUnresolvableDestination {
		// A destination we could not statically resolve might match any
		// allowlist entry at runtime. Suppress dead-allow reporting for
		// the whole workflow to avoid false positives.
		return nil
	}

	// Sort dead entries for deterministic output regardless of map order.
	var dead []string
	for _, h := range rule.allowedHosts {
		if rule.allowedHostUsed[h] {
			continue
		}
		if rule.allowedHostSources[h] != "directive" {
			// Global config entries are out of scope for per-workflow
			// dead-allow detection.
			continue
		}
		dead = append(dead, h)
	}
	sort.Strings(dead)
	for _, h := range dead {
		rule.Errorf(
			pos,
			"secret-exfiltration allowed-hosts directive entry %q did not match any network command destination in this workflow. "+
				"Remove it from the per-workflow directive, or fix the typo. "+
				"Dead directive entries silently widen the suppression scope and should be cleaned up.",
			h,
		)
	}
	return nil
}

// normalizeAllowedHost validates and normalizes a single allowed-hosts
// entry. On success it returns (normalized host, ""). On rejection it
// returns ("", reason) so callers can surface a diagnostic instead of
// silently dropping the entry.
//
// Supported forms:
//   - "api.example.com"   (exact DNS host)
//   - "*.example.com"     (suffix wildcard — matches any subdomain of example.com)
//   - "::1" / "2001:db8::1"          (bracket-less IPv6 literal)
//   - "[::1]" / "[2001:db8::1]"      (bracketed IPv6 literal, brackets stripped)
//
// "*" alone, "**.x", "foo.*.bar", scheme://..., bracketed forms with a
// trailing port like "[::1]:443", and host:port are rejected to keep
// allowlist semantics auditable.
func normalizeAllowedHost(entry string) (string, string) {
	value := strings.TrimSpace(strings.Trim(entry, `"'`))
	if value == "" {
		return "", "empty entry"
	}
	// Reject obvious scheme prefixes — entries are hostnames, not URLs.
	if strings.Contains(value, "://") {
		return "", "scheme prefix is not allowed (entries are hostnames, not URLs)"
	}
	if strings.ContainsAny(value, "/?#@ \t") {
		return "", "path, query, fragment, userinfo, or whitespace characters are not allowed"
	}

	// IPv6 in brackets: strip brackets only when nothing follows the closing
	// bracket. "[::1]:443" carries a port and is rejected.
	if strings.HasPrefix(value, "[") {
		end := strings.Index(value, "]")
		if end < 0 {
			return "", "unbalanced \"[\" in IPv6 literal"
		}
		if end != len(value)-1 {
			return "", "trailing characters after \"]\" are not allowed (ports are not supported)"
		}
		inner := value[1:end]
		if ip := net.ParseIP(inner); ip == nil || ip.To4() != nil {
			return "", "bracketed value is not a valid IPv6 address"
		}
		return strings.ToLower(inner), ""
	}

	// Unbracketed IPv6: detect any value containing "::" or two-or-more
	// colons and validate via net.ParseIP. A single colon is rejected as a
	// port specifier in step (3) below.
	if strings.Contains(value, "::") || strings.Count(value, ":") >= 2 {
		if ip := net.ParseIP(value); ip != nil && ip.To4() == nil {
			return strings.ToLower(value), ""
		}
		return "", "value contains \":\" but is not a valid IPv6 address"
	}

	// Reject port specifications on DNS / IPv4 forms.
	if strings.Contains(value, ":") {
		return "", "port specifications are not allowed (matching is hostname-only)"
	}
	value = strings.ToLower(value)
	// Validate wildcard form: it must be a single leading "*." prefix.
	if strings.HasPrefix(value, "*.") {
		rest := strings.TrimPrefix(value, "*.")
		if rest == "" {
			return "", "wildcard suffix is empty"
		}
		if strings.Contains(rest, "*") {
			return "", "multiple wildcards are not allowed"
		}
		return "*." + rest, ""
	}
	if strings.Contains(value, "*") {
		return "", "wildcard must appear only as a leading \"*.\" prefix"
	}
	return value, ""
}

// userHostAllowlistMatch reports whether host (already lowercased) matches
// one of the configured allowed-hosts entries. Returns the matched pattern
// so callers can record usage and avoid dead-allow false positives.
func userHostAllowlistMatch(host string, allowed []string) (string, bool) {
	host = strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(host), "@"), ".")
	if host == "" {
		return "", false
	}
	for _, pattern := range allowed {
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*.")
			if host == suffix || strings.HasSuffix(host, "."+suffix) {
				return pattern, true
			}
			continue
		}
		if host == pattern {
			return pattern, true
		}
	}
	return "", false
}

// collectPerWorkflowAllowedHosts walks the workflow's underlying yaml.Node
// tree and collects allowed-hosts entries from any comment line containing
// the perWorkflowAllowedHostsDirective marker. The directive value is a
// comma-separated host list.
func collectPerWorkflowAllowedHosts(workflow *ast.Workflow) []string {
	if workflow == nil || workflow.BaseNode == nil {
		return nil
	}
	var hosts []string
	walkYAMLComments(workflow.BaseNode, func(comment string) {
		hosts = append(hosts, parseAllowedHostsDirective(comment)...)
	})
	return hosts
}

// parseAllowedHostsDirective extracts allowed-hosts entries from a single
// comment string. The comment may contain the directive marker anywhere
// (e.g. as part of a multi-line comment block). Entries are separated by
// commas or whitespace; leading "#" markers are tolerated.
func parseAllowedHostsDirective(comment string) []string {
	var results []string
	for _, line := range strings.Split(comment, "\n") {
		trimmed := strings.TrimSpace(strings.TrimLeft(line, "#"))
		idx := strings.Index(trimmed, perWorkflowAllowedHostsDirective)
		if idx < 0 {
			continue
		}
		payload := strings.TrimSpace(trimmed[idx+len(perWorkflowAllowedHostsDirective):])
		// Allow comma or whitespace separation. Quotes are stripped per entry.
		for _, raw := range splitDirectivePayload(payload) {
			value := strings.TrimSpace(raw)
			if value == "" {
				continue
			}
			results = append(results, value)
		}
	}
	return results
}

func splitDirectivePayload(payload string) []string {
	if payload == "" {
		return nil
	}
	return strings.FieldsFunc(payload, func(r rune) bool {
		switch r {
		case ',', ' ', '\t':
			return true
		default:
			return false
		}
	})
}

// walkYAMLComments invokes visit on comments at workflow-file top level only:
// the document node, the root mapping node, and the immediate top-level keys
// (and their immediate values) of that mapping. Deeper nodes — step names,
// nested env blocks, individual job bodies — are intentionally NOT visited.
//
// Scoping the directive lookup to the top of the file makes the suppression
// surface auditable: a reviewer scanning the workflow header sees every
// allowed-hosts directive that affects the file, instead of having to grep
// every comment in every step. Without this restriction a directive buried
// next to a deep yaml node could silently widen the allowlist for the entire
// workflow with no signal at the top.
func walkYAMLComments(node *yaml.Node, visit func(string)) {
	if node == nil {
		return
	}
	emit := func(n *yaml.Node) {
		if n == nil {
			return
		}
		if n.HeadComment != "" {
			visit(n.HeadComment)
		}
		if n.LineComment != "" {
			visit(n.LineComment)
		}
		if n.FootComment != "" {
			visit(n.FootComment)
		}
	}
	// Document node carries the leading file comment.
	emit(node)
	root := node
	if node.Kind == yaml.DocumentNode {
		if len(node.Content) == 0 {
			return
		}
		root = node.Content[0]
		emit(root)
	}
	if root == nil || root.Kind != yaml.MappingNode {
		return
	}
	// Visit comments on each immediate (key, value) pair of the top-level
	// mapping. Do NOT recurse into the value's children.
	for i := 0; i+1 < len(root.Content); i += 2 {
		emit(root.Content[i])
		emit(root.Content[i+1])
	}
}

// VisitJobPre visits each job and checks steps
func (rule *SecretExfiltrationRule) VisitJobPre(node *ast.Job) error {
	for _, step := range node.Steps {
		rule.currentStep = step
		rule.checkStep(step)
	}
	return nil
}

// checkStep checks a single step for secret exfiltration patterns
func (rule *SecretExfiltrationRule) checkStep(step *ast.Step) {
	if step.Exec == nil {
		return
	}

	// Only check run: scripts
	execRun, ok := step.Exec.(*ast.ExecRun)
	if !ok || execRun.Run == nil {
		return
	}

	script := execRun.Run.Value
	if script == "" {
		return
	}

	// Collect step environment variables
	stepEnvSecrets := rule.collectEnvSecrets(step.Env)

	// Check for exfiltration patterns
	patterns := rule.detectExfiltrationPatterns(script, execRun.Run, stepEnvSecrets)

	for _, pattern := range patterns {
		rule.reportExfiltration(pattern)
	}
}

// collectEnvSecrets collects environment variables that contain secrets
func (rule *SecretExfiltrationRule) collectEnvSecrets(env *ast.Env) map[string]string {
	result := make(map[string]string)
	if env == nil || env.Vars == nil {
		return result
	}

	for key, envVar := range env.Vars {
		if envVar.Value != nil && strings.Contains(envVar.Value.Value, "secrets.") {
			// Extract the secret reference
			secretRef := rule.extractSecretRef(envVar.Value.Value)
			if secretRef != "" {
				// Use the actual env var name from the Name field if available
				envName := key
				if envVar.Name != nil {
					envName = envVar.Name.Value
				}
				result[envName] = secretRef
			}
		}
	}

	return result
}

// extractSecretRef extracts secret reference from a string like "${{ secrets.TOKEN }}"
func (rule *SecretExfiltrationRule) extractSecretRef(value string) string {
	re := regexp.MustCompile(`\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)
	matches := re.FindStringSubmatch(value)
	if len(matches) > 1 {
		return "secrets." + matches[1]
	}
	return ""
}

// resolveVarInScript looks up shell variable assignments within script and returns the
// assigned value for varName, or "" if not found.
// When the variable is assigned multiple times, the last assignment is returned to match
// shell semantics where later assignments overwrite earlier ones. This prevents a bypass
// where an attacker shadows a legitimate assignment with a malicious one.
func resolveVarInScript(script, varName string) string {
	return resolveVarInScriptBefore(script, varName, len(script))
}

func resolveVarInScriptBefore(script, varName string, maxOffset int) string {
	if maxOffset < 0 {
		return ""
	}
	if maxOffset > len(script) {
		maxOffset = len(script)
	}

	valuePattern := `(?:"([^"]+)"|'([^']+)'|([^\s;|&]+))`
	assignmentValue := `(?:"[^"]*"|'[^']*'|[^\s;|&]+)`
	directPattern := `(?m)(?:^|[;&|]\s*)\s*(?:[A-Za-z_][A-Za-z0-9_]*=` + assignmentValue + `\s+)*` + regexp.QuoteMeta(varName) + `=` + valuePattern

	direct := lastAssignmentMatchBefore(script, directPattern, maxOffset)
	if direct == nil {
		return ""
	}
	return direct.value
}

type assignmentMatch struct {
	end   int
	value string
}

func lastAssignmentMatchBefore(script, pattern string, maxOffset int) *assignmentMatch {
	re := regexp.MustCompile(pattern)
	all := re.FindAllStringSubmatchIndex(script, -1)

	var last *assignmentMatch
	for _, match := range all {
		if len(match) < 8 || match[1] > maxOffset {
			continue
		}
		if !assignmentPersistsBeforeOffset(script, match[1], maxOffset) {
			continue
		}
		for groupIdx := 2; groupIdx < len(match); groupIdx += 2 {
			if match[groupIdx] >= 0 && match[groupIdx+1] >= 0 {
				last = &assignmentMatch{
					end:   match[1],
					value: script[match[groupIdx]:match[groupIdx+1]],
				}
				break
			}
		}
	}
	return last
}

func assignmentPersistsBeforeOffset(script string, assignmentEnd, maxOffset int) bool {
	if assignmentEnd >= len(script) || assignmentEnd > maxOffset {
		return true
	}
	for idx := assignmentEnd; idx <= maxOffset && idx < len(script); idx++ {
		switch script[idx] {
		case ' ', '\t', '\r':
			continue
		case '\n', ';', '&', '|':
			return true
		default:
			return false
		}
	}
	return true
}

// detectExfiltrationPatterns analyzes the script for exfiltration patterns.
func (rule *SecretExfiltrationRule) detectExfiltrationPatterns(script string, runStr *ast.String, envSecrets map[string]string) []exfiltrationPattern {
	parsedScript, secretPlaceholders := shellScriptForNetworkParsing(script)
	parser := shell.NewShellParser(parsedScript)
	calls := parser.FindNetworkCommands()
	if len(calls) == 0 {
		// If the shell parser failed and the raw script contains both a
		// network command keyword and a secret-bearing or env reference, the
		// AST walk has been silently disabled. Emit a conservative warning so
		// the gap surfaces instead of becoming a false negative.
		if parser.ParseError() != nil && scriptHasNetworkKeyword(script) && scriptHasSecretReference(script, envSecrets) {
			rule.reportShellParseFailure(runStr, parser.ParseError())
		}
		return nil
	}

	var patterns []exfiltrationPattern
	for _, call := range calls {
		cmd, ok := networkCommandByName(call.CommandName)
		if !ok {
			continue
		}
		if rule.networkCallMatchesAllowlist(call, script, cmd) {
			continue
		}
		patterns = append(patterns, rule.analyzeNetworkCommandCall(call, script, runStr, envSecrets, cmd, secretPlaceholders)...)
	}
	return patterns
}

func shellScriptForNetworkParsing(script string) (string, map[string]string) {
	re := regexp.MustCompile(`\$\{\{\s*([^}]*)\s*\}\}`)
	secretPlaceholders := map[string]string{}
	secretIdx := 0

	normalized := re.ReplaceAllStringFunc(script, func(match string) string {
		submatches := re.FindStringSubmatch(match)
		if len(submatches) < 2 {
			return strings.Repeat("_", len(match))
		}

		expr := strings.TrimSpace(submatches[1])
		if strings.HasPrefix(expr, "secrets.") {
			secretName := strings.TrimPrefix(expr, "secrets.")
			if regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(secretName) {
				token := "__slgha" + strconv.FormatInt(int64(secretIdx), 36) + "__"
				secretIdx++
				if len(token) > len(match) {
					token = "__" + strconv.FormatInt(int64(secretIdx), 36) + "__"
				}
				if len(token) > len(match) {
					return strings.Repeat("_", len(match))
				}
				token += strings.Repeat("_", len(match)-len(token))
				secretPlaceholders[token] = "secrets." + secretName
				return token
			}
		}
		return strings.Repeat("_", len(match))
	})
	return normalized, secretPlaceholders
}

// scriptHasNetworkKeyword reports whether the raw script contains a token
// that looks like a network command we care about. Used as a coarse trigger
// for the parse-failure fallback warning so genuinely script-free run blocks
// (echo only, etc.) do not generate noise on parse errors.
func scriptHasNetworkKeyword(script string) bool {
	keywords := []string{
		"curl", "wget", "http", "https",
		"nc ", "netcat", "ncat", "socat", "telnet",
		"dig ", "nslookup", "host ",
	}
	for _, kw := range keywords {
		if strings.Contains(script, kw) {
			return true
		}
	}
	return false
}

// scriptHasSecretReference reports whether the raw script contains either a
// `${{ secrets.X }}` expression or a reference to an environment variable
// that has been wired to a secret value. Used together with
// scriptHasNetworkKeyword to gate the parse-failure fallback warning so we
// only warn on plausibly secret-bearing exfiltration scripts.
func scriptHasSecretReference(script string, envSecrets map[string]string) bool {
	if strings.Contains(script, "secrets.") {
		return true
	}
	for envName := range envSecrets {
		if envName == "" {
			continue
		}
		if strings.Contains(script, "$"+envName) || strings.Contains(script, "${"+envName) {
			return true
		}
	}
	return false
}

// reportShellParseFailure emits a single warning when the shell AST parser
// could not parse the run script and the raw script otherwise looks like it
// might exfiltrate a secret. This converts a silent FN into a reviewable
// warning at the run-block position.
func (rule *SecretExfiltrationRule) reportShellParseFailure(runStr *ast.String, parseErr error) {
	if runStr == nil || runStr.Pos == nil {
		return
	}
	pos := &ast.Position{Line: runStr.Pos.Line, Col: runStr.Pos.Col}
	rule.Errorf(
		pos,
		"secret exfiltration: shell parser could not analyze this run script (%v); "+
			"network-command sink detection was skipped. Simplify the script or split the suspicious portion into its own step so the rule can verify it.",
		parseErr,
	)
}

func networkCommandByName(name string) (networkCommand, bool) {
	for _, cmd := range networkCommands {
		if cmd.name == name {
			return cmd, true
		}
	}
	return networkCommand{}, false
}

func (rule *SecretExfiltrationRule) analyzeNetworkCommandCall(call shell.NetworkCommandCall, script string, runStr *ast.String, envSecrets map[string]string, cmd networkCommand, secretPlaceholders map[string]string) []exfiltrationPattern {
	var patterns []exfiltrationPattern
	// For calls extracted from inline shell wrappers (bash -c, sh -c, eval),
	// shell-assignment resolution must run against the inner script — the
	// outer script has the assignment buried inside a quoted body where the
	// regex anchors (`^|[;&|]`) cannot reach it. InnerScript / InnerOffset
	// preserved by walkInlineScript before the position rewrite let us pick
	// the correct frame.
	resolutionScript := script
	maxOffset := int(call.Position.Offset()) //nolint:gosec // workflow shell script offsets fit in int
	if call.InnerScript != "" {
		resolutionScript = call.InnerScript
		maxOffset = int(call.InnerOffset) //nolint:gosec // workflow shell script offsets fit in int
	}

	for idx, arg := range call.Args {
		if !rule.isDataSinkArg(call, idx, cmd) {
			continue
		}

		for _, secretRef := range secretRefsFromCommandArgWithPlaceholders(arg, secretPlaceholders) {
			patterns = append(patterns, exfiltrationPattern{
				command:   cmd.name,
				secretRef: secretRef,
				position:  positionFromCommandArg(runStr, arg),
				severity:  rule.severityForCallArg(call, idx, cmd),
			})
		}

		for _, envLeak := range rule.envSecretRefsFromCommandArg(arg, envSecrets) {
			patterns = append(patterns, exfiltrationPattern{
				command:      cmd.name,
				secretRef:    envLeak.secretRef,
				envVarName:   envLeak.envName,
				isEnvVarLeak: true,
				position:     positionFromCommandArg(runStr, arg),
				severity:     rule.severityForCallArg(call, idx, cmd),
			})
		}

		for _, envLeak := range rule.shellAssignmentSecretRefsFromCommandArg(arg, resolutionScript, maxOffset, secretPlaceholders) {
			patterns = append(patterns, exfiltrationPattern{
				command:      cmd.name,
				secretRef:    envLeak.secretRef,
				envVarName:   envLeak.envName,
				isEnvVarLeak: true,
				position:     positionFromCommandArg(runStr, arg),
				severity:     rule.severityForCallArg(call, idx, cmd),
			})
		}
	}

	stdinDataArgIdx := stdinDataArgIndex(call, cmd)
	if commandReadsStdinAsNetworkSink(cmd) || stdinDataArgIdx >= 0 {
		stdinSeverity := "high"
		if stdinDataArgIdx >= 0 {
			stdinSeverity = rule.severityForCallArg(call, stdinDataArgIdx, cmd)
		}
		for _, pipeArg := range call.PipeInputs {
			for _, secretRef := range secretRefsFromCommandArgWithPlaceholders(pipeArg, secretPlaceholders) {
				patterns = append(patterns, exfiltrationPattern{
					command:   cmd.name,
					secretRef: secretRef,
					position:  positionFromCommandArg(runStr, pipeArg),
					severity:  stdinSeverity,
				})
			}
			for _, envLeak := range rule.envSecretRefsFromCommandArg(pipeArg, envSecrets) {
				patterns = append(patterns, exfiltrationPattern{
					command:      cmd.name,
					secretRef:    envLeak.secretRef,
					envVarName:   envLeak.envName,
					isEnvVarLeak: true,
					position:     positionFromCommandArg(runStr, pipeArg),
					severity:     stdinSeverity,
				})
			}
			for _, envLeak := range rule.shellAssignmentSecretRefsFromCommandArg(pipeArg, resolutionScript, maxOffset, secretPlaceholders) {
				patterns = append(patterns, exfiltrationPattern{
					command:      cmd.name,
					secretRef:    envLeak.secretRef,
					envVarName:   envLeak.envName,
					isEnvVarLeak: true,
					position:     positionFromCommandArg(runStr, pipeArg),
					severity:     stdinSeverity,
				})
			}
		}
		for _, stdinArg := range call.StdinInputs {
			for _, secretRef := range secretRefsFromCommandArgWithPlaceholders(stdinArg, secretPlaceholders) {
				patterns = append(patterns, exfiltrationPattern{
					command:   cmd.name,
					secretRef: secretRef,
					position:  positionFromCommandArg(runStr, stdinArg),
					severity:  stdinSeverity,
				})
			}
			for _, envLeak := range rule.envSecretRefsFromCommandArg(stdinArg, envSecrets) {
				patterns = append(patterns, exfiltrationPattern{
					command:      cmd.name,
					secretRef:    envLeak.secretRef,
					envVarName:   envLeak.envName,
					isEnvVarLeak: true,
					position:     positionFromCommandArg(runStr, stdinArg),
					severity:     stdinSeverity,
				})
			}
			for _, envLeak := range rule.shellAssignmentSecretRefsFromCommandArg(stdinArg, resolutionScript, maxOffset, secretPlaceholders) {
				patterns = append(patterns, exfiltrationPattern{
					command:      cmd.name,
					secretRef:    envLeak.secretRef,
					envVarName:   envLeak.envName,
					isEnvVarLeak: true,
					position:     positionFromCommandArg(runStr, stdinArg),
					severity:     stdinSeverity,
				})
			}
		}
	}

	return patterns
}

func commandReadsStdinAsNetworkSink(cmd networkCommand) bool {
	switch cmd.name {
	case "nc", "netcat", "ncat", "telnet", "socat":
		return true
	default:
		return false
	}
}

func commandUsesStdinDataArg(call shell.NetworkCommandCall, cmd networkCommand) bool {
	return stdinDataArgIndex(call, cmd) >= 0
}

func stdinDataArgIndex(call shell.NetworkCommandCall, cmd networkCommand) int {
	for idx, arg := range call.Args {
		if argIsInlineStdinDataFlag(arg, cmd) {
			return idx
		}
		if idx > 0 && previousFlagConsumesStdinData(call.Args[idx-1], arg, cmd) {
			return idx
		}
	}
	return -1
}

func argIsInlineStdinDataFlag(arg shell.CommandArg, cmd networkCommand) bool {
	if !arg.IsFlag || !flagHasInlineValue(arg) {
		return false
	}
	return flagValueReadsStdin(cmd.name, flagName(arg), inlineFlagValue(arg))
}

func previousFlagConsumesStdinData(previous, current shell.CommandArg, cmd networkCommand) bool {
	if !previous.IsFlag || flagHasInlineValue(previous) {
		return false
	}
	return flagValueReadsStdin(cmd.name, flagName(previous), commandArgComparableValue(current))
}

func flagValueReadsStdin(commandName, flag, value string) bool {
	value = strings.Trim(value, `"'`)
	switch commandName {
	case "curl":
		return stringInSlice(flag, []string{"-d", "--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode", "-F", "--form"}) && value == "@-"
	case "wget":
		return flag == "--post-file" && value == "-"
	default:
		return false
	}
}

type envSecretLeak struct {
	envName   string
	secretRef string
}

func (rule *SecretExfiltrationRule) envSecretRefsFromCommandArg(arg shell.CommandArg, envSecrets map[string]string) []envSecretLeak {
	if len(envSecrets) == 0 || len(arg.VarNames) == 0 {
		return nil
	}

	leaks := make([]envSecretLeak, 0, len(arg.VarNames))
	seen := map[string]bool{}
	for _, varName := range arg.VarNames {
		secretRef, ok := envSecrets[varName]
		if !ok || seen[varName] {
			continue
		}
		seen[varName] = true
		leaks = append(leaks, envSecretLeak{
			envName:   varName,
			secretRef: secretRef,
		})
	}
	return leaks
}

func (rule *SecretExfiltrationRule) shellAssignmentSecretRefsFromCommandArg(arg shell.CommandArg, script string, maxOffset int, secretPlaceholders map[string]string) []envSecretLeak {
	if len(arg.VarNames) == 0 {
		return nil
	}

	leaks := make([]envSecretLeak, 0, len(arg.VarNames))
	seen := map[string]bool{}
	for _, varName := range arg.VarNames {
		if seen[varName] {
			continue
		}
		resolved := resolveVarInScriptBefore(script, varName, maxOffset)
		if resolved == "" {
			continue
		}
		secretRef := rule.extractSecretRef(resolved)
		// When the resolution script comes from a wrapper-extracted inner
		// (bash -c '...' / eval '...'), the assignment value contains the
		// pre-tokenization placeholder rather than the original
		// `${{ secrets.X }}` expression — extractSecretRef misses it. Fall
		// back to the placeholder map so the inner-script flow stays in
		// parity with the outer-script flow.
		if secretRef == "" {
			secretRef = secretRefFromPlaceholders(resolved, secretPlaceholders)
		}
		if secretRef == "" {
			continue
		}
		seen[varName] = true
		leaks = append(leaks, envSecretLeak{
			envName:   varName,
			secretRef: secretRef,
		})
	}
	return leaks
}

func secretRefFromPlaceholders(value string, secretPlaceholders map[string]string) string {
	for placeholder, secretRef := range secretPlaceholders {
		if strings.Contains(value, placeholder) {
			return secretRef
		}
	}
	return ""
}

func secretRefsFromCommandArg(arg shell.CommandArg) []string {
	return secretRefsFromCommandArgWithPlaceholders(arg, nil)
}

func secretRefsFromCommandArgWithPlaceholders(arg shell.CommandArg, secretPlaceholders map[string]string) []string {
	refs := make([]string, 0, len(arg.GHAExprs))
	seen := map[string]bool{}

	for _, expr := range arg.GHAExprs {
		expr = strings.TrimSpace(expr)
		if !strings.HasPrefix(expr, "secrets.") {
			continue
		}
		if !seen[expr] {
			seen[expr] = true
			refs = append(refs, expr)
		}
	}

	if len(refs) > 0 {
		return refs
	}

	for placeholder, secretRef := range secretPlaceholders {
		if strings.Contains(arg.Value, placeholder) || strings.Contains(arg.LiteralValue, placeholder) {
			if !seen[secretRef] {
				seen[secretRef] = true
				refs = append(refs, secretRef)
			}
		}
	}
	if len(refs) > 0 {
		return refs
	}

	re := regexp.MustCompile(`\$\{\{\s*(secrets\.[A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)
	matches := re.FindAllStringSubmatch(arg.Value, -1)
	for _, match := range matches {
		if len(match) > 1 && !seen[match[1]] {
			seen[match[1]] = true
			refs = append(refs, match[1])
		}
	}
	return refs
}

func (rule *SecretExfiltrationRule) isDataSinkArg(call shell.NetworkCommandCall, argIdx int, cmd networkCommand) bool {
	if argIdx < 0 || argIdx >= len(call.Args) {
		return false
	}
	arg := call.Args[argIdx]

	if len(cmd.dataFlags) == 0 {
		return true
	}

	if rule.argIsInlineDataFlag(arg, cmd) {
		return true
	}

	if argIdx > 0 && rule.argConsumesPreviousDataFlag(call.Args[argIdx-1], cmd) {
		return true
	}

	return false
}

func (rule *SecretExfiltrationRule) argConsumesPreviousDataFlag(previous shell.CommandArg, cmd networkCommand) bool {
	if !previous.IsFlag {
		return false
	}
	flag := flagName(previous)
	if flagHasInlineValue(previous) {
		return false
	}
	return stringInSlice(flag, cmd.dataFlags)
}

func (rule *SecretExfiltrationRule) argIsInlineDataFlag(arg shell.CommandArg, cmd networkCommand) bool {
	if !arg.IsFlag || !flagHasInlineValue(arg) {
		return false
	}
	return stringInSlice(flagName(arg), cmd.dataFlags)
}

func flagName(arg shell.CommandArg) string {
	value := arg.LiteralValue
	if value == "" {
		value = arg.Value
	}
	if flag, ok := attachedShortFlagName(value); ok {
		return flag
	}
	if idx := strings.Index(value, "="); idx >= 0 {
		return value[:idx]
	}
	return value
}

func flagHasInlineValue(arg shell.CommandArg) bool {
	value := arg.LiteralValue
	if value == "" {
		value = arg.Value
	}
	if strings.Contains(value, "=") {
		return true
	}
	_, ok := attachedShortFlagName(value)
	return ok
}

func inlineFlagValue(arg shell.CommandArg) string {
	value := arg.LiteralValue
	if value == "" {
		value = arg.Value
	}
	if idx := strings.Index(value, "="); idx >= 0 {
		return value[idx+1:]
	}
	if flag, ok := attachedShortFlagName(value); ok {
		return value[len(flag):]
	}
	return ""
}

func attachedShortFlagName(value string) (string, bool) {
	if len(value) <= 2 || !strings.HasPrefix(value, "-") || strings.HasPrefix(value, "--") {
		return "", false
	}

	flag := value[:2]
	if !knownAttachedShortValueFlag(flag) {
		return "", false
	}
	return flag, true
}

func knownAttachedShortValueFlag(flag string) bool {
	switch flag {
	case "-A", "-b", "-c", "-d", "-e", "-F", "-H", "-K", "-o", "-O", "-u", "-w", "-X":
		return true
	default:
		return false
	}
}

func stringInSlice(value string, values []string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func (rule *SecretExfiltrationRule) severityForCallArg(call shell.NetworkCommandCall, argIdx int, cmd networkCommand) string {
	if cmd.isHighRisk && len(cmd.dataFlags) > 0 && rule.isDataSinkArg(call, argIdx, cmd) {
		return "critical"
	}
	return "high"
}

func positionFromCommandArg(runStr *ast.String, arg shell.CommandArg) *ast.Position {
	line := int(arg.Position.Line()) //nolint:gosec // workflow line numbers fit in int
	col := int(arg.Position.Col())   //nolint:gosec // workflow columns fit in int

	if runStr != nil && runStr.Pos != nil {
		line += runStr.Pos.Line - 1
	}
	if runStr != nil && runStr.Literal {
		line++
	}
	if line <= 0 {
		line = 1
	}
	if col <= 0 {
		col = 1
	}

	return &ast.Position{Line: line, Col: col}
}

func (rule *SecretExfiltrationRule) networkCallMatchesAllowlist(call shell.NetworkCommandCall, script string, cmd networkCommand) bool {
	maxOffset := int(call.Position.Offset()) //nolint:gosec // workflow shell script offsets fit in int
	destinationArgs := rule.destinationArgsForCall(call, cmd)
	if len(destinationArgs) == 0 {
		return false
	}

	// Track whether any destination is dynamic (cannot be resolved to a
	// concrete hostname). VisitWorkflowPost uses this signal to suppress
	// dead-allow false positives when the analyzer cannot see which
	// hostname will actually be hit at runtime.
	for _, arg := range destinationArgs {
		if !destinationIsStaticallyResolvable(arg, script, maxOffset) {
			rule.hasUnresolvableDestination = true
			break
		}
	}

	// Every destination arg must match either the built-in legit patterns or
	// the user-configured allowlist for the call to be suppressed. This keeps
	// commands with mixed destinations (one trusted, one not) from being
	// silently dropped just because part of the destination set is allowed.
	for _, arg := range destinationArgs {
		if rule.argMatchesLegitPattern(arg, script, cmd, maxOffset) {
			continue
		}
		if rule.argMatchesUserAllowedHosts(arg, script, maxOffset) {
			continue
		}
		return false
	}
	return true
}

// destinationIsStaticallyResolvable reports whether the destination string
// carried by arg yields at least one concrete (non-empty, non-template) host
// when expanded with the script's shell-assignment context. Returns false
// when the destination is fully variable (e.g. `$URL` with no resolvable
// assignment) or carries an unresolved GitHub Actions expression.
func destinationIsStaticallyResolvable(arg shell.CommandArg, script string, maxOffset int) bool {
	for _, candidate := range destinationCandidatesForArg(arg, script, maxOffset) {
		trimmed := strings.TrimSpace(strings.Trim(candidate, `"'`))
		if trimmed == "" {
			continue
		}
		// Unresolved shell var or GHA expression — skip; we want at least
		// one fully literal candidate.
		if strings.Contains(trimmed, "${{") || strings.HasPrefix(trimmed, "$") {
			continue
		}
		host, _ := destinationHostAndPath(trimmed)
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		// A host containing a leftover $ means a partial expansion (e.g.
		// `api.$ENV.example.com` where $ENV did not resolve). Treat as
		// dynamic.
		if strings.Contains(host, "$") {
			continue
		}
		return true
	}
	return false
}

// argMatchesUserAllowedHosts checks whether the destination hostname carried
// by arg matches any user-configured allowed-hosts entry. Records usage on a
// match so VisitWorkflowPost can flag dead entries.
//
// Best-effort: if the hostname cannot be statically extracted (e.g. the URL
// is fully assembled from a shell variable whose assignment is not resolvable
// in scope), the call returns false and detection proceeds as before — the
// safe default is to keep flagging.
func (rule *SecretExfiltrationRule) argMatchesUserAllowedHosts(arg shell.CommandArg, script string, maxOffset int) bool {
	if len(rule.allowedHosts) == 0 {
		return false
	}

	candidates := destinationCandidatesForArg(arg, script, maxOffset)
	for _, candidate := range candidates {
		host, _ := destinationHostAndPath(candidate)
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if matched, ok := userHostAllowlistMatch(host, rule.allowedHosts); ok {
			if rule.allowedHostUsed != nil {
				rule.allowedHostUsed[matched] = true
			}
			return true
		}
	}
	return false
}

// destinationCandidatesForArg expands a CommandArg into every concrete
// destination string the rule should test against the allowlist. It mirrors
// argMatchesLegitPattern's resolution logic (variable substitution, inline
// flag value) so allowed-hosts suppression behaves consistently with the
// built-in legit-pattern suppression.
func destinationCandidatesForArg(arg shell.CommandArg, script string, maxOffset int) []string {
	values := []string{arg.Value, arg.LiteralValue}
	for _, varName := range arg.VarNames {
		resolved := resolveVarInScriptBefore(script, varName, maxOffset)
		if resolved == "" {
			continue
		}
		values = append(values, resolved)
		values = append(values, strings.ReplaceAll(arg.Value, "$"+varName, resolved))
		values = append(values, strings.ReplaceAll(arg.Value, "${"+varName+"}", resolved))
		values = append(values, strings.ReplaceAll(arg.LiteralValue, "$"+varName, resolved))
		values = append(values, strings.ReplaceAll(arg.LiteralValue, "${"+varName+"}", resolved))
	}
	if arg.IsFlag && flagHasInlineValue(arg) {
		values = append(values, inlineFlagValue(arg))
	}
	return values
}

func (rule *SecretExfiltrationRule) argMatchesLegitPattern(arg shell.CommandArg, script string, cmd networkCommand, maxOffset int) bool {
	values := []string{arg.Value, arg.LiteralValue}
	for _, varName := range arg.VarNames {
		if resolved := resolveVarInScriptBefore(script, varName, maxOffset); resolved != "" {
			values = append(values, resolved)
			values = append(values, strings.ReplaceAll(arg.Value, "$"+varName, resolved))
			values = append(values, strings.ReplaceAll(arg.Value, "${"+varName+"}", resolved))
			values = append(values, strings.ReplaceAll(arg.LiteralValue, "$"+varName, resolved))
			values = append(values, strings.ReplaceAll(arg.LiteralValue, "${"+varName+"}", resolved))
		}
	}

	for _, value := range values {
		if rule.destinationMatchesLegitPattern(value, cmd) {
			return true
		}
	}
	if arg.IsFlag && flagHasInlineValue(arg) {
		if value := inlineFlagValue(arg); rule.destinationMatchesLegitPattern(value, cmd) {
			return true
		}
	}
	return false
}

func (rule *SecretExfiltrationRule) destinationArgsForCall(call shell.NetworkCommandCall, cmd networkCommand) []shell.CommandArg {
	switch cmd.name {
	case "curl", "http", "https":
		return destinationArgsForURLCommand(call.Args, curlFlagsConsumingNextArg(), []string{"--url"})
	case "wget":
		return destinationArgsForURLCommand(call.Args, wgetFlagsConsumingNextArg(), nil)
	default:
		return destinationArgsForDNSCommand(call.Args)
	}
}

func destinationArgsForURLCommand(args []shell.CommandArg, consumingFlags map[string]bool, destinationFlags []string) []shell.CommandArg {
	var destinations []shell.CommandArg
	for idx := 0; idx < len(args); idx++ {
		arg := args[idx]
		if arg.IsFlag {
			flag := flagName(arg)
			if stringInSlice(flag, destinationFlags) {
				if flagHasInlineValue(arg) {
					destinations = append(destinations, arg)
				} else if idx+1 < len(args) {
					idx++
					destinations = append(destinations, args[idx])
				}
				continue
			}
			if consumingFlags[flag] && !flagHasInlineValue(arg) {
				idx++
			}
			continue
		}
		if isURLishCommandArg(arg) {
			destinations = append(destinations, arg)
		}
	}
	return destinations
}

func destinationArgsForDNSCommand(args []shell.CommandArg) []shell.CommandArg {
	var destinations []shell.CommandArg
	for _, arg := range args {
		if arg.IsFlag {
			continue
		}
		destinations = append(destinations, arg)
	}
	return destinations
}

func curlFlagsConsumingNextArg() map[string]bool {
	return map[string]bool{
		"-A": true, "--user-agent": true,
		"-b": true, "--cookie": true,
		"-c": true, "--cookie-jar": true,
		"-d": true, "--data": true, "--data-ascii": true, "--data-binary": true, "--data-raw": true, "--data-urlencode": true,
		"-e": true, "--referer": true,
		"-F": true, "--form": true, "--form-string": true,
		"-H": true, "--header": true,
		"-K": true, "--config": true,
		"-o": true, "--output": true,
		"-u": true, "--user": true,
		"-w": true, "--write-out": true,
		"-X": true, "--request": true,
		"--cacert": true, "--cert": true, "--connect-to": true, "--key": true, "--proxy": true, "--resolve": true,
	}
}

func wgetFlagsConsumingNextArg() map[string]bool {
	return map[string]bool{
		"-O": true, "--output-document": true,
		"-o": true, "--output-file": true,
		"--body-data": true, "--body-file": true,
		"--header":        true,
		"--http-password": true, "--http-user": true,
		"--post-data": true, "--post-file": true,
		"--referer": true,
		"--user":    true, "--user-agent": true,
		"--password": true,
	}
}

func isURLishCommandArg(arg shell.CommandArg) bool {
	value := commandArgComparableValue(arg)
	value = strings.Trim(value, `"'`)
	if strings.HasPrefix(value, "http://") ||
		strings.HasPrefix(value, "https://") ||
		strings.HasPrefix(value, "$") ||
		strings.HasPrefix(value, "${") {
		return true
	}

	host, _ := destinationHostAndPath(value)
	return host == "localhost" || strings.Contains(host, ".")
}

func (rule *SecretExfiltrationRule) destinationMatchesLegitPattern(value string, cmd networkCommand) bool {
	for _, pattern := range cmd.legitPatterns {
		if legitPatternMatchesDestination(value, pattern) {
			return true
		}
	}
	return false
}

func legitPatternMatchesDestination(value, pattern string) bool {
	value = strings.ToLower(strings.TrimSpace(strings.Trim(value, `"'`)))
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if value == "" || pattern == "" {
		return false
	}

	host, path := destinationHostAndPath(value)
	patternHost, patternPath := splitLegitPattern(pattern)
	if host == "" || patternHost == "" {
		return value == pattern
	}
	if !hostMatchesPattern(host, patternHost) {
		return false
	}
	if patternPath == "" {
		return true
	}
	// Path boundary required: pattern "slack.com/api" must not match
	// "slack.com/api2/evil" or "slack.com/api-attacker".
	patternPath = strings.TrimSuffix(patternPath, "/")
	if path == patternPath {
		return true
	}
	return strings.HasPrefix(path, patternPath+"/")
}

func splitLegitPattern(pattern string) (string, string) {
	value := strings.TrimSpace(strings.Trim(pattern, `"'`))
	if strings.Contains(value, "://") {
		return destinationHostAndPath(value)
	}
	if strings.HasPrefix(value, "@") {
		return value, ""
	}
	if slashIdx := strings.Index(value, "/"); slashIdx >= 0 {
		return value[:slashIdx], value[slashIdx:]
	}
	return value, ""
}

func destinationHostAndPath(value string) (string, string) {
	value = strings.TrimSpace(strings.Trim(value, `"'`))
	if value == "" {
		return "", ""
	}
	if strings.HasPrefix(value, "@") {
		return value, ""
	}

	parseValue := value
	if !strings.Contains(parseValue, "://") {
		parseValue = "//" + parseValue
	}
	parsed, err := url.Parse(parseValue)
	if err == nil && parsed.Hostname() != "" {
		return parsed.Hostname(), parsed.EscapedPath()
	}

	host := value
	if slashIdx := strings.Index(host, "/"); slashIdx >= 0 {
		host = host[:slashIdx]
	}
	if colonIdx := strings.LastIndex(host, ":"); colonIdx > strings.LastIndex(host, "]") {
		host = host[:colonIdx]
	}
	return strings.Trim(host, "[]"), ""
}

func hostMatchesPattern(host, pattern string) bool {
	host = strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(host), "@"), ".")
	pattern = strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(pattern), "@"), ".")
	if host == "" || pattern == "" {
		return false
	}
	return host == pattern || strings.HasSuffix(host, "."+pattern)
}

func commandArgComparableValue(arg shell.CommandArg) string {
	if arg.LiteralValue != "" {
		return arg.LiteralValue
	}
	return arg.Value
}

// reportExfiltration reports an exfiltration pattern
func (rule *SecretExfiltrationRule) reportExfiltration(pattern exfiltrationPattern) {
	var msg string

	if pattern.isEnvVarLeak {
		if pattern.severity == "critical" {
			msg = fmt.Sprintf(
				"secret exfiltration (critical): environment variable $%s containing %s is used with network command '%s' that sends data externally. "+
					"This could exfiltrate the secret to an attacker-controlled server. "+
					"Ensure the destination is trusted or remove the secret from the command.",
				pattern.envVarName, pattern.secretRef, pattern.command,
			)
		} else {
			msg = fmt.Sprintf(
				"secret exfiltration (high): environment variable $%s containing %s is used with network command '%s'. "+
					"This could potentially exfiltrate the secret. Verify the destination is trusted.",
				pattern.envVarName, pattern.secretRef, pattern.command,
			)
		}
	} else {
		if pattern.severity == "critical" {
			msg = fmt.Sprintf(
				"secret exfiltration (critical): %s is directly used with network command '%s' that sends data externally. "+
					"This could exfiltrate the secret to an attacker-controlled server. "+
					"Never pass secrets directly to network commands that send data to external URLs.",
				pattern.secretRef, pattern.command,
			)
		} else {
			msg = fmt.Sprintf(
				"secret exfiltration (high): %s is used with network command '%s'. "+
					"This could potentially exfiltrate the secret. Verify the destination is trusted.",
				pattern.secretRef, pattern.command,
			)
		}
	}

	rule.Error(pattern.position, msg)
}
