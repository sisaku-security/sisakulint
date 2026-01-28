package core

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// SecretExfiltrationRule detects patterns where secrets may be exfiltrated to external services.
// This rule identifies dangerous patterns such as:
// 1. Network commands (curl, wget, nc, etc.) with secrets in arguments
// 2. Secrets passed via environment variables to network commands
// 3. DNS exfiltration via dig/nslookup with secrets
//
// The rule distinguishes between legitimate uses (npm publish, docker login, etc.)
// and potentially malicious patterns.
type SecretExfiltrationRule struct {
	BaseRule
	currentStep *ast.Step
	workflow    *ast.Workflow
}

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
			"artifactory",
			"nexus",
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
			"vault.",
			"hashicorp",
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

// Patterns for legitimate authentication/publishing commands
var legitimatePatterns = []*regexp.Regexp{
	// Package managers and registries
	regexp.MustCompile(`(?i)npm\s+(publish|login|adduser)`),
	regexp.MustCompile(`(?i)yarn\s+publish`),
	regexp.MustCompile(`(?i)pnpm\s+publish`),
	regexp.MustCompile(`(?i)docker\s+(login|push)`),
	regexp.MustCompile(`(?i)podman\s+(login|push)`),
	regexp.MustCompile(`(?i)pip\s+upload`),
	regexp.MustCompile(`(?i)twine\s+upload`),
	regexp.MustCompile(`(?i)gem\s+push`),
	regexp.MustCompile(`(?i)cargo\s+publish`),
	regexp.MustCompile(`(?i)dotnet\s+nuget\s+push`),
	regexp.MustCompile(`(?i)mvn\s+deploy`),
	regexp.MustCompile(`(?i)gradle\s+publish`),
	regexp.MustCompile(`(?i)go\s+mod\s+publish`),
	regexp.MustCompile(`(?i)composer\s+publish`),

	// Cloud CLI tools (authentication)
	regexp.MustCompile(`(?i)aws\s+(configure|sts|ecr)`),
	regexp.MustCompile(`(?i)gcloud\s+(auth|config)`),
	regexp.MustCompile(`(?i)az\s+(login|acr)`),
	regexp.MustCompile(`(?i)kubectl\s+config`),
	regexp.MustCompile(`(?i)helm\s+(push|repo)`),

	// Git operations
	regexp.MustCompile(`(?i)git\s+(push|clone|fetch|pull|remote)`),
	regexp.MustCompile(`(?i)gh\s+(api|pr|issue|release)`),

	// CI/CD tools
	regexp.MustCompile(`(?i)codecov`),
	regexp.MustCompile(`(?i)coveralls`),

	// Terraform/Infrastructure
	regexp.MustCompile(`(?i)terraform\s+(login|init|apply|plan)`),
	regexp.MustCompile(`(?i)vault\s+(login|kv|read|write)`),
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

// VisitWorkflowPre captures workflow context
func (rule *SecretExfiltrationRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.workflow = node
	return nil
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

	// Check if script matches legitimate patterns
	if rule.isLegitimateUse(script) {
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

// isLegitimateUse checks if the script contains legitimate authentication/publishing patterns
func (rule *SecretExfiltrationRule) isLegitimateUse(script string) bool {
	for _, pattern := range legitimatePatterns {
		if pattern.MatchString(script) {
			return true
		}
	}
	return false
}

// detectExfiltrationPatterns analyzes the script for exfiltration patterns
func (rule *SecretExfiltrationRule) detectExfiltrationPatterns(script string, runStr *ast.String, envSecrets map[string]string) []exfiltrationPattern {
	var patterns []exfiltrationPattern

	// Split script into lines for line-by-line analysis
	lines := strings.Split(script, "\n")
	lineOffset := 0

	for lineIdx, line := range lines {
		linePatterns := rule.analyzeLine(line, runStr, lineIdx, lineOffset, envSecrets)
		patterns = append(patterns, linePatterns...)
		lineOffset += len(line) + 1 // +1 for newline
	}

	return patterns
}

// analyzeLine analyzes a single line for exfiltration patterns
func (rule *SecretExfiltrationRule) analyzeLine(line string, runStr *ast.String, lineIdx, lineOffset int, envSecrets map[string]string) []exfiltrationPattern {
	var patterns []exfiltrationPattern

	// Skip comment lines
	trimmedLine := strings.TrimSpace(line)
	if strings.HasPrefix(trimmedLine, "#") {
		return patterns
	}

	// Check each network command
	for _, cmd := range networkCommands {
		if !rule.lineContainsCommand(line, cmd.name) {
			continue
		}

		// Skip if line matches legitimate patterns for this command
		if rule.matchesLegitPattern(line, cmd) {
			continue
		}

		// Check for direct secret references in the line
		// Only detect if both the command and secret are on the same line
		secretRefs := rule.findSecretRefsInLine(line)
		for _, secretRef := range secretRefs {
			pos := rule.calculatePosition(runStr, lineIdx, lineOffset, line, secretRef)
			severity := "high"
			if cmd.isHighRisk && rule.hasDataFlag(line, cmd) {
				severity = "critical"
			}

			patterns = append(patterns, exfiltrationPattern{
				command:   cmd.name,
				secretRef: secretRef,
				position:  pos,
				severity:  severity,
			})
		}

		// Check for environment variable usage that contains secrets
		for envName, secretRef := range envSecrets {
			if rule.lineUsesEnvVar(line, envName) {
				pos := rule.calculatePosition(runStr, lineIdx, lineOffset, line, "$"+envName)
				severity := "high"
				if cmd.isHighRisk && rule.hasDataFlag(line, cmd) {
					severity = "critical"
				}

				patterns = append(patterns, exfiltrationPattern{
					command:      cmd.name,
					secretRef:    secretRef,
					envVarName:   envName,
					isEnvVarLeak: true,
					position:     pos,
					severity:     severity,
				})
			}
		}
	}

	return patterns
}

// lineContainsCommand checks if a line contains a network command
func (rule *SecretExfiltrationRule) lineContainsCommand(line, cmdName string) bool {
	// Match command at start of line or after common shell constructs
	patterns := []string{
		`(?:^|\s|;|&&|\|\||` + "`" + `|\$\()` + regexp.QuoteMeta(cmdName) + `(?:\s|$)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// matchesLegitPattern checks if a line matches legitimate patterns for a command
func (rule *SecretExfiltrationRule) matchesLegitPattern(line string, cmd networkCommand) bool {
	lineLower := strings.ToLower(line)
	for _, pattern := range cmd.legitPatterns {
		if strings.Contains(lineLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// findSecretRefsInLine finds all secret references in a line
func (rule *SecretExfiltrationRule) findSecretRefsInLine(line string) []string {
	var refs []string
	re := regexp.MustCompile(`\$\{\{\s*(secrets\.[A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)
	matches := re.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) > 1 {
			refs = append(refs, match[1])
		}
	}
	return refs
}

// hasDataFlag checks if the line contains data-sending flags
func (rule *SecretExfiltrationRule) hasDataFlag(line string, cmd networkCommand) bool {
	for _, flag := range cmd.dataFlags {
		// Check for flag followed by space or =
		pattern := regexp.QuoteMeta(flag) + `(?:\s|=)`
		re := regexp.MustCompile(pattern)
		if re.MatchString(line) {
			return true
		}
	}
	// Also check for POST/PUT methods in curl
	if cmd.name == "curl" {
		if strings.Contains(line, "-X POST") || strings.Contains(line, "-X PUT") ||
			strings.Contains(line, "--request POST") || strings.Contains(line, "--request PUT") {
			return true
		}
	}
	return false
}

// lineUsesEnvVar checks if a line uses an environment variable
func (rule *SecretExfiltrationRule) lineUsesEnvVar(line, envName string) bool {
	// Check for $VAR, ${VAR}, "$VAR", "${VAR}"
	patterns := []string{
		`\$` + regexp.QuoteMeta(envName) + `(?:\s|$|"|'|;)`,
		`\$\{` + regexp.QuoteMeta(envName) + `\}`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// calculatePosition calculates the position for an error
func (rule *SecretExfiltrationRule) calculatePosition(runStr *ast.String, lineIdx, lineOffset int, line, target string) *ast.Position {
	col := strings.Index(line, target)
	if col == -1 {
		col = 0
	}

	pos := &ast.Position{
		Line: runStr.Pos.Line + lineIdx,
		Col:  col + 1,
	}

	// Adjust for literal block style
	if runStr.Literal {
		pos.Line++
	}

	return pos
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

