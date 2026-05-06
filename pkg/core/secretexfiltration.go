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
// The rule suppresses known trusted network destinations while flagging
// untrusted or unresolved destinations that receive secret-bearing data.
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
	maxOffset := int(call.Position.Offset()) //nolint:gosec // workflow shell script offsets fit in int

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

		for _, envLeak := range rule.shellAssignmentSecretRefsFromCommandArg(arg, script, maxOffset) {
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
			for _, envLeak := range rule.shellAssignmentSecretRefsFromCommandArg(pipeArg, script, maxOffset) {
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
			for _, envLeak := range rule.shellAssignmentSecretRefsFromCommandArg(stdinArg, script, maxOffset) {
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

func (rule *SecretExfiltrationRule) shellAssignmentSecretRefsFromCommandArg(arg shell.CommandArg, script string, maxOffset int) []envSecretLeak {
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
