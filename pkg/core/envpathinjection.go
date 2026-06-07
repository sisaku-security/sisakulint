package core

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
	"gopkg.in/yaml.v3"
	"mvdan.cc/sh/v3/syntax"
)

// EnvPathInjectionRule is a shared implementation for detecting PATH injection vulnerabilities
// It detects when untrusted input is written to $GITHUB_PATH without proper sanitization
// It can be configured to check either privileged triggers (critical) or normal triggers (medium)
type EnvPathInjectionRule struct {
	BaseRule
	severityLevel      string // "critical" or "medium"
	checkPrivileged    bool   // true = check privileged triggers, false = check normal triggers
	stepsWithUntrusted []*stepWithEnvPathInjection
	workflow           *ast.Workflow
}

// stepWithEnvPathInjection tracks steps that need auto-fixing for PATH injection
type stepWithEnvPathInjection struct {
	step *ast.Step
	// job is the enclosing job at the time the step was recorded. Retained
	// so FixStep can consult job-level env vars (and reach workflow.Env via
	// the rule) when deciding whether a generated env var name would
	// shadow an inherited variable.
	job            *ast.Job
	untrustedExprs []envPathUntrustedExprInfo
}

// envPathUntrustedExprInfo contains information about an untrusted expression in $GITHUB_PATH
type envPathUntrustedExprInfo struct {
	expr  parsedExpression
	paths []string
	line  string // The line containing the GITHUB_PATH redirect
}

// Pattern to detect writes to $GITHUB_PATH
// Matches various formats of GITHUB_PATH redirects:
//
//	>> $GITHUB_PATH          (standard format)
//	>> "$GITHUB_PATH"        (double quoted)
//	>> '$GITHUB_PATH'        (single quoted)
//	>> ${GITHUB_PATH}        (with braces)
//	>>$GITHUB_PATH           (no space after >>)
//	>> "${GITHUB_PATH}"      (braces with quotes)
//
// This helps catch all common patterns of PATH writes
var githubPathPattern = regexp.MustCompile(`>>\s*["']?\$\{?GITHUB_PATH\}?["']?`)

// newEnvPathInjectionRule creates a new PATH injection rule with the specified severity level
func newEnvPathInjectionRule(severityLevel string, checkPrivileged bool) *EnvPathInjectionRule {
	var desc string

	if checkPrivileged {
		desc = "Checks for PATH injection vulnerabilities when untrusted input is written to $GITHUB_PATH in privileged workflow triggers (pull_request_target, workflow_run, issue_comment). See https://sisaku-security.github.io/lint/docs/rules/envpathinjectioncritical/"
	} else {
		desc = "Checks for PATH injection vulnerabilities when untrusted input is written to $GITHUB_PATH in normal workflow triggers (pull_request, push, etc.). See https://sisaku-security.github.io/lint/docs/rules/envpathinjectionmedium/"
	}

	return &EnvPathInjectionRule{
		BaseRule: BaseRule{
			RuleName: "envpath-injection-" + severityLevel,
			RuleDesc: desc,
		},
		severityLevel:      severityLevel,
		checkPrivileged:    checkPrivileged,
		stepsWithUntrusted: make([]*stepWithEnvPathInjection, 0),
	}
}

// VisitWorkflowPre is called before visiting a workflow
func (rule *EnvPathInjectionRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.workflow = node
	return nil
}

func (rule *EnvPathInjectionRule) VisitJobPre(node *ast.Job) error {
	// Check if workflow trigger matches what we're looking for
	isPrivileged := rule.hasPrivilegedTriggers()

	// Skip if trigger type doesn't match our severity level
	if rule.checkPrivileged != isPrivileged {
		return nil
	}

	for _, s := range node.Steps {
		if s.Exec == nil || s.Exec.Kind() != ast.ExecKindRun {
			continue
		}

		run := s.Exec.(*ast.ExecRun)
		if run.Run == nil {
			continue
		}

		// Check if the run script writes to $GITHUB_PATH
		script := run.Run.Value
		if !githubPathPattern.MatchString(script) {
			continue
		}

		// Parse expressions from the script
		exprs := rule.extractAndParseExpressions(run.Run)
		if len(exprs) == 0 {
			continue
		}

		var stepUntrusted *stepWithEnvPathInjection

		// Split script into lines to find which lines write to GITHUB_PATH
		lines := strings.Split(script, "\n")
		execPathActive := false
		for lineIdx, line := range lines {
			// Check if this line writes to GITHUB_PATH
			pathWriteRanges, nextExecPathActive := githubPathWriteLineRangesWithExecState(line, execPathActive)
			execPathActive = nextExecPathActive
			if len(pathWriteRanges) == 0 {
				continue
			}

			// Check if a PATH-writing command contains any untrusted expressions
			for _, expr := range exprs {
				// Check if the expression is in a PATH-writing command
				if !githubExpressionInRanges(line, expr.raw, pathWriteRanges) {
					continue
				}

				untrustedPaths := rule.checkUntrustedInput(expr)
				if len(untrustedPaths) > 0 && !rule.isDefinedInEnv(expr, s.Env) {
					if stepUntrusted == nil {
						stepUntrusted = &stepWithEnvPathInjection{step: s, job: node}
					}

					stepUntrusted.untrustedExprs = append(stepUntrusted.untrustedExprs, envPathUntrustedExprInfo{
						expr:  expr,
						paths: untrustedPaths,
						line:  line,
					})

					// Calculate the actual line position
					linePos := &ast.Position{
						Line: run.Run.Pos.Line + lineIdx,
						Col:  run.Run.Pos.Col,
					}
					if run.Run.Literal {
						linePos.Line++
					}

					if rule.checkPrivileged {
						rule.Errorf(
							linePos,
							"PATH injection (critical): \"%s\" is potentially untrusted and written to $GITHUB_PATH in a workflow with privileged triggers. This can allow attackers to hijack command execution by prepending a malicious directory to PATH. Validate the path or use absolute paths instead. See https://sisaku-security.github.io/lint/docs/rules/envpathinjectioncritical/",
							strings.Join(untrustedPaths, "\", \""),
						)
					} else {
						rule.Errorf(
							linePos,
							"PATH injection (medium): \"%s\" is potentially untrusted and written to $GITHUB_PATH. This can allow attackers to hijack command execution by prepending a malicious directory to PATH. Validate the path or use absolute paths instead. See https://sisaku-security.github.io/lint/docs/rules/envpathinjectionmedium/",
							strings.Join(untrustedPaths, "\", \""),
						)
					}
				}
			}
		}

		if stepUntrusted != nil {
			rule.stepsWithUntrusted = append(rule.stepsWithUntrusted, stepUntrusted)
			rule.AddAutoFixer(NewStepFixer(s, rule))
		}
	}
	return nil
}

// hasPrivilegedTriggers checks if the workflow has privileged triggers
func (rule *EnvPathInjectionRule) hasPrivilegedTriggers() bool {
	return HasPrivilegedTriggers(rule.workflow)
}

// RuleNames implements StepFixer interface
func (rule *EnvPathInjectionRule) RuleNames() string {
	return rule.RuleName
}

// FixStep implements StepFixer interface
func (rule *EnvPathInjectionRule) FixStep(step *ast.Step) error {
	// Find the stepWithEnvPathInjection for this step
	var stepInfo *stepWithEnvPathInjection
	for _, s := range rule.stepsWithUntrusted {
		if s.step == step {
			stepInfo = s
			break
		}
	}

	if stepInfo == nil {
		return nil
	}

	// Ensure env exists in AST
	if step.Env == nil {
		step.Env = &ast.Env{
			Vars: make(map[string]*ast.EnvVar),
		}
	}
	if step.Env.Vars == nil {
		step.Env.Vars = make(map[string]*ast.EnvVar)
	}

	run := step.Exec.(*ast.ExecRun)
	if run.Run == nil {
		return nil
	}

	// Group expressions by their raw content to avoid duplicates
	envVarMap := make(map[string]string)             // expr.raw -> chosen env var name
	envVarsForYAML := make(map[string]string)        // env var name -> env var value
	preShadowExistingRefs := make(map[string]string) // expr.raw -> existing env var name

	for _, untrustedInfo := range stepInfo.untrustedExprs {
		expr := untrustedInfo.expr

		// Generate environment variable name from the untrusted path
		baseEnvVarName := rule.generateEnvVarName(untrustedInfo.paths[0])

		// Check if we already created an env var for this expression
		if _, exists := envVarMap[expr.raw]; !exists {
			exprValue := fmt.Sprintf("${{ %s }}", expr.raw)
			matchingExisting, hasMatchingExisting := rule.matchingExistingEnvVarForExpression(step, stepInfo.job, baseEnvVarName, expr.raw, exprValue)
			envVarName := rule.envVarNameForExpression(step, stepInfo.job, run.Run.Value, baseEnvVarName, expr.raw, exprValue, expr.pos, envVarsForYAML)
			envVarMap[expr.raw] = envVarName
			// If a matching existing env var had to be avoided because
			// the script shadows it in at least one shell scope, references
			// in unshadowed scopes still read the existing tainted value
			// and must be wrapped.
			if hasMatchingExisting && matchingExisting.actualName != envVarName {
				preShadowExistingRefs[expr.raw] = matchingExisting.actualName
			}
		}
	}

	// Update BaseNode with env vars
	if step.BaseNode != nil && len(envVarsForYAML) > 0 {
		if err := AddEnvVarsToStepNode(step.BaseNode, envVarsForYAML); err != nil {
			return fmt.Errorf("failed to add env vars to step node: %w", err)
		}
	}

	newScript := run.Run.Value

	existingNameShadowAnalyses := make(map[string]*shellNameShadowAnalysis)
	for _, existingName := range preShadowExistingRefs {
		if _, seen := existingNameShadowAnalyses[existingName]; seen {
			continue
		}
		if analysis, ok := newShellNameShadowAnalysis(newScript, existingName); ok {
			existingNameShadowAnalyses[existingName] = analysis
		}
	}

	// Additional pass: validate env var references in GITHUB_PATH lines
	// Split into lines and process each line that writes to GITHUB_PATH
	lines := strings.Split(newScript, "\n")
	lineStart := 0
	execPathActive := false
	for i, line := range lines {
		originalLineLen := len(line)
		lineEnd := lineStart + originalLineLen
		lineExecPathActive := execPathActive
		pathWriteRanges, nextExecPathActive := githubPathWriteLineRangesWithExecState(line, lineExecPathActive)
		if len(pathWriteRanges) > 0 {
			recomputePathWriteRanges := func() {
				pathWriteRanges, _ = githubPathWriteLineRangesWithExecState(line, lineExecPathActive)
			}
			// This line writes to GITHUB_PATH
			// Replace any $ENV_VAR references with the validated version.
			// Only rewrite the env var actually chosen for this expression.
			// When envVarNameForExpression suffixes the name (e.g.,
			// PR_BODY_2) because the base name is occupied by an unrelated
			// user value, the base name must be left untouched — otherwise
			// the user's `$PR_BODY` references on GITHUB_PATH lines get
			// silently rewritten to the attacker-controlled value.
			processedExistingNames := make(map[string]struct{})
			for _, untrustedInfo := range stepInfo.untrustedExprs {
				existingName, ok := preShadowExistingRefs[untrustedInfo.expr.raw]
				if !ok {
					continue
				}
				if _, seen := processedExistingNames[existingName]; seen {
					continue
				}
				processedExistingNames[existingName] = struct{}{}
				if analysis := existingNameShadowAnalyses[existingName]; analysis != nil {
					line = replaceInTextRanges(line, pathWriteRanges, func(segment string, segmentStart int) string {
						return replaceUnshadowedShellEnvVarRef(segment, existingName, lineStart+segmentStart, analysis)
					})
					recomputePathWriteRanges()
				}
			}
			for _, untrustedInfo := range stepInfo.untrustedExprs {
				envVarName := envVarMap[untrustedInfo.expr.raw]
				line = replaceInTextRanges(line, pathWriteRanges, func(segment string, _ int) string {
					// If the user already had one occurrence wrapped on this
					// statement, unwrap it first so we can re-wrap every shell
					// reference uniformly. A coarse "skip if it already
					// contains validatedVar" check would leave any other
					// `$NAME` reference in the same PATH write untouched.
					validatedVar := fmt.Sprintf("$(realpath \"$%s\")", envVarName)
					if strings.Contains(segment, validatedVar) {
						segment = strings.ReplaceAll(segment, validatedVar, "$"+envVarName)
					}
					return replaceShellEnvVarRef(segment, envVarName)
				})
				recomputePathWriteRanges()
			}
			for _, untrustedInfo := range stepInfo.untrustedExprs {
				envVarName := envVarMap[untrustedInfo.expr.raw]
				line = replaceInTextRanges(line, pathWriteRanges, func(segment string, _ int) string {
					// Replace ${{ expr }} with validated path using realpath.
					newPattern := fmt.Sprintf("$(realpath \"$%s\")", envVarName)
					return replaceGitHubExpression(segment, untrustedInfo.expr.raw, newPattern)
				})
				recomputePathWriteRanges()
			}
			lines[i] = line
		}
		execPathActive = nextExecPathActive
		lineStart = lineEnd + 1
	}
	newScript = strings.Join(lines, "\n")

	// Update AST
	run.Run.Value = newScript

	// Update BaseNode
	if step.BaseNode != nil {
		// Directly update the run script value in the YAML node
		if err := setRunScriptValueForPath(step.BaseNode, newScript); err != nil {
			return fmt.Errorf("failed to update run script: %w", err)
		}
	}

	return nil
}

// matchingExistingEnvVarForExpression returns a step/job/workflow env var that
// already binds the exact expression the autofix would otherwise lift.
func (rule *EnvPathInjectionRule) matchingExistingEnvVarForExpression(
	step *ast.Step,
	job *ast.Job,
	baseName string,
	exprRaw string,
	exprValue string,
) (envVarLookup, bool) {
	key := strings.ToLower(baseName)
	if existing, exists := lookupEnvVar(step.Env, key); exists {
		if envValueMatchesExpression(existing.value, exprRaw, exprValue) {
			return existing, true
		}
		return envVarLookup{}, false
	}
	inherited, has := lookupInheritedEnvVar(rule.workflow, job, key)
	if !has || !envValueMatchesExpression(inherited.value, exprRaw, exprValue) {
		return envVarLookup{}, false
	}
	return inherited, true
}

func (rule *EnvPathInjectionRule) envVarNameForExpression(
	step *ast.Step,
	job *ast.Job,
	runScript string,
	baseName string,
	exprRaw string,
	exprValue string,
	pos *ast.Position,
	envVarsForYAML map[string]string,
) string {
	for suffix := 0; ; suffix++ {
		candidate := baseName
		if suffix > 0 {
			candidate = fmt.Sprintf("%s_%d", baseName, suffix+1)
		}

		key := strings.ToLower(candidate)
		if existing, exists := lookupEnvVar(step.Env, key); exists {
			// Linux shell env vars are case-sensitive; the AST keys
			// envs by lowercase name but preserves the original casing
			// in Name.Value. Always return the existing casing so a
			// later `$NAME` rewrite resolves to the real env var. Even
			// a matching step env cannot be reused after a script-level
			// assignment shadows it before the PATH write.
			if envValueMatchesExpression(existing.value, exprRaw, exprValue) && !assignmentShadowsUntrustedExpression(runScript, existing.actualName, exprRaw) {
				return existing.actualName
			}
			continue
		}
		// GitHub Actions env precedence is step > job > workflow. A
		// step-level env var with the same name would silently shadow
		// any inherited value for the rest of the step, redirecting any
		// command that consumes the inherited env var (curl, kubectl,
		// etc.) to the attacker-controlled body. Treat job-level and
		// workflow-level env entries as collisions, reusing the name
		// only when the inherited value is the exact same expression
		// the autofix would emit. Return the inherited variable's
		// actual casing for the same reason as the step lookup above.
		//
		// Reuse is gated on scriptAssignsShellName even when the inherited
		// value matches: a script-level `PR_BODY=/safe` would shadow the
		// inherited env at runtime, so a rewritten `$(realpath "$PR_BODY")`
		// would silently resolve to `/safe` instead of the inherited
		// expression. References without assignment (`$PR_BODY`,
		// `${PR_BODY:-/safe}`) do NOT block reuse — those refer to the
		// inherited value the same way the autofix would, and we WANT
		// the second wrap pass to cover them. Codex PR #514 regression.
		if inherited, has := lookupInheritedEnvVar(rule.workflow, job, key); has {
			// Reuse the inherited name when the value matches, EXCEPT
			// when a script-level assignment precedes any rewrite
			// location and would shadow the inherited env at that point.
			// A pure-presence check (scriptAssignsShellName) would also
			// suffix when the assignment happens AFTER all the rewrite
			// locations — in that case the earlier `$NAME` references on
			// GITHUB_PATH lines still read the inherited (untrusted)
			// value and the second pass should wrap them, which only
			// works if we reuse the inherited name. assignmentShadows-
			// UntrustedExpression bakes in the expression-specific,
			// order-aware logic.
			// Codex PR #514 regression. Casing is preserved by passing
			// inherited.actualName (case-sensitive bash names).
			if envValueMatchesExpression(inherited.value, exprRaw, exprValue) && !assignmentShadowsUntrustedExpression(runScript, inherited.actualName, exprRaw) {
				return inherited.actualName
			}
			continue
		}
		// When creating a new env var (not reusing an existing one with the
		// same expression), make sure the chosen name does not collide with
		// a shell variable the run script already assigns or references.
		// Otherwise the autofix would silently shadow the user's `$NAME`
		// reference with the new env var's attacker-controlled value.
		if scriptUsesShellName(runScript, candidate) {
			continue
		}

		step.Env.Vars[key] = &ast.EnvVar{
			Name:  &ast.String{Value: candidate, Pos: pos},
			Value: &ast.String{Value: exprValue, Pos: pos},
		}
		envVarsForYAML[candidate] = exprValue
		return candidate
	}
}

// envVarLookup carries the case-preserving name and raw value of an
// existing env var entry. actualName falls back to the lookup key only
// when the entry stores no Name.Value (defensive — the parser should
// always populate it).
type envVarLookup struct {
	actualName string
	value      string
}

func lookupEnvVar(env *ast.Env, key string) (envVarLookup, bool) {
	if env == nil || env.Vars == nil {
		return envVarLookup{}, false
	}
	ev, ok := env.Vars[key]
	if !ok {
		return envVarLookup{}, false
	}
	out := envVarLookup{actualName: key}
	if ev != nil {
		if ev.Name != nil && ev.Name.Value != "" {
			out.actualName = ev.Name.Value
		}
		if ev.Value != nil {
			out.value = ev.Value.Value
		}
	}
	return out, true
}

func envValueMatchesExpression(value, exprRaw, exprValue string) bool {
	if value == exprValue {
		return true
	}
	trimmed := strings.TrimSpace(value)
	matches := taintGhExprPattern.FindAllStringSubmatchIndex(trimmed, -1)
	if len(matches) != 1 {
		return false
	}
	match := matches[0]
	if len(match) < 4 || match[0] != 0 || match[1] != len(trimmed) {
		return false
	}
	return normalizeExpression(trimmed[match[2]:match[3]]) == normalizeExpression(exprRaw)
}

// lookupInheritedEnvVar walks job.Env then workflow.Env in GitHub Actions
// precedence order and returns the first matching entry. The lookup is
// keyed by the already-lowercased candidate name.
func lookupInheritedEnvVar(workflow *ast.Workflow, job *ast.Job, key string) (envVarLookup, bool) {
	if job != nil {
		if lk, ok := lookupEnvVar(job.Env, key); ok {
			return lk, true
		}
	}
	if workflow != nil {
		if lk, ok := lookupEnvVar(workflow.Env, key); ok {
			return lk, true
		}
	}
	return envVarLookup{}, false
}

// scriptUsesShellName reports whether the run script assigns to or
// references a shell variable with the given name. GitHub Actions
// `${{ ... }}` expressions are stripped first so they cannot
// false-positive on path components like `${{ github.event.NAME }}`.
//
// Detection uses the bash AST when the sanitized script parses cleanly:
// every ParamExp `Param.Value` and Assign `Name.Value` is collected, so
// all parameter-expansion shapes are recognized — `${NAME}`,
// `${NAME:-default}`, `${NAME:+alt}`, `${NAME#prefix}`, `${NAME%suffix}`,
// `${NAME/pat/repl}`, `${NAME^^}`, `${#NAME}`, `${!NAME}`, etc. — plus
// plain `$NAME` and `NAME=...` (including `export NAME=...`,
// `local NAME=...`). On parse failure (best-effort), falls back to a
// regex that catches the common `${NAME}`, `$NAME`, and `NAME=` forms.
//
// Used by envVarNameForExpression to keep the autofix from generating
// an env var name that would shadow a script-level shell variable.
func scriptUsesShellName(script, name string) bool {
	if name == "" || script == "" {
		return false
	}
	sanitized, _ := sanitizeForShellParse(script)

	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(sanitized), "")
	if err != nil || file == nil {
		return scriptUsesShellNameRegex(sanitized, name)
	}

	var found bool
	syntax.Walk(file, func(node syntax.Node) bool {
		if found || node == nil {
			return false
		}
		if _, ok := shellAssignmentOffset(node, name); ok {
			found = true
			return false
		}
		if x, ok := node.(*syntax.ParamExp); ok {
			if x.Param != nil && x.Param.Value == name {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// assignmentShadowsUntrustedExpression reports whether the run script
// assigns to `name` BEFORE a PATH-write occurrence of the target
// `${{ ... }}` expression appears. Order matters: when the assignment
// happens AFTER all rewrite positions, the autofix's rewrites at those
// positions still read the inherited (untrusted) value — so reuse is safe
// and we want to wrap them with realpath. When the assignment precedes at
// least one rewrite position, that expression's rewrite would resolve the
// shadowed local value at runtime — semantically wrong — so the caller must
// suffix to a fresh helper name. Reported by codex on PR #514.
//
// Implementation: sanitize `${{ ... }}` to same-length placeholders so bash
// can parse the script, collect assignment offsets with their shell scope,
// then ask whether each PATH-write occurrence is in a scope where a previous
// assignment is visible. Unrelated GitHub expressions, same-expression
// occurrences outside PATH writes, assignments in non-propagating subshells,
// pipeline/background elements, and uncalled function-body assignments must
// not force suffixing.
func assignmentShadowsUntrustedExpression(script, name, exprRaw string) bool {
	if name == "" || script == "" || exprRaw == "" {
		return false
	}
	targetOffsets := githubPathExpressionOffsets(script, exprRaw)
	if len(targetOffsets) == 0 {
		return false
	}

	analysis, ok := newShellNameShadowAnalysis(script, name)
	if !ok {
		// Conservative on parse failure: any assignment forces a suffix.
		return scriptAssignsShellName(script, name)
	}

	// If any target `${{ ... }}` occurrence is in a shell scope where an
	// earlier assignment to name is visible, that expression's rewrite
	// would resolve the shadowed value. Assignments inside subshells,
	// command substitutions, process substitutions, pipelines, and
	// background jobs are only visible in that nested scope; they do not
	// shadow later parent-shell writes.
	for _, offset := range targetOffsets {
		if analysis.shadowedAt(offset) {
			return true
		}
	}
	return false
}

type shellNameShadowAnalysis struct {
	assignments   []shellAssignmentRef
	scopes        []shellScopeRange
	functions     []shellFunctionRef
	functionCalls []shellFunctionCallRef
}

type shellAssignmentRef struct {
	offset int
	scope  []int
}

type shellScopeRange struct {
	start int
	end   int
	path  []int
}

type shellFunctionRef struct {
	id              int
	names           []string
	start           int
	end             int
	definitionScope []int
	bodyScope       []int
}

type shellFunctionCallRef struct {
	name               string
	offset             int
	scope              []int
	assignsNameLocally bool
}

type functionShadowInfo struct {
	assignsNameGlobally            bool
	assignsNameThroughCommandLocal bool
}

type shellFunctionInvocationState struct {
	offset   int
	scope    []int
	shadowed bool
}

func newShellNameShadowAnalysis(script, name string) (*shellNameShadowAnalysis, bool) {
	if name == "" || script == "" {
		return &shellNameShadowAnalysis{}, true
	}
	sanitized := sanitizeForShellParsePreservingLength(script)
	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(sanitized), "")
	if err != nil || file == nil {
		return nil, false
	}

	analysis := &shellNameShadowAnalysis{}
	scopePath := []int{}
	nodeFrames := []int{}
	functionsByScope := make(map[string]map[string]functionShadowInfo)
	pipelineStmtScopeIDs := make(map[*syntax.Stmt]int)
	nextScopeID := 1
	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil {
			if len(nodeFrames) == 0 {
				return true
			}
			openedScopeID := nodeFrames[len(nodeFrames)-1]
			nodeFrames = nodeFrames[:len(nodeFrames)-1]
			if openedScopeID != 0 && len(scopePath) > 0 {
				scopePath = scopePath[:len(scopePath)-1]
			}
			return true
		}

		openedScopeID := 0
		if stmt, ok := node.(*syntax.Stmt); ok {
			scopeID := 0
			if id, ok := pipelineStmtScopeIDs[stmt]; ok {
				scopeID = id
			} else if stmt.Background {
				scopeID = nextScopeID
				nextScopeID++
			}
			if scopeID != 0 {
				openedScopeID = scopeID
				scopePath = append(scopePath, openedScopeID)
				analysis.scopes = append(analysis.scopes, shellScopeRange{
					start: int(stmt.Pos().Offset()),
					end:   int(stmt.End().Offset()),
					path:  cloneIntSlice(scopePath),
				})
			}
		}
		if binary, ok := node.(*syntax.BinaryCmd); ok && isPipelineBinaryCmd(binary) {
			registerPipelineElementScopes(binary, pipelineStmtScopeIDs, &nextScopeID)
		}
		var funcNames []string
		var funcDefinitionScope []int
		if fn, ok := node.(*syntax.FuncDecl); ok {
			shadowInfo := functionBodyNameShadowInfo(fn, name)
			funcNames = funcDeclNames(fn)
			funcDefinitionScope = cloneIntSlice(scopePath)
			for _, funcName := range funcNames {
				recordFunctionShadowInfo(functionsByScope, scopePath, funcName, shadowInfo)
			}
		}
		if opensNestedShellScope(node) {
			nestedScopeID := nextScopeID
			nextScopeID++
			scopePath = append(scopePath, nestedScopeID)
			analysis.scopes = append(analysis.scopes, shellScopeRange{
				start: int(node.Pos().Offset()),
				end:   int(node.End().Offset()),
				path:  cloneIntSlice(scopePath),
			})
			if len(funcNames) > 0 {
				analysis.functions = append(analysis.functions, shellFunctionRef{
					id:              len(analysis.functions),
					names:           append([]string(nil), funcNames...),
					start:           int(node.Pos().Offset()),
					end:             int(node.End().Offset()),
					definitionScope: funcDefinitionScope,
					bodyScope:       cloneIntSlice(scopePath),
				})
			}
			openedScopeID = nestedScopeID
		}
		nodeFrames = append(nodeFrames, openedScopeID)

		if off, ok := persistentShellAssignmentOffset(node, name); ok {
			analysis.assignments = append(analysis.assignments, shellAssignmentRef{
				offset: off,
				scope:  cloneIntSlice(scopePath),
			})
		}
		if call, ok := node.(*syntax.CallExpr); ok {
			if callName := callExprName(call); callName != "" {
				analysis.functionCalls = append(analysis.functionCalls, shellFunctionCallRef{
					name:               callName,
					offset:             int(call.Pos().Offset()),
					scope:              cloneIntSlice(scopePath),
					assignsNameLocally: callHasAssignmentPrefix(call, name),
				})
			}
			if functionCallAssignsNameGlobally(call, functionsByScope, scopePath, name) {
				analysis.assignments = append(analysis.assignments, shellAssignmentRef{
					offset: int(call.Pos().Offset()),
					scope:  cloneIntSlice(scopePath),
				})
			}
		}
		return true
	})
	return analysis, true
}

func isPipelineBinaryCmd(binary *syntax.BinaryCmd) bool {
	return binary != nil && (binary.Op == syntax.Pipe || binary.Op == syntax.PipeAll)
}

func registerPipelineElementScopes(binary *syntax.BinaryCmd, stmtScopeIDs map[*syntax.Stmt]int, nextScopeID *int) {
	if binary == nil {
		return
	}
	registerPipelineStmtScope(binary.X, stmtScopeIDs, nextScopeID)
	registerPipelineStmtScope(binary.Y, stmtScopeIDs, nextScopeID)
}

func registerPipelineStmtScope(stmt *syntax.Stmt, stmtScopeIDs map[*syntax.Stmt]int, nextScopeID *int) {
	if stmt == nil {
		return
	}
	if binary, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && isPipelineBinaryCmd(binary) {
		registerPipelineElementScopes(binary, stmtScopeIDs, nextScopeID)
		return
	}
	if _, exists := stmtScopeIDs[stmt]; exists {
		return
	}
	stmtScopeIDs[stmt] = *nextScopeID
	*nextScopeID = *nextScopeID + 1
}

func opensNestedShellScope(node syntax.Node) bool {
	switch node.(type) {
	case *syntax.Subshell, *syntax.CmdSubst, *syntax.ProcSubst, *syntax.FuncDecl:
		return true
	}
	return false
}

func funcDeclNames(fn *syntax.FuncDecl) []string {
	if fn == nil {
		return nil
	}
	var names []string
	if fn.Name != nil && fn.Name.Value != "" {
		names = append(names, fn.Name.Value)
	}
	for _, name := range fn.Names {
		if name != nil && name.Value != "" {
			names = append(names, name.Value)
		}
	}
	return names
}

func recordFunctionShadowInfo(functionsByScope map[string]map[string]functionShadowInfo, scope []int, name string, info functionShadowInfo) {
	if name == "" {
		return
	}
	key := shellScopeKey(scope)
	if functionsByScope[key] == nil {
		functionsByScope[key] = make(map[string]functionShadowInfo)
	}
	functionsByScope[key][name] = info
}

func functionCallAssignsNameGlobally(call *syntax.CallExpr, functionsByScope map[string]map[string]functionShadowInfo, scope []int, name string) bool {
	cmd := callExprName(call)
	if cmd == "" {
		return false
	}
	for i := len(scope); i >= 0; i-- {
		if info, ok := functionsByScope[shellScopeKey(scope[:i])][cmd]; ok {
			if callHasAssignmentPrefix(call, name) {
				return info.assignsNameThroughCommandLocal
			}
			return info.assignsNameGlobally
		}
	}
	return false
}

func callExprName(call *syntax.CallExpr) string {
	if call == nil || len(call.Args) == 0 {
		return ""
	}
	return wordLitValue(call.Args[0])
}

func shellFunctionHasName(fn shellFunctionRef, name string) bool {
	for _, candidate := range fn.names {
		if candidate == name {
			return true
		}
	}
	return false
}

func functionBodyAssignsNameGlobally(fn *syntax.FuncDecl, name string) bool {
	return functionBodyNameShadowInfo(fn, name).assignsNameGlobally
}

func functionBodyNameShadowInfo(fn *syntax.FuncDecl, name string) functionShadowInfo {
	var info functionShadowInfo
	if fn == nil || fn.Body == nil || name == "" {
		return info
	}
	var localName bool
	syntax.Walk(fn.Body, func(node syntax.Node) bool {
		if (info.assignsNameGlobally && info.assignsNameThroughCommandLocal) || node == nil {
			return false
		}
		switch x := node.(type) {
		case *syntax.FuncDecl, *syntax.Subshell, *syntax.CmdSubst, *syntax.ProcSubst:
			return false
		case *syntax.DeclClause:
			if declClauseAssignsNameThroughCommandLocal(x, name) {
				info.assignsNameGlobally = true
				info.assignsNameThroughCommandLocal = true
			} else if !localName && declClauseAssignsNameGlobally(x, name) {
				info.assignsNameGlobally = true
			} else if declClauseDeclaresLocalName(x, name) {
				localName = true
			}
			return false
		}
		if localName {
			return true
		}
		if _, ok := persistentShellAssignmentOffset(node, name); ok {
			info.assignsNameGlobally = true
			return false
		}
		return true
	})
	return info
}

func declClauseAssignsNameGlobally(decl *syntax.DeclClause, name string) bool {
	if decl == nil || decl.Variant == nil || name == "" {
		return false
	}
	variant := decl.Variant.Value
	if variant == "declare" || variant == "typeset" || variant == "local" {
		if !declClauseHasOption(decl, 'g') {
			return false
		}
	} else if variant != "export" && variant != "readonly" {
		return false
	}
	return declClauseHasName(decl, name)
}

func declClauseAssignsNameThroughCommandLocal(decl *syntax.DeclClause, name string) bool {
	if decl == nil || decl.Variant == nil || name == "" {
		return false
	}
	switch decl.Variant.Value {
	case "declare", "typeset", "local":
		return declClauseHasOption(decl, 'g') && declClauseHasName(decl, name)
	}
	return false
}

func declClauseDeclaresLocalName(decl *syntax.DeclClause, name string) bool {
	if decl == nil || decl.Variant == nil || name == "" {
		return false
	}
	switch decl.Variant.Value {
	case "local":
		return !declClauseHasOption(decl, 'g') && declClauseHasName(decl, name)
	case "declare", "typeset":
		return !declClauseHasOption(decl, 'g') && declClauseHasName(decl, name)
	}
	return false
}

func declClauseHasName(decl *syntax.DeclClause, name string) bool {
	for _, arg := range decl.Args {
		if arg != nil && arg.Name != nil && arg.Name.Value == name {
			return true
		}
	}
	return false
}

func declClauseHasOption(decl *syntax.DeclClause, option byte) bool {
	for _, arg := range decl.Args {
		if arg == nil || !arg.Naked || arg.Name != nil || arg.Value == nil {
			continue
		}
		value := wordLitValue(arg.Value)
		if len(value) < 2 || value[0] != '-' {
			continue
		}
		if strings.ContainsRune(value[1:], rune(option)) {
			return true
		}
	}
	return false
}

func (analysis *shellNameShadowAnalysis) shadowedAt(offset int) bool {
	if analysis == nil {
		return false
	}
	targetScope := analysis.scopeAt(offset)
	targetFn := analysis.functionAt(offset)
	for _, assignment := range analysis.assignments {
		if assignment.offset < offset && shellScopeCanShadow(assignment.scope, targetScope) {
			if targetFn != nil && !shellScopeCanShadow(targetFn.bodyScope, assignment.scope) {
				continue
			}
			return true
		}
	}
	if targetFn != nil && analysis.functionBodyShadowedAtCall(*targetFn) {
		return true
	}
	return false
}

func (analysis *shellNameShadowAnalysis) functionAt(offset int) *shellFunctionRef {
	if analysis == nil {
		return nil
	}
	var found *shellFunctionRef
	for i := range analysis.functions {
		fn := &analysis.functions[i]
		if fn.start <= offset && offset < fn.end && (found == nil || len(fn.bodyScope) > len(found.bodyScope)) {
			found = fn
		}
	}
	return found
}

func (analysis *shellNameShadowAnalysis) functionBodyShadowedAtCall(fn shellFunctionRef) bool {
	for _, state := range analysis.functionInvocationStates(fn, fn.start, nil) {
		if state.shadowed {
			return true
		}
	}
	return false
}

func (analysis *shellNameShadowAnalysis) functionInvocationStates(fn shellFunctionRef, requiredStart int, stack map[int]bool) []shellFunctionInvocationState {
	if analysis == nil || stack[fn.id] {
		return nil
	}
	if stack == nil {
		stack = make(map[int]bool)
	}
	stack[fn.id] = true
	defer delete(stack, fn.id)

	var states []shellFunctionInvocationState
	for _, call := range analysis.functionCalls {
		if !shellFunctionHasName(fn, call.name) {
			continue
		}
		caller := analysis.functionAt(call.offset)
		if caller == nil {
			if call.offset <= requiredStart || !analysis.callResolvesToFunction(call, fn, call.offset, call.scope) {
				continue
			}
			states = append(states, shellFunctionInvocationState{
				offset:   call.offset,
				scope:    cloneIntSlice(call.scope),
				shadowed: analysis.callSiteShadowsName(call),
			})
			continue
		}

		callerRequiredStart := requiredStart
		if fn.start > callerRequiredStart {
			callerRequiredStart = fn.start
		}
		for _, callerState := range analysis.functionInvocationStates(*caller, callerRequiredStart, stack) {
			if !analysis.functionResolvesAt(call.name, fn, callerState.offset, callerState.scope) {
				continue
			}
			states = append(states, shellFunctionInvocationState{
				offset:   callerState.offset,
				scope:    cloneIntSlice(callerState.scope),
				shadowed: callerState.shadowed || analysis.callSiteShadowsName(call),
			})
		}
	}
	return states
}

func (analysis *shellNameShadowAnalysis) callResolvesToFunction(call shellFunctionCallRef, fn shellFunctionRef, runtimeOffset int, runtimeScope []int) bool {
	return analysis.functionResolvesAt(call.name, fn, runtimeOffset, runtimeScope)
}

func (analysis *shellNameShadowAnalysis) functionResolvesAt(name string, fn shellFunctionRef, runtimeOffset int, runtimeScope []int) bool {
	resolved := analysis.functionNamedAt(name, runtimeOffset, runtimeScope)
	return resolved != nil && resolved.id == fn.id
}

func (analysis *shellNameShadowAnalysis) functionNamedAt(name string, runtimeOffset int, runtimeScope []int) *shellFunctionRef {
	if analysis == nil || name == "" {
		return nil
	}
	var resolved *shellFunctionRef
	for i := range analysis.functions {
		fn := &analysis.functions[i]
		if fn.start >= runtimeOffset || !shellFunctionHasName(*fn, name) {
			continue
		}
		if !shellScopeCanShadow(fn.definitionScope, runtimeScope) {
			continue
		}
		if resolved == nil || fn.start > resolved.start {
			resolved = fn
		}
	}
	return resolved
}

func (analysis *shellNameShadowAnalysis) callSiteShadowsName(call shellFunctionCallRef) bool {
	if call.assignsNameLocally {
		return true
	}
	caller := analysis.functionAt(call.offset)
	for _, assignment := range analysis.assignments {
		if assignment.offset < call.offset && shellScopeCanShadow(assignment.scope, call.scope) {
			if caller != nil && !shellScopeCanShadow(caller.bodyScope, assignment.scope) {
				continue
			}
			return true
		}
	}
	return false
}

func (analysis *shellNameShadowAnalysis) scopeAt(offset int) []int {
	if analysis == nil {
		return nil
	}
	var scope []int
	for _, candidate := range analysis.scopes {
		if candidate.start <= offset && offset < candidate.end && len(candidate.path) > len(scope) {
			scope = candidate.path
		}
	}
	return scope
}

func shellScopeCanShadow(assignmentScope, targetScope []int) bool {
	if len(assignmentScope) > len(targetScope) {
		return false
	}
	for i := range assignmentScope {
		if assignmentScope[i] != targetScope[i] {
			return false
		}
	}
	return true
}

func shellScopeKey(scope []int) string {
	return fmt.Sprint(scope)
}

func cloneIntSlice(in []int) []int {
	if len(in) == 0 {
		return nil
	}
	out := make([]int, len(in))
	copy(out, in)
	return out
}

func sanitizeForShellParsePreservingLength(script string) string {
	return taintGhExprPattern.ReplaceAllStringFunc(script, func(match string) string {
		return strings.Repeat("_", len(match))
	})
}

func githubPathExpressionOffsets(script, exprRaw string) []int {
	var offsets []int
	targetExpr := strings.TrimSpace(exprRaw)
	if script == "" || targetExpr == "" {
		return offsets
	}

	lineStart := 0
	execPathActive := false
	for _, line := range strings.Split(script, "\n") {
		pathWriteRanges, nextExecPathActive := githubPathWriteLineRangesWithExecState(line, execPathActive)
		matches := taintGhExprPattern.FindAllStringSubmatchIndex(line, -1)
		for _, match := range matches {
			if len(match) < 4 {
				continue
			}
			if strings.TrimSpace(line[match[2]:match[3]]) != targetExpr {
				continue
			}
			if !offsetInTextRanges(match[0], pathWriteRanges) {
				continue
			}
			offsets = append(offsets, lineStart+match[0])
		}
		execPathActive = nextExecPathActive
		lineStart += len(line) + 1
	}
	return offsets
}

type textRange struct {
	start int
	end   int
}

// githubPathWriteLineRanges returns byte ranges for shell statements that write
// to $GITHUB_PATH. It deliberately avoids using the whole physical line, so
// neighboring commands joined with `;`, `&&`, `||`, or compound-command
// internals are not rewritten just because another command appends to PATH. If
// parsing fails, it falls back to the full line to preserve conservative
// behavior.
func githubPathWriteLineRanges(line string) []textRange {
	ranges, _ := githubPathWriteLineRangesWithExecState(line, false)
	return ranges
}

func githubPathWriteLineRangesWithExecState(line string, execPathActive bool) ([]textRange, bool) {
	hasGitHubPathRedirect := githubPathPattern.MatchString(line)
	if line == "" || (!execPathActive && !hasGitHubPathRedirect) {
		return nil, execPathActive
	}

	sanitized := sanitizeForShellParsePreservingLength(line)
	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(sanitized), "")
	if err != nil || file == nil {
		if execPathActive || hasGitHubPathRedirect {
			return []textRange{{start: 0, end: len(line)}}, execPathActive
		}
		return nil, execPathActive
	}

	var ranges []textRange
	execPathActiveByScope := map[int]bool{0: execPathActive}
	scopeStack := []int{0}
	nodeFrames := []int{}
	pipelineStmtScopeIDs := make(map[*syntax.Stmt]int)
	nextScopeID := 1
	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil {
			if len(nodeFrames) == 0 {
				return true
			}
			openedScopeID := nodeFrames[len(nodeFrames)-1]
			nodeFrames = nodeFrames[:len(nodeFrames)-1]
			if openedScopeID != 0 && len(scopeStack) > 1 {
				scopeStack = scopeStack[:len(scopeStack)-1]
			}
			return true
		}

		openedScopeID := 0
		if stmt, ok := node.(*syntax.Stmt); ok {
			scopeID := 0
			if id, ok := pipelineStmtScopeIDs[stmt]; ok {
				scopeID = id
			} else if stmt.Background {
				scopeID = nextScopeID
				nextScopeID++
			}
			if scopeID != 0 {
				openedScopeID = scopeID
				parentScopeID := scopeStack[len(scopeStack)-1]
				execPathActiveByScope[scopeID] = execPathActiveByScope[parentScopeID]
				scopeStack = append(scopeStack, scopeID)
			}
		}
		if binary, ok := node.(*syntax.BinaryCmd); ok && isPipelineBinaryCmd(binary) {
			registerPipelineElementScopes(binary, pipelineStmtScopeIDs, &nextScopeID)
		}
		if opensExecNestedShellScope(node) {
			openedScopeID = nextScopeID
			nextScopeID++
			parentScopeID := scopeStack[len(scopeStack)-1]
			execPathActiveByScope[openedScopeID] = nestedExecInitialState(node, execPathActiveByScope[parentScopeID])
			scopeStack = append(scopeStack, openedScopeID)
		}
		nodeFrames = append(nodeFrames, openedScopeID)

		stmt, ok := node.(*syntax.Stmt)
		if !ok || stmt == nil {
			return true
		}
		scopeID := scopeStack[len(scopeStack)-1]
		scopeExecPathActive := execPathActiveByScope[scopeID]
		if scopeExecPathActive && stmtCanWriteInheritedStdout(stmt) {
			if r, ok := nodeTextRange(line, stmt); ok {
				ranges = append(ranges, r)
			}
		}
		if stmtHasGitHubPathAppend(line, stmt) {
			if r, ok := nodeTextRange(line, stmt); ok {
				ranges = append(ranges, r)
			}
		}
		if changed, nextExecPathActive := stmtPersistentExecStdoutState(line, stmt); changed {
			execPathActiveByScope[scopeID] = nextExecPathActive
		}
		return true
	})
	ranges = normalizeTextRanges(ranges)
	return ranges, execPathActiveByScope[0]
}

func opensExecNestedShellScope(node syntax.Node) bool {
	switch node.(type) {
	case *syntax.Subshell, *syntax.CmdSubst, *syntax.ProcSubst, *syntax.FuncDecl:
		return true
	}
	return false
}

func nestedExecInitialState(node syntax.Node, parentExecPathActive bool) bool {
	if _, ok := node.(*syntax.FuncDecl); ok {
		return false
	}
	return parentExecPathActive
}

func stmtPersistentExecStdoutState(line string, stmt *syntax.Stmt) (bool, bool) {
	if stmt == nil || !stmtIsRedirectOnlyExec(stmt) {
		return false, false
	}
	var changed bool
	var execPathActive bool
	for _, redir := range stmt.Redirs {
		if redir == nil || !redirAffectsStdout(redir) {
			continue
		}
		changed = true
		if redirAppendsGitHubPath(line, redir) {
			execPathActive = true
		} else {
			execPathActive = false
		}
	}
	return changed, execPathActive
}

func stmtIsRedirectOnlyExec(stmt *syntax.Stmt) bool {
	if stmt == nil {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || callExprName(call) != "exec" {
		return false
	}
	for _, arg := range call.Args[1:] {
		value := wordLitValue(arg)
		if value == "" || !strings.HasPrefix(value, "-") {
			return false
		}
	}
	return true
}

func stmtRedirectsStdout(stmt *syntax.Stmt) bool {
	if stmt == nil {
		return false
	}
	for _, redir := range stmt.Redirs {
		if redir != nil && redirAffectsStdout(redir) {
			return true
		}
	}
	return false
}

func stmtCanWriteInheritedStdout(stmt *syntax.Stmt) bool {
	if stmt == nil || stmtRedirectsStdout(stmt) || stmtIsFunctionDecl(stmt) {
		return false
	}
	return true
}

func stmtIsFunctionDecl(stmt *syntax.Stmt) bool {
	if stmt == nil {
		return false
	}
	_, ok := stmt.Cmd.(*syntax.FuncDecl)
	return ok
}

func redirAffectsStdout(redir *syntax.Redirect) bool {
	if redir == nil {
		return false
	}
	switch redir.Op {
	case syntax.RdrAll, syntax.RdrAllClob, syntax.AppAll, syntax.AppAllClob:
		return true
	case syntax.RdrOut, syntax.AppOut, syntax.DplOut, syntax.RdrClob, syntax.AppClob:
		return redir.N == nil || redir.N.Value == "1"
	}
	return false
}

func redirAppendsGitHubPath(line string, redir *syntax.Redirect) bool {
	if redir == nil || (redir.Op != syntax.AppOut && redir.Op != syntax.AppAll && redir.Op != syntax.AppAllClob) {
		return false
	}
	if r, ok := nodeTextRange(line, redir); ok && githubPathPattern.MatchString(line[r.start:r.end]) {
		return true
	}
	return false
}

func stmtHasGitHubPathAppend(line string, stmt *syntax.Stmt) bool {
	if stmt == nil {
		return false
	}
	for _, redir := range stmt.Redirs {
		if redirAppendsGitHubPath(line, redir) {
			return true
		}
	}
	return false
}

func nodeTextRange(line string, node syntax.Node) (textRange, bool) {
	if node == nil || !node.Pos().IsValid() || !node.End().IsValid() {
		return textRange{}, false
	}
	start := int(node.Pos().Offset())
	end := int(node.End().Offset())
	if start < 0 || end > len(line) || start >= end {
		return textRange{}, false
	}
	return textRange{start: start, end: end}, true
}

func normalizeTextRanges(ranges []textRange) []textRange {
	if len(ranges) <= 1 {
		return ranges
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start != ranges[j].start {
			return ranges[i].start < ranges[j].start
		}
		return ranges[i].end > ranges[j].end
	})

	normalized := ranges[:0]
	for _, r := range ranges {
		if r.start < 0 || r.start >= r.end {
			continue
		}
		if len(normalized) > 0 {
			last := &normalized[len(normalized)-1]
			if r.start >= last.start && r.end <= last.end {
				continue
			}
			if r.start < last.end {
				if r.end > last.end {
					last.end = r.end
				}
				continue
			}
		}
		normalized = append(normalized, r)
	}
	return normalized
}

func offsetInTextRanges(offset int, ranges []textRange) bool {
	for _, r := range ranges {
		if r.start <= offset && offset < r.end {
			return true
		}
	}
	return false
}

func githubExpressionInRanges(text, exprRaw string, ranges []textRange) bool {
	targetExpr := normalizeExpression(exprRaw)
	if targetExpr == "" || len(ranges) == 0 {
		return false
	}
	matches := taintGhExprPattern.FindAllStringSubmatchIndex(text, -1)
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}
		if normalizeExpression(text[match[2]:match[3]]) != targetExpr {
			continue
		}
		if offsetInTextRanges(match[0], ranges) {
			return true
		}
	}
	return false
}

func replaceGitHubExpression(text, exprRaw, replacement string) string {
	targetExpr := normalizeExpression(exprRaw)
	if targetExpr == "" || text == "" {
		return text
	}
	return taintGhExprPattern.ReplaceAllStringFunc(text, func(match string) string {
		parts := taintGhExprPattern.FindStringSubmatch(match)
		if len(parts) < 2 || normalizeExpression(parts[1]) != targetExpr {
			return match
		}
		return replacement
	})
}

func replaceInTextRanges(line string, ranges []textRange, replace func(segment string, segmentStart int) string) string {
	if line == "" || len(ranges) == 0 || replace == nil {
		return line
	}
	ranges = append([]textRange(nil), ranges...)
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start > ranges[j].start })

	out := line
	for _, r := range ranges {
		if r.start < 0 || r.end > len(out) || r.start >= r.end {
			continue
		}
		out = out[:r.start] + replace(out[r.start:r.end], r.start) + out[r.end:]
	}
	return out
}

func lineAtOffsetWithStart(script string, offset int) (string, int) {
	if offset < 0 {
		offset = 0
	}
	if offset > len(script) {
		offset = len(script)
	}
	start := strings.LastIndex(script[:offset], "\n") + 1
	end := len(script)
	if rel := strings.Index(script[offset:], "\n"); rel >= 0 {
		end = offset + rel
	}
	return script[start:end], start
}

// scriptAssignsShellName reports whether the run script assigns to a
// shell variable with the given name. References (`$NAME`, `${NAME}`,
// `${NAME:-default}`, etc.) are intentionally NOT treated as
// assignments — they read the variable rather than bind it, so they
// do not shadow an inherited env value. Used by the inherited-env
// reuse path to keep a script-level `PR_BODY=/safe` from silently
// redirecting the autofix's `$(realpath "$PR_BODY")` rewrite to a
// shadowed local value while still allowing reuse when the script
// only references the inherited variable.
func scriptAssignsShellName(script, name string) bool {
	if name == "" || script == "" {
		return false
	}
	sanitized, _ := sanitizeForShellParse(script)

	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(sanitized), "")
	if err != nil || file == nil {
		return scriptAssignsShellNameRegex(sanitized, name)
	}

	var found bool
	syntax.Walk(file, func(node syntax.Node) bool {
		if found || node == nil {
			return false
		}
		if _, ok := persistentShellAssignmentOffset(node, name); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

// scriptAssignsShellNameRegex is the parse-failure fallback for
// scriptAssignsShellName. Matches `NAME=` (with `export NAME=`,
// `local NAME=`, etc. covered by the `[^A-Za-z0-9_.]` boundary).
// Does not catch `read NAME` / `mapfile NAME` built-ins; on parse
// failure those slip past, but parse failures should be rare.
func scriptAssignsShellNameRegex(sanitized, name string) bool {
	q := regexp.QuoteMeta(name)
	re := regexp.MustCompile(`(?:^|[^A-Za-z0-9_.])` + q + `=`)
	return re.MatchString(sanitized)
}

// callAssignsName reports whether a CallExpr is a built-in command that
// assigns to the named variable (e.g., `read NAME`, `mapfile NAME`,
// `readarray NAME`).
func callAssignsName(call *syntax.CallExpr, name string) bool {
	if len(call.Args) < 1 {
		return false
	}
	cmd := wordLitValue(call.Args[0])
	switch cmd {
	case "read":
		return readCallAssignsName(call.Args[1:], name)
	case "mapfile", "readarray":
		return mapfileCallAssignsName(call.Args[1:], name)
	}
	return false
}

// persistentShellAssignmentOffset reports assignments that persist in the
// current shell scope. Command-local prefixes like `NAME=value command` are
// intentionally ignored because bash applies them only to that simple command.
func persistentShellAssignmentOffset(node syntax.Node, name string) (int, bool) {
	if node == nil || name == "" {
		return 0, false
	}
	switch x := node.(type) {
	case *syntax.CallExpr:
		if off, ok := callPersistentAssignmentOffset(x, name); ok {
			return off, true
		}
		if callAssignsName(x, name) {
			return int(x.Pos().Offset()), true
		}
	case *syntax.DeclClause:
		return declClauseAssignmentOffset(x, name)
	case *syntax.WordIter:
		if x.Name != nil && x.Name.Value == name {
			return int(x.Name.Pos().Offset()), true
		}
	case *syntax.BinaryArithm:
		if arithmAssignsName(x, name) {
			return int(x.X.Pos().Offset()), true
		}
	case *syntax.UnaryArithm:
		if (x.Op == syntax.Inc || x.Op == syntax.Dec) && arithmExprName(x.X) == name {
			return int(x.X.Pos().Offset()), true
		}
	}
	return 0, false
}

func callPersistentAssignmentOffset(call *syntax.CallExpr, name string) (int, bool) {
	if call == nil || len(call.Args) > 0 {
		return 0, false
	}
	for _, assign := range call.Assigns {
		if off, ok := assignNameOffset(assign, name); ok {
			return off, true
		}
	}
	return 0, false
}

func callHasAssignmentPrefix(call *syntax.CallExpr, name string) bool {
	if call == nil || len(call.Args) == 0 {
		return false
	}
	for _, assign := range call.Assigns {
		if _, ok := assignNameOffset(assign, name); ok {
			return true
		}
	}
	return false
}

func declClauseAssignmentOffset(decl *syntax.DeclClause, name string) (int, bool) {
	if decl == nil {
		return 0, false
	}
	for _, arg := range decl.Args {
		if off, ok := assignNameOffset(arg, name); ok {
			return off, true
		}
	}
	return 0, false
}

func assignNameOffset(assign *syntax.Assign, name string) (int, bool) {
	if assign != nil && assign.Name != nil && assign.Name.Value == name {
		return int(assign.Pos().Offset()), true
	}
	return 0, false
}

// shellAssignmentOffset is a broader name-use detector used for collision
// avoidance. Unlike persistentShellAssignmentOffset, it includes command-local
// assignment prefixes because generating a same-named env var can still
// collide with user-authored shell names.
func shellAssignmentOffset(node syntax.Node, name string) (int, bool) {
	if node == nil || name == "" {
		return 0, false
	}
	switch x := node.(type) {
	case *syntax.Assign:
		return assignNameOffset(x, name)
	case *syntax.CallExpr:
		// Built-ins like `read NAME`, `mapfile NAME`, `readarray NAME`
		// bind the named variable but are represented as plain CallExpr
		// (not Assign) in the AST.
		if callAssignsName(x, name) {
			return int(x.Pos().Offset()), true
		}
	case *syntax.WordIter:
		// `for NAME in ...` and bash `select NAME in ...` both assign the
		// loop value to NAME before running the loop body.
		if x.Name != nil && x.Name.Value == name {
			return int(x.Name.Pos().Offset()), true
		}
	case *syntax.BinaryArithm:
		if arithmAssignsName(x, name) {
			return int(x.X.Pos().Offset()), true
		}
	case *syntax.UnaryArithm:
		if (x.Op == syntax.Inc || x.Op == syntax.Dec) && arithmExprName(x.X) == name {
			return int(x.X.Pos().Offset()), true
		}
	}
	return 0, false
}

func arithmAssignsName(expr *syntax.BinaryArithm, name string) bool {
	if expr == nil || arithmExprName(expr.X) != name {
		return false
	}
	switch expr.Op {
	case syntax.Assgn, syntax.AddAssgn, syntax.SubAssgn, syntax.MulAssgn,
		syntax.QuoAssgn, syntax.RemAssgn, syntax.AndAssgn, syntax.OrAssgn,
		syntax.XorAssgn, syntax.ShlAssgn, syntax.ShrAssgn, syntax.AndBoolAssgn,
		syntax.OrBoolAssgn, syntax.XorBoolAssgn, syntax.PowAssgn:
		return true
	}
	return false
}

func arithmExprName(expr syntax.ArithmExpr) string {
	if word, ok := expr.(*syntax.Word); ok {
		return wordLitValue(word)
	}
	return ""
}

func readCallAssignsName(args []*syntax.Word, name string) bool {
	arrayMode := false
	sawName := false
	for i := 0; i < len(args); i++ {
		v := wordLitValue(args[i])
		if v == "" {
			continue
		}
		if v == "--" {
			for _, arg := range args[i+1:] {
				if arrayMode {
					continue
				}
				sawName = true
				if wordLitValue(arg) == name {
					return true
				}
			}
			return !arrayMode && !sawName && name == "REPLY"
		}
		if strings.HasPrefix(v, "-") && v != "-" {
			assigned, consumedNext, arrayOption := readOptionAssignsName(v, name)
			if arrayOption {
				arrayMode = true
			}
			if assigned {
				return true
			} else if consumedNext {
				if arrayOption && i+1 < len(args) && wordLitValue(args[i+1]) == name {
					return true
				}
				i++
			}
			continue
		}
		if arrayMode {
			continue
		}
		sawName = true
		if v == name {
			return true
		}
	}
	return !arrayMode && !sawName && name == "REPLY"
}

func readOptionAssignsName(option, name string) (assigned bool, consumedNext bool, arrayOption bool) {
	for i := 1; i < len(option); i++ {
		opt := option[i]
		inlineArg := option[i+1:]
		switch opt {
		case 'a':
			if inlineArg != "" {
				return inlineArg == name, false, true
			}
			return false, true, true
		case 'd', 'i', 'n', 'N', 'p', 't', 'u':
			return false, inlineArg == "", false
		}
	}
	return false, false, false
}

func mapfileCallAssignsName(args []*syntax.Word, name string) bool {
	for i := 0; i < len(args); i++ {
		v := wordLitValue(args[i])
		if v == "" {
			continue
		}
		if v == "--" {
			return mapfileArrayOperandAssignsName(args[i+1:], name)
		}
		if strings.HasPrefix(v, "-") && v != "-" {
			if mapfileOptionConsumesNext(v) {
				i++
			}
			continue
		}
		return v == name
	}
	return name == "MAPFILE"
}

func mapfileArrayOperandAssignsName(args []*syntax.Word, name string) bool {
	for _, arg := range args {
		v := wordLitValue(arg)
		if v == "" {
			continue
		}
		return v == name
	}
	return name == "MAPFILE"
}

func mapfileOptionConsumesNext(option string) bool {
	for i := 1; i < len(option); i++ {
		opt := option[i]
		inlineArg := option[i+1:]
		switch opt {
		case 'd', 'n', 'O', 's', 'u', 'C', 'c':
			return inlineArg == ""
		}
	}
	return false
}

// wordLitValue returns the literal-string value of a Word when it is
// composed of plain Lits (and/or DblQuoted-wrapped Lits). Returns "" for
// Words containing expansions, command substitutions, etc.
func wordLitValue(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var b strings.Builder
	for _, p := range w.Parts {
		switch x := p.(type) {
		case *syntax.Lit:
			b.WriteString(x.Value)
		case *syntax.SglQuoted:
			b.WriteString(x.Value)
		case *syntax.DblQuoted:
			for _, inner := range x.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return ""
				}
				b.WriteString(lit.Value)
			}
		default:
			return ""
		}
	}
	return b.String()
}

// scriptUsesShellNameRegex is the best-effort fallback used when the
// shell parser cannot parse the sanitized run script. It catches the
// common shapes but does not understand all parameter-expansion
// operators. Prefer the AST path; this exists only so a parse error
// does not silently bypass the collision check.
func scriptUsesShellNameRegex(sanitized, name string) bool {
	q := regexp.QuoteMeta(name)
	re := regexp.MustCompile(
		`\$\{#?!?` + q + `(?:[}:#%/^,@]|$)` +
			`|\$` + q + `(?:[^A-Za-z0-9_]|$)` +
			`|(?:^|[^A-Za-z0-9_.])` + q + `=`,
	)
	return re.MatchString(sanitized)
}

// replaceShellEnvVarRef wraps every shell-level reference of envVarName
// on the given line with `$(realpath "<source>")`, preserving the
// original parameter-expansion shape so semantics survive. The parse-
// based path catches all forms — `$NAME`, `${NAME}`, `${NAME:-default}`,
// `${NAME:+alt}`, `${NAME#pre}`, `${NAME%suf}`, `${NAME/p/r}`,
// `${NAME^^}`, `${#NAME}`, `${!NAME}`, `${NAME[i]}`, etc. — by walking
// every ParamExp whose Param.Value matches and rewriting its byte range
// with the source-preserving wrap.
//
// Any leftover GitHub Actions `${{ ... }}` expression on the same line
// is replaced with a placeholder via sanitizeForShellParse before
// parsing, then restored afterwards. Without sanitization the bash
// parser fails on `${{ ... }}` (not valid bash) and the regex fallback
// kicks in, which misses expansion forms with operators — codex PR
// #514 regression where a line like
// `printf '%s\n%s\n%s\n' "${{ expr }}" "${NAME:-/safe}" "${{ other }}"
// >> "$GITHUB_PATH"` left the middle arg unwrapped because the
// trailing GH expression broke the bash parse.
//
// On parse failure (defensive), falls back to the regex form covering
// the common `$NAME` / `${NAME}` shapes.
func replaceShellEnvVarRef(line, envVarName string) string {
	return replaceShellEnvVarRefBeforeOffset(line, envVarName, len(line))
}

func replaceUnshadowedShellEnvVarRef(line, envVarName string, lineStart int, analysis *shellNameShadowAnalysis) string {
	if envVarName == "" || line == "" || analysis == nil {
		return line
	}
	sanitized := sanitizeForShellParsePreservingLength(line)

	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(sanitized), "")
	if err != nil || file == nil {
		return line
	}

	type rng struct{ start, end int }
	var ranges []rng
	syntax.Walk(file, func(node syntax.Node) bool {
		if pe, ok := node.(*syntax.ParamExp); ok {
			if pe.Param != nil && pe.Param.Value == envVarName {
				start := int(pe.Pos().Offset())
				if !analysis.shadowedAt(lineStart + start) {
					ranges = append(ranges, rng{
						start: start,
						end:   int(pe.End().Offset()),
					})
				}
			}
		}
		return true
	})
	if len(ranges) == 0 {
		return line
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start > ranges[j].start })

	out := line
	for _, r := range ranges {
		if r.start < 0 || r.end > len(out) || r.start >= r.end {
			continue
		}
		src := out[r.start:r.end]
		out = out[:r.start] + `$(realpath "` + src + `")` + out[r.end:]
	}
	return out
}

func replaceShellEnvVarRefBeforeOffset(line, envVarName string, limit int) string {
	if envVarName == "" || line == "" {
		return line
	}
	if limit <= 0 {
		return line
	}
	if limit < len(line) {
		return replaceShellEnvVarRef(line[:limit], envVarName) + line[limit:]
	}

	// Strip `${{ ... }}` so bash can parse the line. Placeholders are
	// word-only (no `$`/`{`) so they appear as plain literals in the
	// AST and never accidentally match envVarName.
	sanitized, exprMap := sanitizeForShellParse(line)

	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(sanitized), "")
	if err != nil || file == nil {
		return replaceShellEnvVarRefRegex(line, envVarName)
	}

	// Collect every ParamExp byte range that references envVarName.
	type rng struct{ start, end int }
	var ranges []rng
	syntax.Walk(file, func(node syntax.Node) bool {
		if pe, ok := node.(*syntax.ParamExp); ok {
			if pe.Param != nil && pe.Param.Value == envVarName {
				ranges = append(ranges, rng{
					start: int(pe.Pos().Offset()),
					end:   int(pe.End().Offset()),
				})
			}
		}
		return true
	})
	if len(ranges) == 0 {
		return line
	}
	// Rightmost-first so earlier offsets remain valid as we splice.
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start > ranges[j].start })

	out := sanitized
	for _, r := range ranges {
		if r.start < 0 || r.end > len(out) || r.start >= r.end {
			continue
		}
		src := out[r.start:r.end]
		out = out[:r.start] + `$(realpath "` + src + `")` + out[r.end:]
	}
	// Restore the GitHub expression placeholders to their original form.
	for ph, expr := range exprMap {
		out = strings.ReplaceAll(out, ph, "${{ "+expr+" }}")
	}
	return out
}

func replaceShellEnvVarRefRegex(line, envVarName string) string {
	q := regexp.QuoteMeta(envVarName)
	re := regexp.MustCompile(`\$\{` + q + `\}|\$` + q + `([^A-Za-z0-9_]|$)`)
	plainPrefix := "$" + envVarName
	bracedForm := "${" + envVarName + "}"
	return re.ReplaceAllStringFunc(line, func(match string) string {
		if strings.HasPrefix(match, "${") {
			return `$(realpath "` + bracedForm + `")`
		}
		if match == plainPrefix {
			return `$(realpath "` + plainPrefix + `")`
		}
		return `$(realpath "` + plainPrefix + `")` + match[len(plainPrefix):]
	})
}

// setRunScriptValueForPath directly sets the run script value in a step's YAML node
func setRunScriptValueForPath(stepNode *yaml.Node, newValue string) error {
	if stepNode == nil || stepNode.Kind != yaml.MappingNode {
		return fmt.Errorf("step node must be a mapping node")
	}

	// Find 'run' section
	for i := 0; i < len(stepNode.Content); i += 2 {
		if stepNode.Content[i].Value == SBOMRun {
			runNode := stepNode.Content[i+1]
			if runNode.Kind == yaml.ScalarNode {
				runNode.Value = newValue
				return nil
			}
		}
	}

	return fmt.Errorf("run section not found in step node")
}

// generateEnvVarName generates an environment variable name from an untrusted path
func (rule *EnvPathInjectionRule) generateEnvVarName(path string) string {
	path = stripTaintAnnotation(path)
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return "UNTRUSTED_INPUT"
	}

	// Common patterns
	if len(parts) >= 4 && parts[0] == ContextGithub && parts[1] == EventCategory {
		category := parts[2]         // pull_request, issue, comment, etc.
		field := parts[len(parts)-1] // title, body, etc.

		// Convert to uppercase and join
		categoryUpper := strings.ToUpper(strings.ReplaceAll(category, "_", ""))
		fieldUpper := sanitizeEnvVarNameComponent(field)

		// Create readable name
		if categoryUpper == EventCategoryPR {
			categoryUpper = "PR"
		}

		return sanitizeEnvVarNameComponent(fmt.Sprintf("%s_%s", categoryUpper, fieldUpper))
	}

	// Fallback: use last part
	lastPart := parts[len(parts)-1]
	if name := sanitizeEnvVarNameComponent(lastPart); name != "" {
		return name
	}
	return "UNTRUSTED_INPUT"
}

// extractAndParseExpressions extracts all expressions from string and parses them
func (rule *EnvPathInjectionRule) extractAndParseExpressions(str *ast.String) []parsedExpression {
	if str == nil {
		return nil
	}

	value := str.Value
	var result []parsedExpression
	offset := 0

	for {
		idx := strings.Index(value[offset:], "${{")
		if idx == -1 {
			break
		}

		start := offset + idx
		endIdx := strings.Index(value[start:], "}}")
		if endIdx == -1 {
			break
		}

		exprContent := value[start+3 : start+endIdx]
		exprContent = strings.TrimSpace(exprContent)

		expr, parseErr := rule.parseExpression(exprContent)
		if parseErr == nil && expr != nil {
			lineIdx := strings.Count(value[:start], "\n")
			col := start
			if lastNewline := strings.LastIndex(value[:start], "\n"); lastNewline != -1 {
				col = start - lastNewline - 1
			}

			pos := &ast.Position{
				Line: str.Pos.Line + lineIdx,
				Col:  str.Pos.Col + col,
			}
			if str.Literal {
				pos.Line++
			}

			result = append(result, parsedExpression{
				raw:  exprContent,
				node: expr,
				pos:  pos,
			})
		}

		offset = start + endIdx + 2
	}

	return result
}

// parseExpression parses a single expression string into an AST node
func (rule *EnvPathInjectionRule) parseExpression(exprStr string) (expressions.ExprNode, *expressions.ExprError) {
	if !strings.HasSuffix(exprStr, "}}") {
		exprStr = exprStr + "}}"
	}
	l := expressions.NewTokenizer(exprStr)
	p := expressions.NewMiniParser()
	return p.Parse(l)
}

// checkUntrustedInput checks if the expression contains untrusted input
func (rule *EnvPathInjectionRule) checkUntrustedInput(expr parsedExpression) []string {
	checker := expressions.NewExprSemanticsChecker(true, nil)
	_, errs := checker.Check(expr.node)

	var paths []string
	for _, err := range errs {
		msg := err.Message
		if strings.Contains(msg, "potentially untrusted") {
			if idx := strings.Index(msg, "\""); idx != -1 {
				endIdx := strings.Index(msg[idx+1:], "\"")
				if endIdx != -1 {
					path := msg[idx+1 : idx+1+endIdx]
					paths = append(paths, path)
				}
			}
		}
	}

	return paths
}

// isDefinedInEnv checks if the expression is defined in the step's env section
func (rule *EnvPathInjectionRule) isDefinedInEnv(expr parsedExpression, env *ast.Env) bool {
	if env == nil {
		return false
	}

	normalizedExpr := normalizeExpression(expr.raw)

	if env.Vars != nil {
		for _, envVar := range env.Vars {
			if envVar.Value != nil && envVar.Value.ContainsExpression() {
				envExprs := extractExpressionsFromString(envVar.Value.Value)
				for _, envExpr := range envExprs {
					if normalizeExpression(envExpr) == normalizedExpr {
						return true
					}
				}
			}
		}
	}

	if env.Expression != nil && env.Expression.ContainsExpression() {
		envExprs := extractExpressionsFromString(env.Expression.Value)
		for _, envExpr := range envExprs {
			if normalizeExpression(envExpr) == normalizedExpr {
				return true
			}
		}
	}

	return false
}
