package core

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
	"github.com/sisaku-security/sisakulint/pkg/shell"
)

// taintPlaceholderPrefix is the prefix used to substitute GitHub Actions
// `${{ ... }}` expressions in shell scripts before bash parsing. The bash
// parser cannot accept `${{` as a parameter expansion, so each occurrence is
// replaced with a unique placeholder identifier (e.g. _SISAKULINT_E_0_) of
// arbitrary length. We record the placeholder→expression mapping so that
// callers can recover the original expression when extracting taint sources.
const taintPlaceholderPrefix = "_SISAKULINT_E_"

var (
	// taintGhExprPattern matches `${{ expr }}`. Uses `[\s\S]+?` (non-greedy
	// across any character including `}`) so expressions with nested braces
	// like `format('{0}', github.head_ref)` are captured in full instead of
	// being truncated at the first `}`.
	taintGhExprPattern = regexp.MustCompile(`\$\{\{\s*([\s\S]+?)\s*\}\}`)
	// taintPlaceholderPattern matches placeholders inserted by sanitizeForShellParse.
	taintPlaceholderPattern = regexp.MustCompile(`_SISAKULINT_E_\d+_`)
)

// sanitizeForShellParse replaces `${{ expr }}` with a unique placeholder so
// the bash parser accepts the script. Returns the sanitized script plus a
// placeholder→expression map for source recovery.
func sanitizeForShellParse(script string) (string, map[string]string) {
	exprMap := make(map[string]string)
	counter := 0
	sanitized := taintGhExprPattern.ReplaceAllStringFunc(script, func(m string) string {
		sub := taintGhExprPattern.FindStringSubmatch(m)
		ph := fmt.Sprintf("%s%d_", taintPlaceholderPrefix, counter)
		counter++
		if len(sub) >= 2 {
			exprMap[ph] = strings.TrimSpace(sub[1])
		}
		return ph
	})
	return sanitized, exprMap
}

// TaintTracker tracks taint propagation through step outputs.
// Phase 1 focuses on tracking $GITHUB_OUTPUT writes with untrusted inputs.
// Phase 2 extends this to track step output to step output propagation.
//
// Example of tracked vulnerability (GHSL-2024-325):
//
//   - id: get-ref
//     run: echo "ref=${{ github.head_ref }}" >> $GITHUB_OUTPUT
//   - env:
//     BRANCH: ${{ steps.get-ref.outputs.ref }}  # This is now tainted
//     run: git push origin HEAD:${BRANCH}         # Code injection!
//
// Phase 2 example (step output to step output):
//
//   - id: step-a
//     run: echo "val=${{ github.head_ref }}" >> $GITHUB_OUTPUT
//   - id: step-b
//     env:
//     INPUT: ${{ steps.step-a.outputs.val }}  # Tainted via step-a
//     run: echo "derived=$INPUT" >> $GITHUB_OUTPUT  # Output is also tainted
//   - env:
//     FINAL: ${{ steps.step-b.outputs.derived }}  # Tainted via step-b -> step-a
//     run: echo $FINAL  # Code injection!
type TaintTracker struct {
	// taintedOutputs maps stepID -> outputName -> taint sources
	// Example: {"get-ref": {"ref": ["github.head_ref"]}}
	taintedOutputs map[string]map[string][]string

	// taintedVars tracks variables in the current script that hold tainted values.
	// shell.Entry holds Sources (taint origins) and Offset (position-aware byte offset).
	// Used for intra-step variable propagation.
	taintedVars map[string]shell.Entry

	// knownTaintedActions maps action patterns to their tainted outputs
	// Phase 3: Used to infer taint from known action behaviors
	knownTaintedActions map[string][]KnownTaintedOutput
}

// KnownTaintedOutput represents a known tainted output from an action.
type KnownTaintedOutput struct {
	OutputName  string // Name of the output that is tainted
	TaintSource string // Description of where the taint comes from
}

// NewTaintTracker creates a new TaintTracker instance.
func NewTaintTracker() *TaintTracker {
	tracker := &TaintTracker{
		taintedOutputs:      make(map[string]map[string][]string),
		taintedVars:         make(map[string]shell.Entry),
		knownTaintedActions: make(map[string][]KnownTaintedOutput),
	}

	// Phase 3: Initialize known tainted actions database
	// These actions are known to expose untrusted PR/issue data as outputs
	tracker.initKnownTaintedActions()

	return tracker
}

// initKnownTaintedActions initializes the database of known actions with tainted outputs.
// Phase 3: This allows detection of taint from action outputs without analyzing action code.
func (t *TaintTracker) initKnownTaintedActions() {
	// gotson/pull-request-comment-branch - exposes PR branch info from comments
	// Used in GHSL-2024-325 vulnerability
	t.knownTaintedActions["gotson/pull-request-comment-branch"] = []KnownTaintedOutput{
		{OutputName: "head_ref", TaintSource: "github.event.pull_request.head.ref (via action)"},
		{OutputName: "head_sha", TaintSource: "github.event.pull_request.head.sha (via action)"},
		{OutputName: "base_ref", TaintSource: "github.event.pull_request.base.ref (via action)"},
		{OutputName: "base_sha", TaintSource: "github.event.pull_request.base.sha (via action)"},
	}

	// xt0rted/pull-request-comment-branch - similar to gotson
	t.knownTaintedActions["xt0rted/pull-request-comment-branch"] = []KnownTaintedOutput{
		{OutputName: "head_ref", TaintSource: "github.event.pull_request.head.ref (via action)"},
		{OutputName: "head_sha", TaintSource: "github.event.pull_request.head.sha (via action)"},
		{OutputName: "base_ref", TaintSource: "github.event.pull_request.base.ref (via action)"},
		{OutputName: "base_sha", TaintSource: "github.event.pull_request.base.sha (via action)"},
	}

	// actions/github-script - if inputs contain untrusted data, outputs may be tainted
	// Note: This is handled dynamically based on script content, not here

	// peter-evans/find-comment - extracts comment body which is untrusted
	t.knownTaintedActions["peter-evans/find-comment"] = []KnownTaintedOutput{
		{OutputName: "comment-body", TaintSource: "github.event.comment.body (via action)"},
		{OutputName: "comment-author", TaintSource: "github.event.comment.user.login (via action)"},
	}

	// actions/create-github-app-token - outputs are safe (tokens are not user-controlled)
	// Not adding to tainted list

	// EndBug/add-and-commit - if inputs contain untrusted data, may propagate
	// Outputs are generally safe (commit sha)

	// juliangruber/read-file-action - reads file content and outputs it
	// Used in GHSL-2025-087 vulnerability: artifact content read and used in shell
	// The file content may come from artifacts or other untrusted sources
	t.knownTaintedActions["juliangruber/read-file-action"] = []KnownTaintedOutput{
		{OutputName: "content", TaintSource: "file content (potentially from artifact)"},
	}

	// andstor/file-reader-action - similar to juliangruber/read-file-action
	t.knownTaintedActions["andstor/file-reader-action"] = []KnownTaintedOutput{
		{OutputName: "contents", TaintSource: "file content (potentially from artifact)"},
	}

	// tj-actions/changed-files - exposes PR-controlled filenames as outputs
	// GHSL-2023-271: attacker creates PR with crafted filenames containing shell metacharacters
	// All file-list outputs reflect filenames from the PR, making them untrusted input
	t.knownTaintedActions["tj-actions/changed-files"] = []KnownTaintedOutput{
		{OutputName: "all_changed_files", TaintSource: "PR filenames (attacker-controlled via pull request)"},
		{OutputName: "modified_files", TaintSource: "PR filenames (attacker-controlled via pull request)"},
		{OutputName: "added_files", TaintSource: "PR filenames (attacker-controlled via pull request)"},
		{OutputName: "deleted_files", TaintSource: "PR filenames (attacker-controlled via pull request)"},
		{OutputName: "renamed_files", TaintSource: "PR filenames (attacker-controlled via pull request)"},
		{OutputName: "all_changed_and_modified_files", TaintSource: "PR filenames (attacker-controlled via pull request)"},
		{OutputName: "all_modified_files", TaintSource: "PR filenames (attacker-controlled via pull request)"},
		{OutputName: "other_changed_files", TaintSource: "PR filenames (attacker-controlled via pull request)"},
		{OutputName: "other_modified_files", TaintSource: "PR filenames (attacker-controlled via pull request)"},
		{OutputName: "other_deleted_files", TaintSource: "PR filenames (attacker-controlled via pull request)"},
	}
}

// AnalyzeStep analyzes a step for $GITHUB_OUTPUT writes with tainted values.
// It tracks which outputs become tainted based on the script content.
// Phase 2: Also considers env vars that reference tainted step outputs.
// Phase 3: Also handles action steps with known tainted outputs.
func (t *TaintTracker) AnalyzeStep(step *ast.Step) {
	if step == nil || step.ID == nil || step.ID.Value == "" {
		return
	}

	if step.Exec == nil {
		return
	}

	stepID := step.ID.Value

	// Phase 3: Handle action steps
	if step.Exec.Kind() == ast.ExecKindAction {
		t.analyzeActionStep(step)
		return
	}

	// Handle run: steps
	if step.Exec.Kind() != ast.ExecKindRun {
		return
	}

	run, ok := step.Exec.(*ast.ExecRun)
	if !ok || run.Run == nil {
		return
	}

	// Reset tainted vars for this step
	t.taintedVars = make(map[string]shell.Entry)

	// Phase 2: Pre-populate tainted vars from env section
	// If env vars reference tainted step outputs, those vars are also tainted
	t.populateTaintedVarsFromEnv(step.Env)

	// Parse script once and dispatch to AST-based helpers (Issue #446).
	// Bash cannot natively parse `${{ ... }}`, so substitute placeholders that
	// preserve detectability while remaining valid bash literals.
	sanitized, exprMap := sanitizeForShellParse(run.Run.Value)
	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(sanitized), "")
	if err != nil || file == nil {
		return
	}

	// Seed taintedVars from `${{ untrusted }}` and `${{ steps.X.outputs.Y }}`
	// found directly in assignment values. PropagateTaint then propagates
	// these across shell-variable references.
	t.seedTaintFromExpressions(file, exprMap)

	// Forward dataflow with order-aware Offset
	scoped := shell.PropagateTaint(file, t.taintedVars)
	t.taintedVars = scoped.Final
	expandShellvarMarkers(t.taintedVars)

	// shell.PropagateTaint marks derived variables with "shellvar:X" chain
	// markers; taint.go callers expect transitive source lists for richer
	// reporting (e.g. trace back to "github.event.issue.title"). Expand the
	// markers in place. Bounded passes guard against pathological chains.
	// (NOTE: scope-aware per-stmt expansion is added in Task 10)

	// GITHUB_OUTPUT writes
	for _, w := range shell.WalkRedirectWrites(file, "GITHUB_OUTPUT") {
		t.recordRedirWrite(stepID, w, exprMap)
	}
}

// seedTaintFromExpressions seeds taintedVars by inspecting each shell
// assignment for embedded `${{ ... }}` expressions (substituted to
// placeholders during sanitization). This preserves the legacy regex-era
// behavior of detecting direct expression injection like `URL="${{ ... }}"`.
func (t *TaintTracker) seedTaintFromExpressions(file *syntax.File, exprMap map[string]string) {
	for _, a := range shell.WalkAssignments(file) {
		if a.Value == nil {
			continue
		}
		// wordLitPrefix-equivalent: collect Lit parts to capture placeholder text.
		valueText := assignmentValueText(a.Value)
		sources := t.collectExpressionSources(valueText, exprMap)
		if len(sources) == 0 {
			continue
		}
		existing := t.taintedVars[a.Name]
		existing.Sources = mergeUnique(existing.Sources, sources)
		if existing.Offset == 0 {
			existing.Offset = a.Offset
		}
		t.taintedVars[a.Name] = existing
	}
}

// assignmentValueText concatenates literal segments of a Word for placeholder
// detection. Both *syntax.Lit and *syntax.SglQuoted contribute their text
// (single-quoted strings expose their content via SglQuoted.Value, not via
// child Lit nodes, so a Lit-only walk would miss `X='${{ ... }}'`).
// ParamExp / CmdSubst boundaries are walked through.
func assignmentValueText(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var sb strings.Builder
	syntax.Walk(w, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.Lit:
			sb.WriteString(x.Value)
		case *syntax.SglQuoted:
			sb.WriteString(x.Value)
		}
		return true
	})
	return sb.String()
}

// collectExpressionSources extracts taint sources from a string containing
// either raw `${{ }}` (defensive) or sanitized placeholders.
func (t *TaintTracker) collectExpressionSources(value string, exprMap map[string]string) []string {
	if value == "" {
		return nil
	}
	var sources []string
	sources = append(sources, t.extractUntrustedSources(value)...)
	for _, ph := range taintPlaceholderPattern.FindAllString(value, -1) {
		expr, ok := exprMap[ph]
		if !ok {
			continue
		}
		if tainted, srcs := t.IsTaintedExpr(expr); tainted {
			sources = append(sources, srcs...)
		}
		if t.isUntrustedExpression(expr) {
			sources = append(sources, expr)
		}
	}
	return sources
}

// analyzeActionStep checks if an action step uses a known tainted action.
// Phase 3: If the action is known to expose untrusted data, mark its outputs as tainted.
func (t *TaintTracker) analyzeActionStep(step *ast.Step) {
	action, ok := step.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return
	}

	stepID := step.ID.Value
	uses := action.Uses.Value

	// Extract action name (without version)
	actionName := strings.ToLower(t.extractActionName(uses))

	// Check if this action is known to have tainted outputs
	taintedOutputs, exists := t.knownTaintedActions[actionName]
	if !exists {
		return
	}

	// Mark all known tainted outputs for this step
	if t.taintedOutputs[stepID] == nil {
		t.taintedOutputs[stepID] = make(map[string][]string)
	}

	for _, output := range taintedOutputs {
		t.taintedOutputs[stepID][output.OutputName] = []string{output.TaintSource}
	}
}

// extractActionName extracts the action name from a uses string.
// Example: "gotson/pull-request-comment-branch@v1" -> "gotson/pull-request-comment-branch"
func (t *TaintTracker) extractActionName(uses string) string {
	// Remove version suffix (`@v1`, `@main`, `@sha`, etc.)
	if idx := strings.Index(uses, "@"); idx != -1 {
		return uses[:idx]
	}
	return uses
}

// populateTaintedVarsFromEnv checks env vars for tainted step output references.
// Phase 2: If an env var references a tainted step output, that var becomes tainted.
//
// Example:
//
//	env:
//	  INPUT: ${{ steps.step-a.outputs.val }}  # If step-a.outputs.val is tainted, INPUT is tainted
func (t *TaintTracker) populateTaintedVarsFromEnv(env *ast.Env) {
	if env == nil || env.Vars == nil {
		return
	}

	for _, envVar := range env.Vars {
		if envVar.Value == nil || !envVar.Value.ContainsExpression() {
			continue
		}

		varName := envVar.Name.Value
		value := envVar.Value.Value

		// Find all ${{ }} expressions in the env var value (uses [\s\S]+?
		// so expressions with nested `}` like `format('{0}', x)` are captured).
		matches := taintGhExprPattern.FindAllStringSubmatch(value, -1)

		var collected []string
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			exprContent := strings.TrimSpace(match[1])

			// Propagate taint via tainted step output references.
			if tainted, sources := t.IsTaintedExpr(exprContent); tainted {
				collected = append(collected, sources...)
			}

			// Direct untrusted expression contributes its own source.
			if t.isUntrustedExpression(exprContent) {
				collected = append(collected, exprContent)
			}
		}
		if len(collected) == 0 {
			continue
		}
		// env-derived taint has Offset=-1 (precedes any script position).
		existing := t.taintedVars[varName]
		existing.Sources = mergeUnique(existing.Sources, collected)
		existing.Offset = -1
		t.taintedVars[varName] = existing
	}
}

// expandShellvarMarkers replaces `shellvar:X` markers in each entry's Sources
// with X's transitive sources, iterating up to maxPasses to handle chains.
func expandShellvarMarkers(tainted map[string]shell.Entry) {
	const maxPasses = 16
	for pass := 0; pass < maxPasses; pass++ {
		changed := false
		for name, entry := range tainted {
			expanded := make([]string, 0, len(entry.Sources))
			anyExpanded := false
			for _, src := range entry.Sources {
				if ref, ok := strings.CutPrefix(src, "shellvar:"); ok && ref != name {
					if upstream, exists := tainted[ref]; exists {
						expanded = mergeUnique(expanded, upstream.Sources)
						anyExpanded = true
						continue
					}
				}
				expanded = append(expanded, src)
			}
			// Only update / mark changed when the expanded slice differs from the
			// existing Sources. Without this, mutual references (A->B, B->A)
			// would keep `anyExpanded` true on every pass even after content
			// stabilizes, forcing the loop to run all maxPasses iterations.
			if anyExpanded && !slices.Equal(expanded, entry.Sources) {
				entry.Sources = expanded
				tainted[name] = entry
				changed = true
			}
		}
		if !changed {
			return
		}
	}
}

// mergeUnique は順序保持で重複なしの merge。
func mergeUnique(dst, src []string) []string {
	seen := make(map[string]struct{}, len(dst)+len(src))
	for _, s := range dst {
		seen[s] = struct{}{}
	}
	out := dst
	for _, s := range src {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// recordRedirWrite は WalkRedirectWrites の結果をもとに taintedOutputs に記録する。
// VALUE 内に直接 untrusted 式（プレースホルダ経由を含む）があるか、または
// tainted 変数を参照していれば、その output を tainted として登録する。
func (t *TaintTracker) recordRedirWrite(stepID string, w shell.RedirWrite, exprMap map[string]string) {
	sources := t.collectExpressionSources(w.Value, exprMap)

	// VALUE 内の $VAR 参照を tainted vars と照合
	if w.ValueWord != nil {
		if name, ok := shell.WordReferencesEntry(w.ValueWord, t.taintedVars); ok {
			sources = mergeUnique(sources, t.taintedVars[name].Sources)
		}
	} else {
		// heredoc 等で ValueWord が無い場合は文字列ベースで $VAR を検出
		varRefPattern := regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
		for _, m := range varRefPattern.FindAllStringSubmatch(w.Value, -1) {
			if len(m) < 2 {
				continue
			}
			if entry, ok := t.taintedVars[m[1]]; ok {
				sources = mergeUnique(sources, entry.Sources)
			}
		}
	}

	if len(sources) == 0 {
		return
	}
	if t.taintedOutputs[stepID] == nil {
		t.taintedOutputs[stepID] = make(map[string][]string)
	}
	t.taintedOutputs[stepID][w.Name] = sources
}

// extractUntrustedSources extracts untrusted expression paths from a string.
// Example: "${{ github.event.issue.title }}" -> ["github.event.issue.title"]
func (t *TaintTracker) extractUntrustedSources(value string) []string {
	var sources []string

	// Find all ${{ }} expressions (shared regex handles nested `}` like
	// `format('{0}', x)`).
	matches := taintGhExprPattern.FindAllStringSubmatch(value, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		exprContent := strings.TrimSpace(match[1])

		// Parse and check if untrusted
		if t.isUntrustedExpression(exprContent) {
			sources = append(sources, exprContent)
		}
	}

	return sources
}

// isUntrustedExpression checks if an expression contains untrusted input.
func (t *TaintTracker) isUntrustedExpression(exprContent string) bool {
	// Parse the expression
	l := expressions.NewTokenizer(exprContent + "}}")
	p := expressions.NewMiniParser()
	node, err := p.Parse(l)
	if err != nil {
		return false
	}

	// Use the existing semantic checker
	checker := expressions.NewExprSemanticsChecker(true, nil)
	_, errs := checker.Check(node)

	// Check if any error indicates untrusted input
	for _, e := range errs {
		if strings.Contains(e.Message, "potentially untrusted") {
			return true
		}
	}

	return false
}

// IsTaintedExpr checks if an expression string references a tainted step output.
// Returns true and the taint sources if tainted.
//
// Example:
//
//	IsTaintedExpr("steps.get-ref.outputs.ref") -> (true, ["github.head_ref"])
func (t *TaintTracker) IsTaintedExpr(exprStr string) (bool, []string) {
	// Check if this is a steps.*.outputs.* reference
	if !strings.HasPrefix(exprStr, "steps.") {
		return false, nil
	}

	parts := strings.Split(exprStr, ".")
	// Expected format: steps.<step-id>.outputs.<output-name>
	if len(parts) < 4 || parts[2] != "outputs" {
		return false, nil
	}

	stepID := parts[1]
	outputName := strings.Join(parts[3:], ".")

	// Check if this output is tainted
	if outputs, exists := t.taintedOutputs[stepID]; exists {
		if sources, outputExists := outputs[outputName]; outputExists {
			return true, sources
		}
	}

	return false, nil
}

// IsTainted checks if an expression AST node references a tainted step output.
// This is the primary method to use when integrating with CodeInjectionRule.
func (t *TaintTracker) IsTainted(node expressions.ExprNode) (bool, []string) {
	// Convert AST node to string representation for checking
	exprStr := t.nodeToString(node)
	return t.IsTaintedExpr(exprStr)
}

// GetTaintedOutputs returns a deep copy of all tracked tainted outputs (for testing/debugging).
func (t *TaintTracker) GetTaintedOutputs() map[string]map[string][]string {
	result := make(map[string]map[string][]string, len(t.taintedOutputs))
	for step, outputMap := range t.taintedOutputs {
		inner := make(map[string][]string, len(outputMap))
		for output, sources := range outputMap {
			srcs := make([]string, len(sources))
			copy(srcs, sources)
			inner[output] = srcs
		}
		result[step] = inner
	}
	return result
}

// nodeToString converts an expression AST node to its string representation.
// Delegates to the package-level exprNodeToString for reuse across rules.
func (t *TaintTracker) nodeToString(node expressions.ExprNode) string {
	return exprNodeToString(node)
}

// exprNodeToString converts an expression AST node to its dot-separated string representation.
// Examples:
//   - needs.extract.outputs.pr_title → "needs.extract.outputs.pr_title"
//   - steps.get-ref.outputs.ref → "steps.get-ref.outputs.ref"
//   - github.event.pull_request.title → "github.event.pull_request.title"
func exprNodeToString(node expressions.ExprNode) string {
	switch n := node.(type) {
	case *expressions.ObjectDerefNode:
		return buildExprObjectDerefString(n)
	case *expressions.IndexAccessNode:
		return buildExprIndexAccessString(n)
	case *expressions.VariableNode:
		return n.Name
	default:
		return ""
	}
}

func buildExprObjectDerefString(node *expressions.ObjectDerefNode) string {
	var parts []string
	var current expressions.ExprNode = node
	for current != nil {
		switch n := current.(type) {
		case *expressions.ObjectDerefNode:
			parts = append([]string{n.Property}, parts...)
			current = n.Receiver
		case *expressions.VariableNode:
			parts = append([]string{n.Name}, parts...)
			current = nil
		default:
			current = nil
		}
	}
	return strings.Join(parts, ".")
}

func buildExprIndexAccessString(node *expressions.IndexAccessNode) string {
	operandStr := exprNodeToString(node.Operand)
	if operandStr == "" {
		return ""
	}
	if strNode, ok := node.Index.(*expressions.StringNode); ok {
		return operandStr + "." + strNode.Value
	}
	return operandStr
}
