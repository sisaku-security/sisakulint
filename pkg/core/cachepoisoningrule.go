package core

import (
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
	"gopkg.in/yaml.v3"
)

// CachePoisoningRule detects potential cache poisoning vulnerabilities in GitHub Actions workflows.
// It checks for:
// 1. Indirect cache poisoning: Untrusted triggers + unsafe checkout + cache actions
// 2. Direct cache poisoning: Untrusted input in cache key/restore-keys/path (any trigger)
// 3. Predictable cache keys: Cache keys using only hashFiles() without unique prefix
// 4. High-risk context: Cache usage in release/deploy workflows
// 5. Cache hierarchy exploitation: Workflows that can write to default branch cache
// 6. Cache eviction risk: Multiple cache actions that could enable cache flooding
type CachePoisoningRule struct {
	BaseRule
	unsafeTriggers      []string
	jobUnsafeTriggers   []string
	checkoutUnsafeRef   bool
	unsafeCheckoutStep  *ast.Step
	autoFixerRegistered bool
	actionMetadata      ActionMetadataResolver
	directCacheFixSteps []*directCacheFixInfo
	// New fields for extended detection
	isReleaseWorkflow      bool
	isPullRequestEvent     bool
	hasPushToDefaultBranch bool
	hasExternalTrigger     bool // workflow_dispatch, schedule, repository_dispatch
	cacheActionCount       int
	workflowTriggers       []string
	directCacheDirWrites   []directCacheDirectoryWriteInfo
}

// directCacheFixInfo stores information needed for auto-fixing direct cache poisoning
type directCacheFixInfo struct {
	step      *ast.Step
	inputName string // "key", "restore-keys", or "path"
	expr      string // the untrusted expression
}

type directCacheDirectoryWriteInfo struct {
	cacheDir string
}

// NewCachePoisoningRule creates a new cache poisoning detection rule.
func NewCachePoisoningRule(actionMetadata ...ActionMetadataResolver) *CachePoisoningRule {
	var resolver ActionMetadataResolver
	if len(actionMetadata) > 0 {
		resolver = NewMultiActionMetadataResolver(actionMetadata...)
	}
	return &CachePoisoningRule{
		BaseRule: BaseRule{
			RuleName: "cache-poisoning",
			RuleDesc: "Detects potential cache poisoning vulnerabilities when using cache with untrusted triggers or untrusted inputs in cache configuration",
		},
		actionMetadata:      resolver,
		directCacheFixSteps: make([]*directCacheFixInfo, 0),
	}
}

func isCacheAction(uses string, inputs map[string]*ast.Input) bool {
	if uses == "" {
		return false
	}

	actionName := uses
	if idx := strings.Index(uses, "@"); idx != -1 {
		actionName = uses[:idx]
	}

	if actionName == "actions/cache" ||
		actionName == "actions/cache/save" ||
		actionName == "actions/cache/restore" {
		return true
	}

	if strings.HasPrefix(actionName, "actions/setup-") {
		if cacheInput, ok := inputs["cache"]; ok && cacheInput != nil {
			if cacheInput.Value != nil && cacheInput.Value.Value != "" && cacheInput.Value.Value != ExprFalseValue {
				return true
			}
		}
	}

	return false
}

func (rule *CachePoisoningRule) VisitWorkflowPre(node *ast.Workflow) error {
	rule.unsafeTriggers = nil
	rule.directCacheFixSteps = make([]*directCacheFixInfo, 0)
	rule.isReleaseWorkflow = false
	rule.isPullRequestEvent = false
	rule.hasPushToDefaultBranch = false
	rule.hasExternalTrigger = false
	rule.cacheActionCount = 0
	rule.workflowTriggers = nil
	rule.directCacheDirWrites = nil

	for _, event := range node.On {
		switch e := event.(type) {
		case *ast.WebhookEvent:
			if e.Hook != nil {
				triggerName := e.Hook.Value
				rule.workflowTriggers = append(rule.workflowTriggers, triggerName)

				if IsUnsafeTrigger(triggerName) {
					rule.unsafeTriggers = append(rule.unsafeTriggers, triggerName)
				}

				// Check for release/deploy workflows (high-risk context)
				if triggerName == "release" || triggerName == "deployment" ||
					triggerName == "deployment_status" {
					rule.isReleaseWorkflow = true
				}

				// Check for PR workflows (cache scope concern)
				if triggerName == EventPullRequest || triggerName == EventPullRequestTarget {
					rule.isPullRequestEvent = true
				}

				// Check for push to default branch (cache hierarchy exploitation risk)
				if triggerName == "push" {
					rule.hasPushToDefaultBranch = rule.isPushToDefaultBranch(e)
				}

				// Check for external triggers (can be exploited for cache hierarchy attacks)
				if triggerName == SubWorkflowDispatch || triggerName == SubSchedule ||
					triggerName == SubRepositoryDispatch {
					rule.hasExternalTrigger = true
				}
			}
		case *ast.ScheduledEvent:
			rule.workflowTriggers = append(rule.workflowTriggers, SubSchedule)
			rule.hasExternalTrigger = true
		case *ast.WorkflowDispatchEvent:
			rule.workflowTriggers = append(rule.workflowTriggers, SubWorkflowDispatch)
			rule.hasExternalTrigger = true
		case *ast.RepositoryDispatchEvent:
			rule.workflowTriggers = append(rule.workflowTriggers, SubRepositoryDispatch)
			rule.hasExternalTrigger = true
		}
	}

	return nil
}

// isPushToDefaultBranch checks if push event targets default branch (main/master)
func (rule *CachePoisoningRule) isPushToDefaultBranch(event *ast.WebhookEvent) bool {
	// If the push event only has tags filter (no branches), it doesn't target branches at all
	if event.Branches == nil && event.Tags != nil {
		return false
	}

	// If no branch filter, it includes default branch
	if event.Branches == nil {
		return true
	}

	// Check if any branch filter includes default branch
	for _, branch := range event.Branches.Values {
		if branch != nil {
			branchName := branch.Value
			if branchName == "main" || branchName == "master" ||
				branchName == "**" || branchName == "*" {
				return true
			}
		}
	}

	return false
}

func (rule *CachePoisoningRule) VisitWorkflowPost(node *ast.Workflow) error {
	// Check for cache eviction risk: multiple cache actions can enable cache flooding attacks
	// GitHub has a 10GB cache limit per repository - attackers can fill it to evict legitimate caches
	if rule.cacheActionCount >= 5 {
		// Use workflow name position if available, otherwise use line 1
		var pos *ast.Position
		if node.Name != nil && node.Name.Pos != nil {
			pos = node.Name.Pos
		} else {
			pos = &ast.Position{Line: 1, Col: 1}
		}
		rule.Errorf(
			pos,
			"cache eviction risk: workflow uses %d cache actions. "+
				"Multiple caches increase risk of cache flooding attacks where attackers fill the 10GB repository limit "+
				"to evict legitimate caches. Consider consolidating caches or using cache-read-only for non-critical jobs",
			rule.cacheActionCount,
		)
	}
	return nil
}

func (rule *CachePoisoningRule) VisitJobPre(node *ast.Job) error {
	rule.checkoutUnsafeRef = false
	rule.unsafeCheckoutStep = nil
	rule.autoFixerRegistered = false
	rule.jobUnsafeTriggers = nil
	rule.directCacheDirWrites = nil

	if len(rule.unsafeTriggers) == 0 {
		return nil
	}

	analyzer := NewJobTriggerAnalyzer(rule.workflowTriggers)
	for _, trigger := range analyzer.AnalyzeJobTriggers(node) {
		if IsUnsafeTrigger(trigger) {
			rule.jobUnsafeTriggers = append(rule.jobUnsafeTriggers, trigger)
		}
	}

	if len(rule.jobUnsafeTriggers) == 0 {
		jobID := "<nil>"
		if node.ID != nil {
			jobID = node.ID.Value
		}
		rule.Debug("Job '%s' filtered out unsafe triggers via if condition", jobID)
	}

	return nil
}

func (rule *CachePoisoningRule) VisitJobPost(node *ast.Job) error {
	return nil
}

func (rule *CachePoisoningRule) VisitStep(node *ast.Step) error {
	if run, ok := node.Exec.(*ast.ExecRun); ok {
		rule.checkDirectCacheDirectoryWrite(run)
		return nil
	}

	action, ok := node.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return nil
	}

	uses := action.Uses.Value

	actionName := uses
	if idx := strings.Index(uses, "@"); idx != -1 {
		actionName = uses[:idx]
	}

	// Check for checkout with unsafe ref (only with unsafe triggers)
	if actionName == "actions/checkout" && len(rule.jobUnsafeTriggers) > 0 {
		if refInput, ok := action.Inputs["ref"]; ok && refInput != nil && refInput.Value != nil {
			if IsUnsafeCheckoutRef(refInput.Value.Value) {
				rule.checkoutUnsafeRef = true
				rule.unsafeCheckoutStep = node
			} else {
				// Safe checkout resets the unsafe state
				// This handles the case where an unsafe checkout is followed by a safe one
				rule.checkoutUnsafeRef = false
				rule.unsafeCheckoutStep = nil
			}
		} else {
			// Checkout without ref (defaults to base branch) is safe
			rule.checkoutUnsafeRef = false
			rule.unsafeCheckoutStep = nil
		}
		return nil
	}

	// Check for direct cache poisoning: untrusted input in cache key/restore-keys/path
	// This applies to any trigger (including pull_request, push, etc.)
	if actionName == "actions/cache" {
		rule.checkDirectCachePoisoning(node, action)
	}

	if actionName == "actions/cache/save" {
		rule.reportCacheSaveAfterDirectCacheDirectoryWrite(node)
	}

	// Check for cache actions
	if isCacheAction(uses, action.Inputs) {
		rule.cacheActionCount++

		// Check cache hierarchy exploitation risk
		rule.checkCacheHierarchyExploitation(node, uses)

		// Check for indirect cache poisoning (unsafe checkout + cache action)
		// This only applies with unsafe triggers
		if len(rule.jobUnsafeTriggers) > 0 && rule.checkoutUnsafeRef {
			rule.reportIndirectCachePoisoning(node, uses)
		}
		return nil
	}

	if len(rule.jobUnsafeTriggers) > 0 && rule.checkoutUnsafeRef {
		inspection := rule.inspectCompositeAction(uses)
		if inspection.cacheFound {
			rule.cacheActionCount++
			rule.checkCacheHierarchyExploitation(node, inspection.cacheUses)
			triggers := strings.Join(rule.jobUnsafeTriggers, ", ")
			rule.Errorf(
				node.Pos,
				"cache poisoning risk (critical): composite action '%s' invokes '%s' after checking out untrusted PR code (triggers: %s, chain: %s). "+
					"This can persist attacker-controlled dependency state through GitHub Actions cache scope crossing; validate cached content or scope cache to PR level",
				uses,
				inspection.cacheUses,
				triggers,
				strings.Join(inspection.chain, " -> "),
			)
			rule.registerIndirectCachePoisoningFixer()
		} else if inspection.resolvedComposite && isMutableRemoteAction(uses) {
			triggers := strings.Join(rule.jobUnsafeTriggers, ", ")
			rule.Errorf(
				node.Pos,
				"cache poisoning risk: mutable remote composite action '%s' runs after checking out untrusted PR code (triggers: %s). "+
					"The action currently resolves as a composite action, but because the ref is not pinned to a full commit SHA, historical transitive actions/cache usage and GitHub Actions cache scope crossing cannot be ruled out from the current repository state; pin the action to a full commit SHA or avoid unsafe checkout under privileged triggers",
				uses,
				triggers,
			)
			rule.registerIndirectCachePoisoningFixer()
		}
	}

	return nil
}

var packageManagerCacheDirs = []string{
	"~/.npm/_cacache",
	"$home/.npm/_cacache",
	"${home}/.npm/_cacache",
	"/home/runner/.npm/_cacache",
	"~/.cache/pip",
	"$home/.cache/pip",
	"${home}/.cache/pip",
	"/home/runner/.cache/pip",
	"~/.cargo/registry",
	"$home/.cargo/registry",
	"${home}/.cargo/registry",
	"/home/runner/.cargo/registry",
	"~/.gradle/caches",
	"$home/.gradle/caches",
	"${home}/.gradle/caches",
	"/home/runner/.gradle/caches",
	"~/.m2/repository",
	"$home/.m2/repository",
	"${home}/.m2/repository",
	"/home/runner/.m2/repository",
	"~/go/pkg/mod/cache",
	"$home/go/pkg/mod/cache",
	"${home}/go/pkg/mod/cache",
	"/home/runner/go/pkg/mod/cache",
}

var packageManagerCommands = map[string]bool{
	"npm":     true,
	"npx":     true,
	"pnpm":    true,
	"yarn":    true,
	"pip":     true,
	"pip3":    true,
	"python":  true,
	"python3": true,
	"cargo":   true,
	"gradle":  true,
	"mvn":     true,
	"go":      true,
}

var cacheDirectoryWriteCommands = map[string]bool{
	"cat":     true,
	"cp":      true,
	"echo":    true,
	"install": true,
	"mkdir":   true,
	"mv":      true,
	"printf":  true,
	"tee":     true,
	"touch":   true,
}

func (rule *CachePoisoningRule) checkDirectCacheDirectoryWrite(run *ast.ExecRun) {
	if run == nil || run.Run == nil {
		return
	}

	lines := strings.Split(run.Run.Value, "\n")
	for idx, line := range lines {
		matchedDir, ok := cacheDirectoryInLine(line)
		if !ok || !isDirectCacheDirectoryWrite(line) {
			continue
		}

		pos := run.Run.Pos
		if pos != nil {
			pos = &ast.Position{Line: pos.Line + idx, Col: pos.Col}
			if run.Run.Literal {
				pos.Line++
			}
		}
		rule.Errorf(
			pos,
			"cache poisoning via package manager cache directory write: command writes directly to %s. "+
				"Direct writes to dependency cache directories can poison later actions/cache/save entries; use package manager commands or avoid saving this cache after untrusted writes",
			matchedDir,
		)
		rule.directCacheDirWrites = append(rule.directCacheDirWrites, directCacheDirectoryWriteInfo{
			cacheDir: matchedDir,
		})
	}
}

func (rule *CachePoisoningRule) reportCacheSaveAfterDirectCacheDirectoryWrite(node *ast.Step) {
	if len(rule.directCacheDirWrites) == 0 {
		return
	}

	dirs := make([]string, 0, len(rule.directCacheDirWrites))
	seen := make(map[string]bool, len(rule.directCacheDirWrites))
	for _, write := range rule.directCacheDirWrites {
		if seen[write.cacheDir] {
			continue
		}
		seen[write.cacheDir] = true
		dirs = append(dirs, write.cacheDir)
	}

	rule.Errorf(
		node.Pos,
		"cache poisoning risk (critical): actions/cache/save follows direct writes to package manager cache directories (%s). "+
			"This can persist attacker-controlled dependency cache content for later workflow runs; avoid saving caches after direct cache directory writes",
		strings.Join(dirs, ", "),
	)
}

func cacheDirectoryInLine(line string) (string, bool) {
	lower := strings.ToLower(line)
	for _, dir := range packageManagerCacheDirs {
		if cacheDirectoryPatternInLine(lower, dir) {
			return dir, true
		}
	}
	return "", false
}

func cacheDirectoryPatternInLine(line string, dir string) bool {
	start := 0
	for {
		idx := strings.Index(line[start:], dir)
		if idx == -1 {
			return false
		}
		end := start + idx + len(dir)
		if end == len(line) || isCacheDirectoryBoundary(line[end]) {
			return true
		}
		start = end
	}
}

func isCacheDirectoryBoundary(ch byte) bool {
	return ch == '/' || ch == '\\' || ch == '\'' || ch == '"' ||
		ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' ||
		ch == ';' || ch == ')' || ch == ']' || ch == '}'
}

func isDirectCacheDirectoryWrite(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return false
	}

	command := firstShellCommandToken(trimmed)
	if command == "" || packageManagerCommands[command] {
		return false
	}

	if redirectsToCacheDirectory(trimmed) {
		return true
	}

	switch command {
	case "mkdir", "touch":
		return true
	case "cp", "install", "mv":
		return containsCacheDirectory(lastShellArgument(trimmed))
	case "tee":
		return anyShellArgumentContainsCacheDirectory(trimmed)
	default:
		return cacheDirectoryWriteCommands[command] && redirectsToCacheDirectory(trimmed)
	}
}

func firstShellCommandToken(line string) string {
	fields := strings.Fields(line)
	for _, field := range fields {
		token := strings.Trim(field, "'\"(){}[];")
		if token == "" {
			continue
		}
		if strings.Contains(token, "=") && !strings.HasPrefix(token, ">") {
			continue
		}
		return strings.ToLower(token)
	}
	return ""
}

func redirectsToCacheDirectory(line string) bool {
	for _, op := range []string{">>", ">"} {
		idx := strings.Index(line, op)
		if idx == -1 {
			continue
		}
		if containsCacheDirectory(line[idx+len(op):]) {
			return true
		}
	}
	return false
}

func lastShellArgument(line string) string {
	fields := strings.Fields(line)
	for i := len(fields) - 1; i >= 0; i-- {
		arg := cleanShellToken(fields[i])
		if arg == "" || strings.HasPrefix(arg, "-") {
			continue
		}
		return arg
	}
	return ""
}

func anyShellArgumentContainsCacheDirectory(line string) bool {
	fields := strings.Fields(line)
	for _, field := range fields[1:] {
		arg := cleanShellToken(field)
		if arg == "" || strings.HasPrefix(arg, "-") {
			continue
		}
		if containsCacheDirectory(arg) {
			return true
		}
	}
	return false
}

func containsCacheDirectory(value string) bool {
	_, ok := cacheDirectoryInLine(value)
	return ok
}

func cleanShellToken(token string) string {
	return strings.Trim(token, "'\"(){}[];,")
}

func isMutableRemoteAction(uses string) bool {
	if uses == "" || strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, ".\\") || strings.HasPrefix(uses, "docker://") {
		return false
	}
	if isFullLengthSha(uses) {
		return false
	}
	actionPath, _, ok := strings.Cut(uses, "@")
	if !ok {
		return false
	}
	return len(strings.Split(actionPath, "/")) >= 2
}

func (rule *CachePoisoningRule) reportIndirectCachePoisoning(node *ast.Step, uses string) {
	triggers := strings.Join(rule.jobUnsafeTriggers, ", ")
	rule.Errorf(
		node.Pos,
		"cache poisoning risk: '%s' used after checking out untrusted PR code (triggers: %s). Validate cached content or scope cache to PR level",
		uses,
		triggers,
	)
	rule.registerIndirectCachePoisoningFixer()
}

func (rule *CachePoisoningRule) registerIndirectCachePoisoningFixer() {
	if rule.unsafeCheckoutStep != nil && !rule.autoFixerRegistered {
		rule.AddAutoFixer(NewStepFixer(rule.unsafeCheckoutStep, rule))
		rule.autoFixerRegistered = true
	}
}

const maxCompositeActionDepth = 4

type compositeActionInspection struct {
	cacheUses         string
	chain             []string
	cacheFound        bool
	resolvedComposite bool
}

func (rule *CachePoisoningRule) inspectCompositeAction(uses string) compositeActionInspection {
	if rule.actionMetadata == nil || uses == "" {
		return compositeActionInspection{}
	}
	return rule.inspectCompositeActionRecursive(uses, nil, make(map[string]bool), 0)
}

func (rule *CachePoisoningRule) inspectCompositeActionRecursive(uses string, chain []string, visited map[string]bool, depth int) compositeActionInspection {
	if uses == "" || depth > maxCompositeActionDepth {
		return compositeActionInspection{}
	}
	if visited[uses] {
		return compositeActionInspection{}
	}
	visited[uses] = true

	meta, err := rule.actionMetadata.FindMetadata(uses)
	if err != nil {
		rule.Debug("failed to resolve action metadata for %s: %v", uses, err)
		return compositeActionInspection{}
	}

	if meta == nil || meta.Runs == nil || !strings.EqualFold(meta.Runs.Using, "composite") {
		return compositeActionInspection{}
	}

	nextChain := append(append([]string{}, chain...), uses)
	for _, step := range meta.Runs.Steps {
		if step == nil || step.Uses == "" {
			continue
		}
		if isCacheAction(step.Uses, metadataStepInputs(step.With)) {
			return compositeActionInspection{
				cacheUses:         step.Uses,
				chain:             append(append([]string{}, nextChain...), step.Uses),
				cacheFound:        true,
				resolvedComposite: true,
			}
		}
		child := rule.inspectCompositeActionRecursive(step.Uses, nextChain, visited, depth+1)
		if child.cacheFound {
			return child
		}
	}

	return compositeActionInspection{chain: nextChain, resolvedComposite: true}
}

func metadataStepInputs(with ActionStepWithMetadata) map[string]*ast.Input {
	if len(with) == 0 {
		return nil
	}

	inputs := make(map[string]*ast.Input, len(with))
	for name, value := range with {
		key := strings.ToLower(name)
		inputs[key] = &ast.Input{
			Name:  &ast.String{Value: name},
			Value: &ast.String{Value: value},
		}
	}
	return inputs
}

// checkDirectCachePoisoning checks for untrusted inputs in cache key/restore-keys/path
func (rule *CachePoisoningRule) checkDirectCachePoisoning(node *ast.Step, action *ast.ExecAction) {
	// Check key input
	if keyInput, ok := action.Inputs["key"]; ok && keyInput != nil && keyInput.Value != nil {
		rule.checkCacheInputForUntrustedExprs(node, "key", keyInput.Value)
		// Check for predictable cache keys
		rule.checkPredictableCacheKey(node, keyInput.Value)
	}

	// Check restore-keys input
	if restoreKeysInput, ok := action.Inputs["restore-keys"]; ok && restoreKeysInput != nil && restoreKeysInput.Value != nil {
		rule.checkCacheInputForUntrustedExprs(node, "restore-keys", restoreKeysInput.Value)
	}

	// Check path input
	if pathInput, ok := action.Inputs["path"]; ok && pathInput != nil && pathInput.Value != nil {
		rule.checkCacheInputForUntrustedExprs(node, "path", pathInput.Value)
	}

	// Check for high-risk context (release/deploy workflows)
	if rule.isReleaseWorkflow {
		rule.Errorf(
			node.Pos,
			"cache poisoning risk in release workflow: cache usage in release/deployment workflows is high-risk. "+
				"Attackers can poison the cache to inject malicious code into releases. "+
				"Consider disabling cache or using isolated cache keys with github.sha",
		)
	}
}

// checkPredictableCacheKey checks if the cache key is predictable (e.g., only hashFiles without unique prefix)
// This enables cache poisoning via Dependabot or similar automated PRs
func (rule *CachePoisoningRule) checkPredictableCacheKey(_ *ast.Step, keyValue *ast.String) {
	if keyValue == nil {
		return
	}

	key := keyValue.Value

	// Check if key only contains hashFiles() without unique identifiers
	// Patterns that make keys predictable:
	// - key: npm-${{ hashFiles('package-lock.json') }}
	// - key: ${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}
	// These are predictable because Dependabot PRs update lock files predictably

	hasHashFiles := strings.Contains(key, "hashFiles(")
	hasUniqueIdentifier := strings.Contains(key, "github.sha") ||
		strings.Contains(key, "github.run_id") ||
		strings.Contains(key, "github.run_number") ||
		strings.Contains(key, "github.run_attempt")

	// If using hashFiles without unique identifier and PR events are enabled,
	// the cache key becomes predictable for Dependabot-style attacks
	if hasHashFiles && !hasUniqueIdentifier && rule.isPullRequestEvent {
		rule.Errorf(
			keyValue.Pos,
			"cache poisoning via predictable key: cache key using hashFiles() without unique identifier (github.sha, github.run_id) "+
				"is predictable in PR workflows. Attackers can pre-poison the cache before Dependabot PRs. "+
				"Add github.sha or github.run_id to make the key unpredictable",
		)
	}
}

// checkCacheInputForUntrustedExprs checks a cache input value for untrusted expressions
func (rule *CachePoisoningRule) checkCacheInputForUntrustedExprs(node *ast.Step, inputName string, inputValue *ast.String) {
	if inputValue == nil {
		return
	}

	// Extract and parse all expressions from the input value
	exprs := rule.extractAndParseExpressions(inputValue)
	for _, expr := range exprs {
		untrustedPaths := rule.checkUntrustedInput(expr)
		if len(untrustedPaths) > 0 {
			// Report the vulnerability
			rule.Errorf(
				expr.pos,
				"cache poisoning via untrusted input: '%s' in cache %s is potentially untrusted. "+
					"An attacker can control the cache key to poison the cache. "+
					"Use trusted inputs like github.sha, hashFiles(), or static values instead",
				strings.Join(untrustedPaths, "', '"),
				inputName,
			)

			// Register auto-fixer for this step
			rule.directCacheFixSteps = append(rule.directCacheFixSteps, &directCacheFixInfo{
				step:      node,
				inputName: inputName,
				expr:      expr.raw,
			})
			rule.AddAutoFixer(NewStepFixer(node, rule))
		}
	}
}

// checkCacheHierarchyExploitation detects cache hierarchy exploitation vulnerabilities
// GitHub Actions caches are scoped by branch - PRs can read caches from their base branch.
// If an attacker can write to the default branch's cache, they can poison all downstream PRs.
func (rule *CachePoisoningRule) checkCacheHierarchyExploitation(node *ast.Step, _ string) {
	// Risk: External triggers (workflow_dispatch, schedule) combined with push to default branch
	// Attackers can trigger workflow_dispatch to write poisoned cache, which PRs will read
	if rule.hasExternalTrigger && rule.hasPushToDefaultBranch {
		rule.Errorf(
			node.Pos,
			"cache hierarchy exploitation risk: workflow with external triggers (%s) and push to default branch "+
				"can be exploited to poison caches. Attacker can trigger workflow_dispatch/schedule to write "+
				"malicious cache that all PRs will read. Consider using PR-scoped cache keys or separate workflows",
			strings.Join(rule.workflowTriggers, ", "),
		)
		return
	}

	// Risk: External triggers alone can write to default branch cache
	if rule.hasExternalTrigger && !rule.hasPushToDefaultBranch {
		// Only warn if there's no branch restriction (workflow runs on default branch by default)
		hasPushTrigger := false
		for _, trigger := range rule.workflowTriggers {
			if trigger == "push" {
				hasPushTrigger = true
				break
			}
		}
		if !hasPushTrigger {
			rule.Errorf(
				node.Pos,
				"cache hierarchy exploitation risk: workflow with external trigger (%s) writes to default branch cache. "+
					"Attackers can exploit this to poison caches read by all PRs. "+
					"Consider using immutable cache keys with github.sha",
				strings.Join(rule.workflowTriggers, ", "),
			)
		}
	}
}

// parsedExpressionCache represents a parsed expression with its position and AST node
type parsedExpressionCache struct {
	raw  string               // Original expression content
	node expressions.ExprNode // Parsed AST node
	pos  *ast.Position        // Position in source
}

// extractAndParseExpressions extracts all expressions from string and parses them
func (rule *CachePoisoningRule) extractAndParseExpressions(str *ast.String) []parsedExpressionCache {
	if str == nil {
		return nil
	}

	value := str.Value
	var result []parsedExpressionCache
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

			result = append(result, parsedExpressionCache{
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
func (rule *CachePoisoningRule) parseExpression(exprStr string) (expressions.ExprNode, *expressions.ExprError) {
	if !strings.HasSuffix(exprStr, "}}") {
		exprStr = exprStr + "}}"
	}
	l := expressions.NewTokenizer(exprStr)
	p := expressions.NewMiniParser()
	return p.Parse(l)
}

// checkUntrustedInput checks if the expression contains untrusted input
func (rule *CachePoisoningRule) checkUntrustedInput(expr parsedExpressionCache) []string {
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

func (rule *CachePoisoningRule) FixStep(node *ast.Step) error {
	if node.BaseNode == nil {
		return nil
	}

	// Check if this is an indirect cache poisoning fix (unsafe checkout)
	if node == rule.unsafeCheckoutStep {
		return RemoveRefFromWith(node.BaseNode)
	}

	// Check if this is a direct cache poisoning fix (untrusted input in cache config)
	for _, fixInfo := range rule.directCacheFixSteps {
		if fixInfo.step == node {
			return rule.fixDirectCachePoisoning(node, fixInfo)
		}
	}

	return nil
}

// fixDirectCachePoisoning fixes direct cache poisoning by suggesting safe alternatives
func (rule *CachePoisoningRule) fixDirectCachePoisoning(node *ast.Step, fixInfo *directCacheFixInfo) error {
	// For key/restore-keys, replace untrusted input with github.sha or hashFiles()
	// For path, we cannot safely auto-fix - just add a comment

	action, ok := node.Exec.(*ast.ExecAction)
	if !ok || action.Uses == nil {
		return nil
	}

	switch fixInfo.inputName {
	case "key", "restore-keys":
		// Replace the untrusted expression with github.sha
		return rule.replaceUntrustedExprInCacheInput(node.BaseNode, fixInfo.inputName, fixInfo.expr)
	case SBOMPath:
		// For path, we cannot safely auto-fix as it depends on the project structure
		// The warning is sufficient to alert users
		return nil
	}

	return nil
}

// replaceUntrustedExprInCacheInput replaces an untrusted expression in cache input with github.sha
func (rule *CachePoisoningRule) replaceUntrustedExprInCacheInput(stepNode *yaml.Node, inputName string, untrustedExpr string) error {
	if stepNode == nil {
		return nil
	}

	for i := 0; i < len(stepNode.Content); i += 2 {
		if i+1 >= len(stepNode.Content) {
			break
		}
		key := stepNode.Content[i]
		val := stepNode.Content[i+1]

		if key.Value == SBOMWith && val.Kind == yaml.MappingNode {
			for j := 0; j < len(val.Content); j += 2 {
				if j+1 >= len(val.Content) {
					break
				}
				withKey := val.Content[j]
				withVal := val.Content[j+1]

				if withKey.Value == inputName {
					// Replace the untrusted expression with github.sha
					oldValue := withVal.Value
					newValue := strings.ReplaceAll(
						oldValue,
						fmt.Sprintf("${{ %s }}", untrustedExpr),
						"${{ github.sha }}",
					)
					newValue = strings.ReplaceAll(
						newValue,
						fmt.Sprintf("${{%s}}", untrustedExpr),
						"${{ github.sha }}",
					)
					withVal.Value = newValue
					return nil
				}
			}
		}
	}
	return nil
}
