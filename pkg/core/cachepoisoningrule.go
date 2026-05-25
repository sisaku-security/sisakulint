package core

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"

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
	jobHasCacheSaveStep    bool
}

// directCacheFixInfo stores information needed for auto-fixing direct cache poisoning
type directCacheFixInfo struct {
	step      *ast.Step
	inputName string // "key", "restore-keys", or "path"
	expr      string // the untrusted expression
}

// directCacheDirectoryWriteInfo records a single write into a package-manager
// cache directory found in a `run:` script. Reports are deferred to
// VisitJobPost so the rule can split severity: a "suspicious" warning when
// no cache-save step follows in the same job, and a "(critical)" warning when
// one does.
type directCacheDirectoryWriteInfo struct {
	cacheDir string
	pos      *ast.Position
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

// isCachePersistingAction reports whether a cache action actually persists the
// cache directory at job end. This is a strict subset of isCacheAction:
// actions/cache (registers a post-job save), actions/cache/save, and
// actions/setup-* with cache: enabled all persist; actions/cache/restore is
// restore-only and never saves, so a restore-only job must not be treated as a
// persistence vector when escalating direct-write reports to "(critical)".
func isCachePersistingAction(uses string, inputs map[string]*ast.Input) bool {
	if uses == "" {
		return false
	}

	actionName := uses
	if idx := strings.Index(uses, "@"); idx != -1 {
		actionName = uses[:idx]
	}

	if actionName == "actions/cache" || actionName == "actions/cache/save" {
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
	rule.jobHasCacheSaveStep = false

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
	rule.flushDirectCacheDirectoryWriteReports()
	return nil
}

// flushDirectCacheDirectoryWriteReports emits per-write diagnostics deferred
// from VisitStep. Severity is split: when a cache-save / setup-* with cache
// followed in the same job, every write is escalated to "(critical)" because
// the persistence vector is real. Without a save in the same job, writes are
// reported as a softer "suspicious" warning so defense-in-depth still surfaces
// the pattern without overstating severity.
func (rule *CachePoisoningRule) flushDirectCacheDirectoryWriteReports() {
	if len(rule.directCacheDirWrites) == 0 {
		return
	}
	defer func() { rule.directCacheDirWrites = nil }()

	if rule.jobHasCacheSaveStep {
		dirs := uniqueCacheDirs(rule.directCacheDirWrites)
		joined := strings.Join(dirs, ", ")
		for _, w := range rule.directCacheDirWrites {
			rule.Errorf(
				w.pos,
				"cache poisoning via package manager cache directory write (critical): "+
					"command writes directly to %s and a cache action in the same job will persist this directory (%s). "+
					"This persists attacker-controlled dependency cache content for later workflow runs; "+
					"avoid writing under cache directories or remove the cache action",
				w.cacheDir,
				joined,
			)
		}
		return
	}

	for _, w := range rule.directCacheDirWrites {
		rule.Errorf(
			w.pos,
			"cache poisoning via package manager cache directory write (suspicious): "+
				"command writes directly to %s. "+
				"Direct writes to dependency cache directories can poison later actions/cache/save entries; "+
				"prefer package manager commands or avoid saving caches after these writes",
			w.cacheDir,
		)
	}
}

// uniqueCacheDirs returns the deduped, order-preserved list of cache
// directories from the recorded writes.
func uniqueCacheDirs(writes []directCacheDirectoryWriteInfo) []string {
	out := make([]string, 0, len(writes))
	seen := make(map[string]bool, len(writes))
	for _, w := range writes {
		if seen[w.cacheDir] {
			continue
		}
		seen[w.cacheDir] = true
		out = append(out, w.cacheDir)
	}
	return out
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

	// Check for cache actions
	if isCacheAction(uses, action.Inputs) {
		// Only save-capable cache steps (actions/cache, actions/cache/save, or
		// actions/setup-* with cache: enabled) persist whatever sits under the
		// cache path at job end. Track that a save will happen so deferred direct
		// cache directory write reports can be upgraded to critical in
		// VisitJobPost. actions/cache/restore is restore-only and must not flip
		// this flag, otherwise restore-only jobs are over-escalated to critical.
		if isCachePersistingAction(uses, action.Inputs) {
			rule.jobHasCacheSaveStep = true
		}
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

// packageManagerCacheRoots lists the canonical home-relative roots that
// actions/cache and actions/setup-* persist for each major package manager
// available on GitHub-hosted runners. Each root is matched after path
// normalization (~ / $HOME / ${HOME} / /home/runner / /Users/runner /
// /root → ~), so callers do not need per-prefix duplication.
//
// Order is informational; matching uses HasPrefix with a path-boundary
// check, so e.g. "~/.npm/_cacache" still matches the "~/.npm" root and is
// reported using the canonical root path. This keeps the rule resilient to
// the most common workflow pattern: a write into the well-known parent
// directory that the cache action then persists wholesale.
var packageManagerCacheRoots = []string{
	// JavaScript ecosystem
	"~/.npm",                   // actions/setup-node default
	"~/.cache/yarn",            // yarn classic / berry global cache
	"~/.yarn/cache",            // yarn berry workspace cache
	"~/.local/share/pnpm/store", // pnpm linux/mac default
	"~/.cache/pnpm",            // pnpm alt store-dir
	// Python ecosystem
	"~/.cache/pip",         // pip default
	"~/.cache/pypoetry",    // poetry default
	// Rust
	"~/.cargo",
	// JVM
	"~/.gradle",
	"~/.m2",
	// Go
	"~/go/pkg/mod",
	// Ruby
	"~/.bundle/cache",
	"vendor/bundle",
	// PHP
	"~/.composer/cache",
	"~/.cache/composer",
	// .NET
	"~/.nuget/packages",
}

// cacheRootPathPrefixes are alternate path forms that normalize to "~/" before
// catalog matching. Order matters: longer prefixes must come before shorter
// ones so "/home/runner" wins over "/home" for runner home detection.
var cacheRootPathPrefixes = []string{
	"/home/runner/",  // GitHub Linux runner home
	"/Users/runner/", // GitHub macOS runner home
	"/root/",         // self-hosted root
	"$HOME/",
	"${HOME}/",
	"$home/",   // case-insensitive match handled below
	"${home}/", // case-insensitive match handled below
	"~/",
}

// packageManagerCommands lists the package manager front-ends whose own
// internal cache writes are intentional and must not be reported.
// "go" is intentionally NOT in this set: `go install`, `go mod download`,
// `go build` populate ~/go/pkg/mod legitimately, but we cannot tell those
// apart from `go run ./scripts/poison.go ~/go/pkg/mod` from a single token.
// Distinguishing requires deeper subcommand awareness; for now the rule
// accepts the FN/FP trade-off for the rarer hostile go invocation in
// favour of detecting hand-rolled writes to the cache root.
var packageManagerCommands = map[string]bool{
	"npm":      true,
	"npx":      true,
	"pnpm":    true,
	"yarn":    true,
	"pip":     true,
	"pip3":    true,
	"python":  true,
	"python3": true,
	"poetry":  true,
	"cargo":   true,
	"gradle":  true,
	"mvn":     true,
	"bundle":  true,
	"bundler": true,
	"composer": true,
	"dotnet":  true,
	"nuget":   true,
}

// cacheDirectoryWriteCommands enumerates utilities whose primary purpose is
// to mutate filesystem state and that this rule recognizes when the target
// path resolves under a cache root. Membership controls *eligibility* — the
// presence of a cache-directory argument or stdout redirection is then
// evaluated by checkCallExprWritesCacheDirectory.
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
	"tar":     true,
	"unzip":   true,
	"rsync":   true,
	"rm":      true,
	"chmod":   true,
	"chown":   true,
	"sed":     true, // only with -i (in-place edit) — checked at call site
	"curl":    true, // only with -o / -O (output) — checked at call site
	"wget":    true, // only with -O — checked at call site
	"git":     true, // only with `clone <repo> <cache-dir>` — checked at call site
	"dd":      true, // only with `of=<cache-dir>` — checked at call site
}

// shellPrefixCommands are wrappers that take an inner command. When seen as
// the call's first arg, the rule looks past their flags for the inner command.
// `sh` / `bash` / `zsh` are NOT here: those wrap an inline script which the
// AST walker recurses into separately (see walkInlineShellScript).
var shellPrefixCommands = map[string]bool{
	"command":   true,
	"env":       true,
	"nohup":     true,
	"sudo":      true,
	"time":      true,
	"timeout":   true,
	"stdbuf":    true,
	"unbuffer":  true,
	"ionice":    true,
	"nice":      true,
}

// checkDirectCacheDirectoryWrite scans a `run:` script for direct writes to
// package-manager cache directories using the shared bash AST. Reports are
// deferred to VisitJobPost via rule.directCacheDirWrites so severity can be
// split based on whether a cache-save action follows in the same job.
//
// Known limitation: detection operates on bash AST tokens. A cache-directory
// path computed at runtime from an external variable (e.g.
// `mkdir -p "$CACHE_ROOT/.npm"`) is not resolved and will be missed.
// Suppression: the workflow author can use `-ignore "cache-poisoning"` for
// false positives.
func (rule *CachePoisoningRule) checkDirectCacheDirectoryWrite(run *ast.ExecRun) {
	if run == nil || run.Run == nil {
		return
	}

	script := run.Run.Value
	sanitized, _ := sanitizeForShellParse(script)
	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(sanitized), "")
	if err != nil || file == nil {
		// Silent skip on parse failure mirrors taint.go / secretinlog.go and
		// trades FN risk on malformed shell for FP-quietness on inputs the
		// outer parser may have accepted.
		return
	}

	rule.walkShellAST(file, sanitized, run.Run)
}

// walkShellAST traverses the parsed bash file looking for direct cache-
// directory writes inside CallExpr nodes (including those nested in
// pipelines, &&/|| chains, $(…), bash -c '…' wrappers, etc.). Stmt-level
// redirections (>, >>, &>, &>>, >|) are evaluated on every statement so that
// `echo x > ~/.npm/foo`, `> ~/.npm/foo`, and `cmd >> ~/.cargo/bar` are all
// recorded — the shell parser hangs the redirect list on the Stmt, not on
// the inner CallExpr.
func (rule *CachePoisoningRule) walkShellAST(file *syntax.File, script string, runStr *ast.String) {
	syntax.Walk(file, func(node syntax.Node) bool {
		switch x := node.(type) {
		case *syntax.CallExpr:
			rule.checkCallExprWritesCacheDirectory(x, script, runStr)
		case *syntax.Stmt:
			rule.recordWritesFromRedirects(x.Redirs, script, runStr)
		}
		return true
	})
}

// checkCallExprWritesCacheDirectory inspects a single CallExpr for cache-
// directory writes. Strategy:
//  1. Resolve the effective inner command past wrapper prefixes (sudo / env /
//     nohup …) and shell wrappers (sh -c '…', which is recursed into via the
//     AST walker on the inline script content).
//  2. If the inner command is a package-manager front-end, skip — the
//     rule trusts those tools to manage their own cache.
//  3. Check redirections (>, >>) on the call's parent Stmt for cache-
//     directory targets; report any.
//  4. For known write commands (mkdir/touch/cp/mv/install/tee/tar/unzip/
//     rsync/rm/chmod/sed -i / curl -o,-O / wget -O / git clone / dd of=…)
//     check the relevant argument positions for cache-directory paths.
func (rule *CachePoisoningRule) checkCallExprWritesCacheDirectory(call *syntax.CallExpr, script string, runStr *ast.String) {
	if len(call.Args) == 0 {
		return
	}

	cmdName, argStart, ok := unwrapCommandPrefixes(call)
	if !ok {
		return
	}

	// Recurse into bash/sh -c '...' inline scripts. The outer walk would
	// otherwise see only the wrapper call and miss the inner commands.
	if isInlineShellWrapper(cmdName) {
		rule.walkInlineShellScript(call, argStart, script, runStr)
		return
	}

	// Package-manager front-ends populate cache directories legitimately.
	// `go` is intentionally NOT excluded here — see comment on
	// packageManagerCommands.
	if packageManagerCommands[cmdName] {
		return
	}

	// Redirection writes (echo "x" > ~/.npm/y, printf '%s' "p" >> ~/.cargo/z).
	// Stmt redirects live one level up; they are handled by the walker's
	// dedicated *syntax.Stmt branch via recordWritesFromRedirects. The call
	// here also recognizes write-by-redirection for common producers
	// (cat / echo / printf / tee).

	if !cacheDirectoryWriteCommands[cmdName] {
		return
	}

	// Per-command argument shape.
	switch cmdName {
	case "mkdir", "touch", "rm", "chmod", "chown":
		// Treat any cache-directory path argument as a write target.
		for _, arg := range call.Args[argStart+1:] {
			if dir, ok := matchCacheDirectoryArg(arg); ok {
				rule.recordCacheDirectoryWrite(dir, arg.Pos(), script, runStr)
			}
		}
	case "cp", "mv", "install", "rsync":
		// The destination is the LAST non-flag positional argument. Any other
		// cache-directory argument is reading from / mirroring out of the cache,
		// which we do not flag.
		if dest, dir, ok := lastNonFlagWithCacheDir(call.Args[argStart+1:]); ok {
			rule.recordCacheDirectoryWrite(dir, dest.Pos(), script, runStr)
		}
	case "tee":
		// `tee` writes every positional argument (excluding flags). Any cache
		// directory path among them is a write target.
		for _, arg := range call.Args[argStart+1:] {
			if isLikelyFlagWord(arg) {
				continue
			}
			if dir, ok := matchCacheDirectoryArg(arg); ok {
				rule.recordCacheDirectoryWrite(dir, arg.Pos(), script, runStr)
			}
		}
	case "tar":
		// Only flag tar when extracting (-x / --extract / -xf …) into a
		// cache directory. `tar -t / -c / -z` etc. are not writes.
		if !tarIsExtract(call.Args[argStart+1:]) {
			return
		}
		// Destination follows -C / --directory; otherwise it's the cwd, which
		// we cannot resolve. Flag any explicit cache-directory destination.
		if dir, pos, ok := tarExtractDest(call.Args[argStart+1:]); ok {
			rule.recordCacheDirectoryWrite(dir, pos, script, runStr)
		}
	case "unzip":
		// `unzip <archive> -d <dest>` — flag cache-directory destinations.
		if dir, pos, ok := unzipDest(call.Args[argStart+1:]); ok {
			rule.recordCacheDirectoryWrite(dir, pos, script, runStr)
		}
	case "sed":
		// Only flag `sed -i ... <cache-dir-file>` (in-place edit).
		if !hasFlagWord(call.Args[argStart+1:], "-i") {
			return
		}
		for _, arg := range call.Args[argStart+1:] {
			if isLikelyFlagWord(arg) {
				continue
			}
			if dir, ok := matchCacheDirectoryArg(arg); ok {
				rule.recordCacheDirectoryWrite(dir, arg.Pos(), script, runStr)
			}
		}
	case "curl":
		// `curl -o <dest>` or `curl -O` (uses URL basename in cwd, can't
		// statically resolve the destination — rely on -o here).
		if dir, pos, ok := curlOutputDest(call.Args[argStart+1:]); ok {
			rule.recordCacheDirectoryWrite(dir, pos, script, runStr)
		}
	case "wget":
		// `wget -O <dest>` or `--output-document=<dest>`.
		if dir, pos, ok := wgetOutputDest(call.Args[argStart+1:]); ok {
			rule.recordCacheDirectoryWrite(dir, pos, script, runStr)
		}
	case "git":
		// `git clone <url> <cache-dir>` is the realistic supply-chain shape.
		if dir, pos, ok := gitCloneDest(call.Args[argStart+1:]); ok {
			rule.recordCacheDirectoryWrite(dir, pos, script, runStr)
		}
	case "dd":
		// `dd if=… of=<cache-dir>` writes raw bytes to the destination.
		if dir, pos, ok := ddOutputDest(call.Args[argStart+1:]); ok {
			rule.recordCacheDirectoryWrite(dir, pos, script, runStr)
		}
	case "cat", "echo", "printf":
		// These only "write" when redirected; the redirection check on the
		// parent Stmt covers it. Nothing to do at the call level.
	}
}

// recordWritesFromRedirects scans Stmt-level redirections for output writes
// (>, >>, &>, &>>, |&) into cache directories and records them. Position
// uses the redirect target word.
func (rule *CachePoisoningRule) recordWritesFromRedirects(redirs []*syntax.Redirect, script string, runStr *ast.String) {
	for _, r := range redirs {
		if r == nil || r.Word == nil {
			continue
		}
		if !isOutputRedirect(r.Op) {
			continue
		}
		if dir, ok := matchCacheDirectoryArg(r.Word); ok {
			rule.recordCacheDirectoryWrite(dir, r.Word.Pos(), script, runStr)
		}
	}
}

// recordCacheDirectoryWrite stores a deferred write report. The report is
// emitted in VisitJobPost with severity scaled to whether a cache-save step
// followed in the same job.
func (rule *CachePoisoningRule) recordCacheDirectoryWrite(cacheDir string, pos syntax.Pos, script string, runStr *ast.String) {
	rule.directCacheDirWrites = append(rule.directCacheDirWrites, directCacheDirectoryWriteInfo{
		cacheDir: cacheDir,
		pos:      shellPosToASTPos(pos, script, runStr),
	})
}

// shellPosToASTPos converts a bash-AST position back into the workflow YAML
// coordinate space. Falls back to the run-string position when the offset
// cannot be resolved (e.g. position synthesized by re-parsed inline script).
// Never returns nil — callers pass directly to Errorf.
func shellPosToASTPos(pos syntax.Pos, script string, runStr *ast.String) *ast.Position {
	if runStr == nil {
		// Should not happen in practice; preserves Errorf invariant.
		return &ast.Position{Line: 1, Col: 1}
	}
	if pos.IsValid() {
		offset := int(pos.Offset())
		if offset <= len(script) {
			return offsetToPosition(runStr, script, offset)
		}
	}
	if runStr.Pos != nil {
		out := *runStr.Pos
		if runStr.Literal {
			out.Line++
		}
		return &out
	}
	return &ast.Position{Line: 1, Col: 1}
}

// unwrapCommandPrefixes resolves the effective command name past sudo/env/
// nohup/etc. wrappers. Returns (cmdName, indexOfCommandWordIntoCall.Args, ok).
// When the call has no recognizable command, returns "", 0, false.
func unwrapCommandPrefixes(call *syntax.CallExpr) (string, int, bool) {
	for i := 0; i < len(call.Args); i++ {
		word := call.Args[i]
		token := bashWordLiteral(word)
		if token == "" {
			return "", 0, false
		}
		// Skip leading VAR=VALUE assignments that bash allows before a command.
		if isVarAssignmentWord(token) {
			continue
		}
		lower := strings.ToLower(token)
		if shellPrefixCommands[lower] {
			// Skip any flag args belonging to the wrapper (`sudo -E`,
			// `env FOO=bar`, `timeout 5s`, …). We don't model each wrapper's
			// option grammar precisely — we just skip subsequent args that
			// look like flags or assignments until we hit a bare token.
			for j := i + 1; j < len(call.Args); j++ {
				next := bashWordLiteral(call.Args[j])
				if next == "" {
					return "", 0, false
				}
				if next == "--" {
					i = j
					continue
				}
				if isLikelyFlagToken(next) || isVarAssignmentWord(next) {
					continue
				}
				// `timeout 5s curl` / `nice 10 curl` — skip the wrapper's
				// positional value (a duration or numeric priority) but only when
				// it actually looks like one. A bare command such as `mkdir` in
				// `timeout mkdir` must NOT be consumed here, otherwise the real
				// command is skipped and the write goes undetected.
				if (lower == "timeout" || lower == "nice" || lower == "ionice") && isLikelyWrapperArg(next) {
					i = j
					continue
				}
				return strings.ToLower(next), j, true
			}
			return "", 0, false
		}
		return lower, i, true
	}
	return "", 0, false
}

// isInlineShellWrapper reports whether cmdName is a shell that may be invoked
// with `-c` to execute an inline script.
func isInlineShellWrapper(cmdName string) bool {
	switch cmdName {
	case "sh", "bash", "zsh", "ksh", "dash":
		return true
	}
	return false
}

// walkInlineShellScript handles `bash -c 'inner script'` form: it locates the
// inline script following `-c`, re-parses it, and walks it for cache-directory
// writes. Position information for findings is best-effort — it points back
// to the wrapper call's position so reports remain near the user's source.
func (rule *CachePoisoningRule) walkInlineShellScript(call *syntax.CallExpr, argStart int, script string, runStr *ast.String) {
	// Find -c followed by the inline script.
	args := call.Args[argStart+1:]
	for i, arg := range args {
		token := bashWordLiteral(arg)
		if token != "-c" || i+1 >= len(args) {
			continue
		}
		inner := bashWordLiteral(args[i+1])
		if inner == "" {
			return
		}
		parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
		innerFile, err := parser.Parse(strings.NewReader(inner), "")
		if err != nil || innerFile == nil {
			return
		}
		// Use the wrapper call's position as the report position so the
		// finding maps to a meaningful spot in the workflow file.
		fallbackPos := args[i+1].Pos()
		syntax.Walk(innerFile, func(node syntax.Node) bool {
			switch x := node.(type) {
			case *syntax.CallExpr:
				rule.checkCallExprForInlineWrapper(x, fallbackPos, script, runStr)
			case *syntax.Stmt:
				// Inspect redirects regardless of whether the statement also has
				// a command, mirroring the top-level walkShellAST handling.
				// `bash -c 'echo x > ~/.npm/foo'` has both a command (echo) and a
				// redirect; gating on x.Cmd == nil here would miss the redirect.
				for _, r := range x.Redirs {
					if r == nil || r.Word == nil || !isOutputRedirect(r.Op) {
						continue
					}
					if dir, ok := matchCacheDirectoryArg(r.Word); ok {
						rule.recordCacheDirectoryWrite(dir, fallbackPos, script, runStr)
					}
				}
			}
			return true
		})
		return
	}
}

// checkCallExprForInlineWrapper is checkCallExprWritesCacheDirectory but
// records every find using the wrapper's outer position rather than offsets
// into the inner re-parsed script (which would be meaningless to the user).
func (rule *CachePoisoningRule) checkCallExprForInlineWrapper(call *syntax.CallExpr, fallbackPos syntax.Pos, script string, runStr *ast.String) {
	if len(call.Args) == 0 {
		return
	}
	cmdName, argStart, ok := unwrapCommandPrefixes(call)
	if !ok || !cacheDirectoryWriteCommands[cmdName] {
		// Don't recurse further into nested wrappers from inside an inline
		// wrapper to keep depth bounded; deeper nests are rare in practice.
		return
	}
	if packageManagerCommands[cmdName] {
		return
	}
	// Reuse argument-shape logic by faking an outer-position record.
	flag := func(dir string) {
		rule.recordCacheDirectoryWrite(dir, fallbackPos, script, runStr)
	}
	switch cmdName {
	case "mkdir", "touch", "rm", "chmod", "chown":
		for _, arg := range call.Args[argStart+1:] {
			if dir, ok := matchCacheDirectoryArg(arg); ok {
				flag(dir)
			}
		}
	case "cp", "mv", "install", "rsync":
		if _, dir, ok := lastNonFlagWithCacheDir(call.Args[argStart+1:]); ok {
			flag(dir)
		}
	case "tee":
		for _, arg := range call.Args[argStart+1:] {
			if isLikelyFlagWord(arg) {
				continue
			}
			if dir, ok := matchCacheDirectoryArg(arg); ok {
				flag(dir)
			}
		}
	case "tar":
		if tarIsExtract(call.Args[argStart+1:]) {
			if dir, _, ok := tarExtractDest(call.Args[argStart+1:]); ok {
				flag(dir)
			}
		}
	case "unzip":
		if dir, _, ok := unzipDest(call.Args[argStart+1:]); ok {
			flag(dir)
		}
	case "sed":
		if hasFlagWord(call.Args[argStart+1:], "-i") {
			for _, arg := range call.Args[argStart+1:] {
				if isLikelyFlagWord(arg) {
					continue
				}
				if dir, ok := matchCacheDirectoryArg(arg); ok {
					flag(dir)
				}
			}
		}
	case "curl":
		if dir, _, ok := curlOutputDest(call.Args[argStart+1:]); ok {
			flag(dir)
		}
	case "wget":
		if dir, _, ok := wgetOutputDest(call.Args[argStart+1:]); ok {
			flag(dir)
		}
	case "git":
		if dir, _, ok := gitCloneDest(call.Args[argStart+1:]); ok {
			flag(dir)
		}
	case "dd":
		if dir, _, ok := ddOutputDest(call.Args[argStart+1:]); ok {
			flag(dir)
		}
	}
}

// matchCacheDirectoryArg checks whether word's resolved literal value points
// under one of the package-manager cache roots and returns the canonical
// root path (e.g. "~/.npm") on a hit.
func matchCacheDirectoryArg(word *syntax.Word) (string, bool) {
	if word == nil {
		return "", false
	}
	literal := bashWordLiteral(word)
	if literal == "" {
		return "", false
	}
	return matchCacheDirectoryPath(literal)
}

// matchCacheDirectoryPath normalizes path and reports the matching cache root.
// Matching is path-boundary-aware: "~/.npm-bad" does NOT match "~/.npm" but
// "~/.npm" or "~/.npm/foo" does.
func matchCacheDirectoryPath(p string) (string, bool) {
	normalized := normalizeCachePath(p)
	if normalized == "" {
		return "", false
	}
	for _, root := range packageManagerCacheRoots {
		if normalized == root || strings.HasPrefix(normalized, root+"/") {
			return root, true
		}
	}
	return "", false
}

// normalizeCachePath strips surrounding quotes and rewrites the home prefix
// to "~". Home-prefixed forms ($HOME/, /home/runner/, …) collapse to "~/…";
// "~" alone stays "~". Paths without a recognized home prefix are preserved
// verbatim (trailing slash trimmed) so relative cache roots such as
// "vendor/bundle" still match; absolute or unrelated paths fall through here
// too but match no catalog root. Lower-cases the prefix portion only (paths
// under home are case-sensitive on Linux runners).
func normalizeCachePath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, `"'`)
	if p == "" {
		return ""
	}
	// Re-trim after quote removal in case of `"'~/.npm'"` etc.
	p = strings.Trim(p, `"'`)
	for _, prefix := range cacheRootPathPrefixes {
		if strings.HasPrefix(p, prefix) {
			rest := p[len(prefix):]
			return "~/" + strings.TrimRight(rest, "/")
		}
		// Case-insensitive variant for $home / ${home}.
		if len(p) >= len(prefix) && strings.EqualFold(p[:len(prefix)], prefix) {
			rest := p[len(prefix):]
			return "~/" + strings.TrimRight(rest, "/")
		}
	}
	if p == "~" {
		return "~"
	}
	return strings.TrimRight(p, "/")
}

// bashWordLiteral concatenates literal segments of a Word. Returns the empty
// string when the Word has no literal contribution (purely variable expansion
// such as "$DIR"). Param expansions and command substitutions resolve to a
// printed form; this is fine for command-name detection but *not* for
// cache-directory path matching, which uses extractLiteralValue-style
// concatenation that would confuse "$DIR/foo" with a literal — see
// matchCacheDirectoryArg, which uses bashWordLiteral and therefore tolerates
// false negatives on fully-dynamic paths in exchange for FP-quietness.
func bashWordLiteral(word *syntax.Word) string {
	if word == nil {
		return ""
	}
	var b strings.Builder
	bashWordLiteralInto(word, &b)
	return strings.TrimSpace(b.String())
}

func bashWordLiteralInto(word *syntax.Word, b *strings.Builder) {
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				switch ip := inner.(type) {
				case *syntax.Lit:
					b.WriteString(ip.Value)
				case *syntax.ParamExp:
					// Preserve the variable name so HOME-form prefixes in
					// "$HOME/.npm" / "${HOME}/.npm" are matched. Other vars
					// remain visible and harmlessly fail matchCacheDirectoryPath.
					if ip.Param != nil {
						if ip.Short {
							b.WriteString("$")
							b.WriteString(ip.Param.Value)
						} else {
							b.WriteString("${")
							b.WriteString(ip.Param.Value)
							b.WriteString("}")
						}
					}
				}
			}
		case *syntax.ParamExp:
			if p.Param != nil {
				if p.Short {
					b.WriteString("$")
					b.WriteString(p.Param.Value)
				} else {
					b.WriteString("${")
					b.WriteString(p.Param.Value)
					b.WriteString("}")
				}
			}
		}
	}
}

// isLikelyFlagWord checks if the first literal segment of word starts with "-".
func isLikelyFlagWord(word *syntax.Word) bool {
	if word == nil {
		return false
	}
	lit := bashWordLiteral(word)
	return isLikelyFlagToken(lit)
}

// isLikelyFlagToken is the string analogue of isLikelyFlagWord.
func isLikelyFlagToken(token string) bool {
	return strings.HasPrefix(token, "-") && token != "-" && token != "--"
}

// isLikelyWrapperArg reports whether token looks like a positional value
// consumed by timeout/nice/ionice — a duration such as "5s" / "1.5m" / "30" or
// a bare numeric priority — rather than the wrapped command itself. This keeps
// `timeout 5s mkdir …` consuming "5s" while still returning "mkdir", and stops
// `timeout mkdir …` from swallowing the real command.
func isLikelyWrapperArg(token string) bool {
	if token == "" {
		return false
	}
	// Optional trailing duration unit accepted by timeout (s/m/h/d).
	body := token
	switch body[len(body)-1] {
	case 's', 'm', 'h', 'd':
		body = body[:len(body)-1]
	}
	if body == "" {
		return false
	}
	dotSeen := false
	for _, ch := range body {
		if ch == '.' {
			if dotSeen {
				return false
			}
			dotSeen = true
			continue
		}
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// isVarAssignmentWord reports whether token is a leading shell var assignment
// like FOO=bar that bash permits before a command.
func isVarAssignmentWord(token string) bool {
	idx := strings.Index(token, "=")
	if idx <= 0 {
		return false
	}
	for _, ch := range token[:idx] {
		if !(ch == '_' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {
			return false
		}
	}
	return true
}

// lastNonFlagWithCacheDir returns the LAST non-flag positional argument in
// args along with its matched cache root, when that argument resolves under
// a cache directory. Used by cp / mv / install / rsync where the destination
// is the last positional argument.
func lastNonFlagWithCacheDir(args []*syntax.Word) (*syntax.Word, string, bool) {
	for i := len(args) - 1; i >= 0; i-- {
		w := args[i]
		if w == nil || isLikelyFlagWord(w) {
			continue
		}
		if dir, ok := matchCacheDirectoryArg(w); ok {
			return w, dir, true
		}
		return nil, "", false
	}
	return nil, "", false
}

// hasFlagWord scans args for a literal flag (e.g. "-i") presence.
func hasFlagWord(args []*syntax.Word, flag string) bool {
	for _, w := range args {
		if bashWordLiteral(w) == flag {
			return true
		}
	}
	return false
}

// tarIsExtract reports whether the tar invocation is an extraction.
// Recognized forms: -x as standalone flag, --extract, or any combined short
// flag including 'x' (e.g. -xzf, -xvf, -xf).
func tarIsExtract(args []*syntax.Word) bool {
	for _, w := range args {
		t := bashWordLiteral(w)
		switch {
		case t == "-x", t == "--extract":
			return true
		case strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--") && strings.ContainsRune(t, 'x'):
			return true
		}
	}
	return false
}

// tarExtractDest returns the cache-directory destination passed via -C / --directory.
func tarExtractDest(args []*syntax.Word) (string, syntax.Pos, bool) {
	for i, w := range args {
		t := bashWordLiteral(w)
		if t == "-C" || t == "--directory" {
			if i+1 >= len(args) {
				return "", syntax.Pos{}, false
			}
			dest := args[i+1]
			if dir, ok := matchCacheDirectoryArg(dest); ok {
				return dir, dest.Pos(), true
			}
			return "", syntax.Pos{}, false
		}
		if strings.HasPrefix(t, "--directory=") {
			path := strings.TrimPrefix(t, "--directory=")
			if dir, ok := matchCacheDirectoryPath(path); ok {
				return dir, w.Pos(), true
			}
		}
	}
	return "", syntax.Pos{}, false
}

// unzipDest returns the cache-directory destination after `-d`.
func unzipDest(args []*syntax.Word) (string, syntax.Pos, bool) {
	for i, w := range args {
		if bashWordLiteral(w) == "-d" && i+1 < len(args) {
			dest := args[i+1]
			if dir, ok := matchCacheDirectoryArg(dest); ok {
				return dir, dest.Pos(), true
			}
		}
	}
	return "", syntax.Pos{}, false
}

// curlOutputDest returns the destination from `curl -o <dest>` /
// `curl --output <dest>`. `-O` uses the URL's basename in cwd; we cannot
// resolve cwd statically so it is not flagged.
func curlOutputDest(args []*syntax.Word) (string, syntax.Pos, bool) {
	for i, w := range args {
		t := bashWordLiteral(w)
		if (t == "-o" || t == "--output") && i+1 < len(args) {
			dest := args[i+1]
			if dir, ok := matchCacheDirectoryArg(dest); ok {
				return dir, dest.Pos(), true
			}
		}
		if strings.HasPrefix(t, "--output=") {
			path := strings.TrimPrefix(t, "--output=")
			if dir, ok := matchCacheDirectoryPath(path); ok {
				return dir, w.Pos(), true
			}
		}
	}
	return "", syntax.Pos{}, false
}

// wgetOutputDest returns the destination from `wget -O <dest>` /
// `wget --output-document=<dest>`.
func wgetOutputDest(args []*syntax.Word) (string, syntax.Pos, bool) {
	for i, w := range args {
		t := bashWordLiteral(w)
		if t == "-O" && i+1 < len(args) {
			dest := args[i+1]
			if dir, ok := matchCacheDirectoryArg(dest); ok {
				return dir, dest.Pos(), true
			}
		}
		if strings.HasPrefix(t, "--output-document=") {
			path := strings.TrimPrefix(t, "--output-document=")
			if dir, ok := matchCacheDirectoryPath(path); ok {
				return dir, w.Pos(), true
			}
		}
	}
	return "", syntax.Pos{}, false
}

// gitCloneDest returns the destination directory of `git clone <repo> <dir>`.
// Skips clone-mode flags (--depth N, --branch X, etc.); without exhaustive
// option modelling some FN remain on long flag lists, but the typical
// supply-chain shape `git clone <url> <dest>` is detected.
func gitCloneDest(args []*syntax.Word) (string, syntax.Pos, bool) {
	if len(args) == 0 {
		return "", syntax.Pos{}, false
	}
	if bashWordLiteral(args[0]) != "clone" {
		return "", syntax.Pos{}, false
	}
	// Collect non-flag positional args after `clone`.
	var positional []*syntax.Word
	for j := 1; j < len(args); j++ {
		w := args[j]
		if w == nil {
			continue
		}
		t := bashWordLiteral(w)
		if isLikelyFlagToken(t) {
			// Common flags consume a value: --depth N, --branch X, -b X, -o X.
			switch t {
			case "--depth", "--branch", "-b", "-o", "--origin", "--config", "-c",
				"--separate-git-dir", "--reference", "--template", "--shallow-since",
				"--shallow-exclude", "--filter", "--server-option", "-j", "--jobs":
				j++ // skip the value
			}
			continue
		}
		positional = append(positional, w)
	}
	if len(positional) < 2 {
		return "", syntax.Pos{}, false
	}
	dest := positional[1]
	if dir, ok := matchCacheDirectoryArg(dest); ok {
		return dir, dest.Pos(), true
	}
	return "", syntax.Pos{}, false
}

// ddOutputDest returns the destination from a `dd of=<path>` argument.
func ddOutputDest(args []*syntax.Word) (string, syntax.Pos, bool) {
	for _, w := range args {
		t := bashWordLiteral(w)
		if !strings.HasPrefix(t, "of=") {
			continue
		}
		path := strings.TrimPrefix(t, "of=")
		if dir, ok := matchCacheDirectoryPath(path); ok {
			return dir, w.Pos(), true
		}
	}
	return "", syntax.Pos{}, false
}

// isOutputRedirect reports whether op is one of the bash output-redirect
// operators that writes (truncates or appends) to the right-hand-side path.
func isOutputRedirect(op syntax.RedirOperator) bool {
	switch op {
	case syntax.RdrOut, // >
		syntax.AppOut,    // >>
		syntax.RdrAll,    // &>
		syntax.AppAll,    // &>>
		syntax.RdrClob,   // >|
		syntax.AppClob,   // >>| (zsh)
		syntax.RdrAllClob, // &>| (zsh)
		syntax.AppAllClob: // &>>| (zsh)
		return true
	}
	return false
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
