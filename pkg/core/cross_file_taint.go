package core

import (
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// workspaceLike is the minimal contract ResolvePendingChains needs to
// inject post-Wait errors and fixers into per-file results.
type workspaceLike interface {
	Path() string
	AppendError(err *LintingError)
	AppendAutoFixer(fx AutoFixer)
}

// workspaceAdapter wraps the linter's anonymous workspace struct.
type workspaceAdapter struct {
	path   string
	result *ValidateResult
}

func (w *workspaceAdapter) Path() string { return w.path }

func (w *workspaceAdapter) AppendError(err *LintingError) {
	if w.result == nil || err == nil {
		return
	}
	if err.FilePath == "" {
		err.FilePath = w.path
	}
	w.result.Errors = append(w.result.Errors, err)
}

func (w *workspaceAdapter) AppendAutoFixer(fx AutoFixer) {
	if w.result == nil || fx == nil {
		return
	}
	w.result.AutoFixers = append(w.result.AutoFixers, fx)
}

// findWorkspace returns the adapter whose path matches normPath, or nil.
// Comparison uses exact string match — callers must normalize paths
// upstream (e.g. via PathToWorkflowSpecification or filepath.Clean).
func findWorkspace(ws []workspaceLike, normPath string) workspaceLike {
	for _, w := range ws {
		if w.Path() == normPath {
			return w
		}
	}
	return nil
}

// filterCallersWithPos drops entries with nil Pos so downstream emit
// helpers can dereference Pos safely. Reuses the input slice's backing
// array — safe because CallersOf returns a fresh copy.
func filterCallersWithPos(in []*CallerTaint) []*CallerTaint {
	out := in[:0]
	for _, c := range in {
		if c != nil && c.Pos != nil {
			out = append(out, c)
		}
	}
	return out
}

// filterSinksWithPos drops entries with nil Pos so downstream emit
// helpers can dereference Pos safely. Reuses the input slice's backing
// array — safe because SinksOf returns a fresh copy.
func filterSinksWithPos(in []*CalleeSink) []*CalleeSink {
	out := in[:0]
	for _, s := range in {
		if s != nil && s.Pos != nil {
			out = append(out, s)
		}
	}
	return out
}

// chainKey dedupes by (caller file path, caller pos, sink pos) so the
// same flow only generates one warning even if recorded multiple times.
// callerPath is included so two callers from different files at
// coincidentally identical positions are not collapsed into one warning.
type chainKey struct {
	callerPath                               string
	callerLine, callerCol, sinkLine, sinkCol int
}

// stepKey groups callee sinks by their containing step so a single
// ChainFixer can lift multiple inputs in one shot.
type stepKey struct {
	path string
	step *ast.Step
}

// ResolvePendingChains correlates caller × callee taint state captured
// during validate() and emits chain warnings (or callee-solo warnings)
// into the appropriate workspaces. Must run single-threaded after
// errgroup.Wait() — no internal locking on workspace results.
func (c *LocalReusableWorkflowCache) ResolvePendingChains(ws []workspaceLike) {
	if c == nil || !c.IsChainResolutionEnabled() {
		return
	}
	for _, spec := range c.CalleeSpecs() {
		callers := c.CallersOf(spec)
		sinks := c.SinksOf(spec)
		callers = filterCallersWithPos(callers)
		sinks = filterSinksWithPos(sinks)

		if len(callers) == 0 && len(sinks) > 0 {
			c.emitCalleeSoloWarnings(ws, sinks)
			continue
		}
		if len(sinks) == 0 {
			continue
		}

		seen := make(map[chainKey]struct{})
		stepSinks := make(map[stepKey][]*CalleeSink)
		for _, caller := range callers {
			for _, sink := range sinks {
				if caller.InputName != sink.InputName {
					continue
				}
				k := chainKey{caller.CallerWorkflowPath, caller.Pos.Line, caller.Pos.Col, sink.Pos.Line, sink.Pos.Col}
				if _, dup := seen[k]; dup {
					continue
				}
				seen[k] = struct{}{}
				c.emitChainWarning(ws, caller, sink)
				sk := stepKey{path: sink.CalleeWorkflowPath, step: sink.Step}
				stepSinks[sk] = append(stepSinks[sk], sink)
			}
		}
		for sk, ss := range stepSinks {
			fx := NewStepFixer(sk.step, NewChainFixer(ss))
			if w := findWorkspace(ws, sk.path); w != nil {
				w.AppendAutoFixer(fx)
			}
		}
	}
}

// ChainFixer is the callee-side autofixer registered after chain
// resolution. The full implementation is added in Plan Task 7.
type ChainFixer struct {
	sinks []*CalleeSink
}

// NewChainFixer constructs a ChainFixer over a list of sinks (typically
// all sinks within one callee step).
func NewChainFixer(sinks []*CalleeSink) *ChainFixer {
	return &ChainFixer{sinks: sinks}
}

func (f *ChainFixer) RuleNames() string { return "reusable-workflow-taint" }

// FixStep lifts ${{ inputs.X }} sinks into a step-level env: var and
// rewrites consuming sites. SinkEnv is warning-only in Phase 1 and is
// skipped here. Mirrors ReusableWorkflowTaintRule.FixStep but operates
// from CalleeSink records joined post-Wait by ResolvePendingChains.
func (f *ChainFixer) FixStep(step *ast.Step) error {
	if step == nil || len(f.sinks) == 0 {
		return nil
	}

	// Ensure step.Env exists for env-var lifting.
	if step.Env == nil {
		step.Env = &ast.Env{Vars: make(map[string]*ast.EnvVar)}
	}
	if step.Env.Vars == nil {
		step.Env.Vars = make(map[string]*ast.EnvVar)
	}

	envVarMap := make(map[string]string)      // inputPath -> env var name
	envVarsForYAML := make(map[string]string) // env var name -> "${{ inputs.X }}"
	runReplacements := make(map[string]string)
	scriptReplacements := make(map[string]string)

	for _, sink := range f.sinks {
		if sink.SinkType == SinkEnv {
			continue // Phase 1: SinkEnv is warning-only, no auto-fix.
		}

		if _, present := envVarMap[sink.InputPath]; !present {
			expectedValue := fmt.Sprintf("${{ %s }}", sink.InputPath)
			envName := envVarNameFor(sink.InputName)
			lower := strings.ToLower(envName)
			if existing, exists := step.Env.Vars[lower]; exists {
				if existing != nil && existing.Value != nil && existing.Value.Value == expectedValue {
					envVarMap[sink.InputPath] = envName
				} else {
					for suffix := 2; ; suffix++ {
						candidate := fmt.Sprintf("%s_%d", envName, suffix)
						candidateLower := strings.ToLower(candidate)
						existing, exists := step.Env.Vars[candidateLower]
						if exists {
							if existing != nil && existing.Value != nil && existing.Value.Value == expectedValue {
								envVarMap[sink.InputPath] = candidate
								break
							}
							continue
						}
						step.Env.Vars[candidateLower] = &ast.EnvVar{
							Name:  &ast.String{Value: candidate, Pos: sink.Pos},
							Value: &ast.String{Value: expectedValue, Pos: sink.Pos},
						}
						envVarsForYAML[candidate] = expectedValue
						envVarMap[sink.InputPath] = candidate
						break
					}
				}
			} else {
				step.Env.Vars[lower] = &ast.EnvVar{
					Name:  &ast.String{Value: envName, Pos: sink.Pos},
					Value: &ast.String{Value: expectedValue, Pos: sink.Pos},
				}
				envVarsForYAML[envName] = expectedValue
				envVarMap[sink.InputPath] = envName
			}
		}
		envName := envVarMap[sink.InputPath]

		switch sink.SinkType {
		case SinkRun:
			runReplacements[fmt.Sprintf("${{ %s }}", sink.InputPath)] = "$" + envName
			runReplacements[fmt.Sprintf("${{%s}}", sink.InputPath)] = "$" + envName
			if run, ok := step.Exec.(*ast.ExecRun); ok && run.Run != nil {
				run.Run.Value = strings.ReplaceAll(run.Run.Value,
					fmt.Sprintf("${{ %s }}", sink.InputPath), "$"+envName)
				run.Run.Value = strings.ReplaceAll(run.Run.Value,
					fmt.Sprintf("${{%s}}", sink.InputPath), "$"+envName)
			}
		case SinkGitHubScript:
			scriptReplacements[fmt.Sprintf("${{ %s }}", sink.InputPath)] = "process.env." + envName
			scriptReplacements[fmt.Sprintf("${{%s}}", sink.InputPath)] = "process.env." + envName
			if action, ok := step.Exec.(*ast.ExecAction); ok {
				if scriptInput, ok := action.Inputs["script"]; ok && scriptInput != nil && scriptInput.Value != nil {
					scriptInput.Value.Value = strings.ReplaceAll(scriptInput.Value.Value,
						fmt.Sprintf("${{ %s }}", sink.InputPath), "process.env."+envName)
					scriptInput.Value.Value = strings.ReplaceAll(scriptInput.Value.Value,
						fmt.Sprintf("${{%s}}", sink.InputPath), "process.env."+envName)
				}
			}
		}
	}

	// Apply YAML-level rewrites via BaseNode (sed-style edits in the source file).
	if step.BaseNode != nil {
		if len(envVarsForYAML) > 0 {
			if err := AddEnvVarsToStepNode(step.BaseNode, envVarsForYAML); err != nil {
				return fmt.Errorf("ChainFixer: add env vars: %w", err)
			}
		}
		if len(runReplacements) > 0 {
			if err := ReplaceInRunScript(step.BaseNode, runReplacements); err != nil &&
				!strings.Contains(err.Error(), "run section not found") {
				return fmt.Errorf("ChainFixer: replace run: %w", err)
			}
		}
		if len(scriptReplacements) > 0 {
			if err := ReplaceInGitHubScript(step.BaseNode, scriptReplacements); err != nil &&
				!strings.Contains(err.Error(), "section not found") &&
				!strings.Contains(err.Error(), "field not found") {
				return fmt.Errorf("ChainFixer: replace script: %w", err)
			}
		}
	}
	return nil
}

func (c *LocalReusableWorkflowCache) emitChainWarning(ws []workspaceLike, caller *CallerTaint, sink *CalleeSink) {
	severity := "medium"
	if caller.HasPrivilegedTrigger {
		severity = "critical"
	}
	msg := fmt.Sprintf(
		"reusable-workflow-taint-chain (%s): untrusted source %v flows from caller %s `with: %s` to callee %s %s sink at line:%d. "+
			"An attacker controlling %v can inject into the callee's %s context. "+
			"Fix: in callee, move ${{ inputs.%s }} to env: and use $%s. "+
			"See https://sisaku-security.github.io/lint/docs/rules/reusableworkflowtaint/",
		severity,
		caller.UntrustedSources,
		caller.CallerWorkflowPath,
		caller.InputName,
		sink.CalleeWorkflowPath,
		sink.SinkType,
		sink.Pos.Line,
		caller.UntrustedSources,
		sink.SinkType,
		sink.InputName,
		envVarNameFor(sink.InputName),
	)
	err := FormattedError(caller.Pos, "reusable-workflow-taint", "%s", msg)
	if w := findWorkspace(ws, caller.CallerWorkflowPath); w != nil {
		w.AppendError(err)
	}
}

func (c *LocalReusableWorkflowCache) emitCalleeSoloWarnings(ws []workspaceLike, sinks []*CalleeSink) {
	dedup := make(map[string]struct{})
	stepSinks := make(map[stepKey][]*CalleeSink)
	for _, sink := range sinks {
		key := fmt.Sprintf("%s:%d:%s", sink.CalleeWorkflowPath, sink.Pos.Line, sink.InputName)
		if _, ok := dedup[key]; ok {
			continue
		}
		dedup[key] = struct{}{}

		msg := fmt.Sprintf(
			"reusable-workflow-taint (medium): callee uses ${{ inputs.%s }} in %s sink, but no caller in this repo passes untrusted data. "+
				"If this workflow is called from outside the repo, future callers passing untrusted input will become injection vectors. "+
				"Recommend lifting to env: regardless. "+
				"See https://sisaku-security.github.io/lint/docs/rules/reusableworkflowtaint/",
			sink.InputName, sink.SinkType,
		)
		err := FormattedError(sink.Pos, "reusable-workflow-taint", "%s", msg)
		if w := findWorkspace(ws, sink.CalleeWorkflowPath); w != nil {
			w.AppendError(err)
		}
		sk := stepKey{path: sink.CalleeWorkflowPath, step: sink.Step}
		stepSinks[sk] = append(stepSinks[sk], sink)
	}
	for sk, ss := range stepSinks {
		fx := NewStepFixer(sk.step, NewChainFixer(ss))
		if w := findWorkspace(ws, sk.path); w != nil {
			w.AppendAutoFixer(fx)
		}
	}
}

// envVarNameFor mirrors generateEnvVarName in the rule (kept duplicated
// to avoid pulling rule state into the cache; covered by tests below).
func envVarNameFor(inputName string) string {
	if inputName == "" {
		return "UNTRUSTED_INPUT"
	}
	upper := strings.ToUpper(inputName)
	upper = strings.ReplaceAll(upper, "-", "_")
	upper = strings.ReplaceAll(upper, ".", "_")
	return "INPUT_" + upper
}
