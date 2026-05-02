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

// chainKey dedupes by (caller pos, sink pos) so the same flow only
// generates one warning even if recorded multiple times.
type chainKey struct {
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
				k := chainKey{caller.Pos.Line, caller.Pos.Col, sink.Pos.Line, sink.Pos.Col}
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

// FixStep is filled in by Plan Task 7.
func (f *ChainFixer) FixStep(step *ast.Step) error { return nil }

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
