package attackrun

import (
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// Marker is where the harm of a rule shows when its example's step runs
// with the attack value.
type Marker uint8

const (
	MarkerNone   Marker = iota // the rule's examples are not run
	MarkerStdout               // a line PWNED on stdout: the value ran as a command (code-injection)
	MarkerEnv                  // a name PWNED in GITHUB_ENV (envvar-injection)
	MarkerOutput               // a name PWNED in GITHUB_OUTPUT (output-clobbering)
	MarkerPath                 // a line /tmp/PWNED in GITHUB_PATH (envpath-injection)
)

// UnrunReason is why the steps an example's attack value reaches are not
// run.
type UnrunReason uint8

const (
	UnrunNone                 UnrunReason = iota // they are run
	UnrunCarrierNotExpression                    // the carrier is words, not an expression
	UnrunCarrierWrapped                          // the carrier is inside another expression
	UnrunOtherExpression                         // a script has another ${{ }}
	UnrunShellNotBash                            // a step's shell is not bash
	UnrunAbsolutePathCommand                     // a script names a command by an absolute path, outside the shut-in PATH
	UnrunSkippedByIf                             // the value reaches only steps whose if (or job's if) an attacker's run does not pass
	UnrunNoAttackerEvent                         // the workflow runs on no event an attacker triggers with the value
	UnrunCarrierNotInRun                         // the value goes only where no run step reads it (the with of an action)
	UnrunCarrierAbsent                           // the example has no ${{ }} at all, so the value goes nowhere
	UnrunStubbedCommandFailed                    // a step failed after a command ran as a stub: what it did is not what the runner does
)

var unrunNames = [...]string{"", "carrier-not-expression", "carrier-wrapped", "other-expression", "shell-not-bash", "absolute-path-command", "skipped-by-if", "no-attacker-event", "carrier-not-in-run", "carrier-absent", "stubbed-command-failed"}

func (r UnrunReason) String() string { return unrunNames[r] }

// ScriptStep is a step to run: its script with the value put in, the
// words the runner gives bash before the path of the script
// (OptionWords: bash -e for a step with no shell, the options of shell:
// bash or of a custom shell, taint.ShellInvocation) and after the path
// (PositionalWords), its env (NAME=value, the value put in), and whether
// it runs after a step before it failed (its if is not false in a job that
// failed).
type ScriptStep struct {
	File            facts.InputPath
	Where           string
	Script          string
	OptionWords     []string
	PositionalWords []string
	Env             []string
	AfterFailure    bool
}

// Preparation is the steps an example's attack value reaches, in the order
// of the files and the steps, or why they are not run.
type Preparation struct {
	Steps []ScriptStep
	Unrun UnrunReason
}

// absolutePath is a path to a directory of commands, from the root or as
// a relative path that a cd to the root makes one.
var absolutePath = regexp.MustCompile(`(^|[^A-Za-z0-9_.$}/-])/?(usr|bin|sbin|opt|snap)/`)

// Prepare is the steps of e that its attack value reaches through ${{ }}
// in their scripts or their env, those an attacker's run does not skip
// (attacker.Table.Kept on some event of the workflow; an action's steps are not
// skipped), or why they are not run: an example whose value reaches no
// step to run has a reason too, never an empty Preparation. A carrier that
// is in no ${{ }} of an example that has some is an error: a misspelt
// carrier must not pass for a value the example keeps out. A carrier that
// no payload of the workflow's attacker's events has goes in empty, and
// one that is an object or an array goes in as Object or Array (valueIn).
func Prepare(e lint.Example) (Preparation, error) {
	a := e.Notes.AttackValue
	if a.IsZero() {
		return Preparation{}, errors.New("the example has no attack-value")
	}
	carrier, ok := carrierOf(a)
	if !ok {
		return Preparation{Unrun: UnrunCarrierNotExpression}, nil
	}
	var p Preparation
	wrapped, skipped, eventless := false, false, false
	anyEvent := taint.EventsAll(taint.TableEvents()) // an action's steps run on the events of its callers
	files := append([]lint.ExampleFile{{InputKind: e.InputKind, Name: e.Name, Text: e.Text}}, e.Others...)
	for _, x := range files {
		tree := cst.ParseMode([]byte(x.Text), cst.ModeGitHub)
		name := x.Name
		if x.InputKind == lint.InputKindActionMetadata {
			am, _ := workflow.ParseActionMetadata(tree)
			if am == nil || am.Runs.Status != workflow.Present || am.Runs.Value.Steps.Status != workflow.Present {
				continue
			}
			for _, st := range am.Runs.Value.Steps.Value.Items {
				s, w, r := stepOf(name, "runs."+st.Place.String(), nil, nil, st, nil, carrier, a.Value(), anyEvent)
				wrapped = wrapped || w
				if r != UnrunNone {
					return Preparation{Unrun: r}, nil
				}
				if s != nil {
					p.Steps = append(p.Steps, *s)
				}
			}
			continue
		}
		w, _ := workflow.Parse(tree)
		if w == nil || w.Jobs.Status != workflow.Present {
			continue
		}
		evs := taint.EventsOf(w, taint.TableEvents())
		eventless = eventless || len(evs) == 0
		value := valueIn(evs, carrier, a.Value())
		at := valuePath(carrier)
		if value != a.Value() && value != "" {
			at = nil // Object or Array, which no if reads as the text
		}
		for _, je := range w.Jobs.Value.Entries {
			if je.Value.Status != workflow.Present || je.Value.Value.Steps.Status != workflow.Present {
				continue
			}
			j := je.Value.Value
			for _, st := range j.Steps.Value.Items {
				envs := []workflow.Field[workflow.Map[workflow.String]]{w.Env, j.Env}
				s, wr, r := stepOf(name, "jobs."+je.Key.AsString()+"."+st.Place.String(), w, &j, st, envs, carrier, value, evs)
				if (s != nil || r != UnrunNone) && !kept(evs, at, value, append(attacker.JobIfs(w, &j), attacker.StepIf(w, &j, st.If))...) {
					skipped = true
					continue
				}
				wrapped = wrapped || wr
				if r != UnrunNone {
					return Preparation{Unrun: r}, nil
				}
				if s != nil {
					p.Steps = append(p.Steps, *s)
				}
			}
		}
	}
	if len(p.Steps) == 0 && wrapped {
		return Preparation{Unrun: UnrunCarrierWrapped}, nil
	}
	switch {
	case len(p.Steps) > 0:
		return p, nil
	case skipped && eventless:
		return Preparation{Unrun: UnrunNoAttackerEvent}, nil
	case skipped:
		return Preparation{Unrun: UnrunSkippedByIf}, nil
	case len(Substitute(e)) > 0:
		return Preparation{Unrun: UnrunCarrierNotInRun}, nil
	case !hasExpression(e):
		return Preparation{Unrun: UnrunCarrierAbsent}, nil
	}
	return Preparation{}, fmt.Errorf("the carrier %s is in no ${{ }} of the example, which has some", a.Carrier())
}

// valueIn is the value an attacker's run of an event of evs puts in for
// carrier, as the runner writes it as text: value when the payload of some
// event of evs has it as a text; else Object when one has it as an object
// or an array, which the runner writes so (taint.LookupText); else none,
// as GitHub writes an absent value (taint.ControlAbsent) empty. A carrier
// through a star is an array whatever the payload, written Array.
func valueIn(evs []analysis.EventActivity, carrier, value string) string {
	n, errs := expr.Parse(carrier)
	if len(errs) > 0 || len(evs) == 0 {
		return value
	}
	p, ok := expr.AccessPath(n)
	if !ok {
		return value
	}
	if slices.ContainsFunc(p, func(e expr.PathElem) bool { return e.Star }) {
		return "Array"
	}
	out := ""
	for _, e := range evs {
		switch c, collection := taint.LookupText(e.Name(), e.ActivityType(), p); {
		case c == taint.ControlArbitrary || c == taint.ControlStructured || c == taint.ControlUnknown:
			return value // a text an attacker writes
		case collection:
			out = "Object"
		case c != taint.ControlAbsent:
			return value
		}
	}
	return out
}

// hasExpression is whether e has a ${{ }} where a step or a job reads it.
func hasExpression(e lint.Example) bool {
	found := false
	visit(e, func(_ facts.InputPath, _ string, s workflow.String) {
		for _, p := range s.Parts {
			found = found || p.Expr
		}
	})
	return found
}

// given is whether a shell is named: an empty one is none, as the runner
// reads it (string.IsNullOrEmpty).
func given(shell workflow.Field[workflow.String]) bool {
	return shell.Status != workflow.Absent && (shell.Status != workflow.Present || shell.Value.AsString() != "")
}

// afterFailure is whether the if p of a step may let the step run after a
// step before it failed, in an attacker's run of some event of evs: p is not
// false in a job that failed (attacker.JobStateFailed), read in its syntax
// tree.
func afterFailure(evs []analysis.EventActivity, p attacker.PlacedIf) bool {
	return slices.ContainsFunc(evs, func(e analysis.EventActivity) bool {
		return attacker.Outsider.RunTruth(p, e, attacker.JobStateFailed) != expr.TruthFalse
	})
}

// kept is whether an attacker's run of some event of evs passes every if of ifs,
// with the value at the reference at (attacker.Table.KeptValue) when there is
// one.
func kept(evs []analysis.EventActivity, at []expr.PathElem, value string, ifs ...attacker.PlacedIf) bool {
	return slices.ContainsFunc(evs, func(e analysis.EventActivity) bool {
		return !slices.ContainsFunc(ifs, func(p attacker.PlacedIf) bool {
			if at != nil {
				return !attacker.Outsider.KeptValue(p, e, at, value)
			}
			return !attacker.Outsider.Kept(p, e)
		})
	})
}

// valuePath is the reference carrier, when it is one: an if reads the
// value that goes in there.
func valuePath(carrier string) []expr.PathElem {
	n, errs := expr.Parse(carrier)
	if len(errs) > 0 {
		return nil
	}
	p, ok := expr.AccessPath(n)
	if !ok {
		return nil
	}
	return p
}

// stepOf is st as a Step to run, when the value reaches it: its run, or
// an env it sees (envs, outermost first, then its own), has
// ${{ <carrier> }}. wrapped is whether the carrier is inside another
// expression there. evs are the events whose runs read the if of st.
func stepOf(file facts.InputPath, where string, w *workflow.Workflow, job *workflow.Job, st workflow.Step, envs []workflow.Field[workflow.Map[workflow.String]], carrier, value string, evs []analysis.EventActivity) (s *ScriptStep, wrapped bool, unrun UnrunReason) {
	if st.Run.Status != workflow.Present {
		return nil, false, UnrunNone
	}
	script, kinds := put(st.Run.Value, carrier, value)
	reached := has(kinds, partCarrier)
	wrapped = has(kinds, partWrapped)
	env := map[string]string{}
	var order []string
	mixed := false // an entry has the carrier and another expression
	for _, m := range append(envs, st.Env) {
		if m.Status != workflow.Present {
			continue
		}
		for _, en := range m.Value.Entries {
			if en.Value.Status != workflow.Present {
				continue
			}
			k := en.Key.AsString()
			if _, ok := taint.RunnerVariable(k, false); ok {
				continue // the runner writes it over env
			}
			text, ks := put(en.Value.Value, carrier, value)
			reached = reached || has(ks, partCarrier)
			wrapped = wrapped || has(ks, partWrapped)
			mixed = mixed || has(ks, partCarrier) && (has(ks, partOther) || has(ks, partWrapped))
			if !slices.Contains(order, k) {
				order = append(order, k)
			}
			if has(ks, partOther) || has(ks, partWrapped) {
				delete(env, k) // an entry of another expression is not set
				continue
			}
			env[k] = text
		}
	}
	// the runner writes the variable of the carrier's context in every
	// step, after env
	if name, ok := runnerVariableOf(carrier); ok && regexp.MustCompile(`\$\{?`+name+`\b`).MatchString(script) {
		reached = true
		if !slices.Contains(order, name) {
			order = append(order, name)
		}
		env[name] = value
	}
	if !reached {
		return nil, wrapped, UnrunNone
	}
	// a step with no shell runs in bash -e, as on ubuntu and macos, whatever
	// runs-on says; a shell is read as the rules read it
	options, positional := []string{"-e"}, []string(nil)
	if given(st.Shell) || job != nil && (given(job.DefaultShell) || w != nil && given(w.DefaultShell)) {
		inv := taint.ShellInvocationOf(w, job, st)
		if inv.Shell != taint.ShellBash {
			return nil, wrapped, UnrunShellNotBash
		}
		options, positional = inv.OptionWords, inv.PositionalWords
	}
	if has(kinds, partWrapped) {
		return nil, wrapped, UnrunCarrierWrapped
	}
	if has(kinds, partOther) || mixed {
		return nil, wrapped, UnrunOtherExpression
	}
	if absolutePath.MatchString(script) {
		return nil, wrapped, UnrunAbsolutePathCommand
	}
	out := &ScriptStep{File: file, Where: where, Script: script, OptionWords: options, PositionalWords: positional, AfterFailure: afterFailure(evs, attacker.StepIf(w, job, st.If))}
	for _, k := range order {
		if v, ok := env[k]; ok {
			out.Env = append(out.Env, k+"="+v)
		}
	}
	return out, wrapped, UnrunNone
}

// Check is what to show of whether a test runs e's attack value, for a
// rule whose harm shows at m: "run by a test", "not run: <why>", or nothing
// when the rule's examples are not run or e has no attack value. A test of
// the rules runs the same Prepare; a run that ends in
// stubbed-command-failed is known only after it, and shows here as run.
func Check(e lint.Example, m Marker) string {
	if m == MarkerNone || e.Notes.AttackValue.IsZero() {
		return ""
	}
	p, err := Prepare(e)
	switch {
	case err != nil:
		return ""
	case p.Unrun != UnrunNone:
		return "not run: " + p.Unrun.String()
	}
	return "run by a test"
}

// runnerVariableOf is the variable the runner writes the context carrier
// to in every step, when carrier is such a context.
func runnerVariableOf(carrier string) (string, bool) {
	n, errs := expr.Parse(carrier)
	if len(errs) > 0 {
		return "", false
	}
	p, ok := expr.AccessPath(n)
	if !ok {
		return "", false
	}
	return taint.RunnerVariableOf(p)
}
