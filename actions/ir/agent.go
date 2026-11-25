package ir

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/agent"
	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/job"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

func (x *IR) allAgentSteps() []*AgentStep {
	x.once(SummaryAgentStep, func() {
		// the values that reach the agent, read once for the input with
		// what the sinks read (the callers, the env, the steps before)
		prompts := map[stepAt][]taint.StepValue{}
		for _, v := range taint.StepValuesIn(x.callersOf(), x.name, x.workflow, x.action, func(s workflow.Step, j *workflow.Job) []taint.Pick {
			a, ok := agent.Of(s)
			if !ok {
				return nil
			}
			var out []taint.Pick
			for _, p := range agent.Prompts(s, a.Action, x.outerEnv(j)...) {
				out = append(out, taint.Pick{Value: p.Value, InEnv: p.Route == analysis.PromptRouteEnv, EnvLevel: p.Level})
			}
			return out
		}) {
			at := stepAt{step: v.StepIndex}
			if v.Job != nil {
				at.job = v.Job.ID.AsString()
			}
			prompts[at] = append(prompts[at], v)
		}
		// the values of the setting inputs, read the same way
		settings := map[stepAt][]taint.StepValue{}
		for _, v := range taint.StepValues(x.callersOf(), x.name, x.workflow, x.action, func(s workflow.Step) []taint.Pick {
			a, ok := agent.Of(s)
			if !ok {
				return nil
			}
			var out []taint.Pick
			for _, sv := range agent.Settings(s, a.Action) {
				out = append(out, taint.Pick{Value: sv.Value})
			}
			return out
		}) {
			at := stepAt{step: v.StepIndex}
			if v.Job != nil {
				at.job = v.Job.ID.AsString()
			}
			settings[at] = append(settings[at], v)
		}
		// what the with of a step that uses an action gives the action of a
		// variable or a secret the attacker writes in every run: the with of
		// a composite action of another repository, whose steps are read
		// without callers
		withs := map[stepAt]withValues{}
		values := x.barriers.Passes(analysis.BarrierVariableValue) || x.barriers.Passes(analysis.BarrierSecretValue)
		for _, v := range taint.StepValues(x.callersOf(), x.name, x.workflow, x.action, func(s workflow.Step) []taint.Pick {
			if !values || s.Uses.Status != workflow.Present {
				return nil
			}
			var out []taint.Pick
			for _, w := range job.MapValues(s.With) {
				out = append(out, taint.Pick{Value: w})
			}
			return out
		}) {
			at := stepAt{step: v.StepIndex}
			if v.Job != nil {
				at.job = v.Job.ID.AsString()
			}
			w := withs[at]
			name := withInputs(v.Step.With)[v.Index]
			text := v.Value.Text()
			given := withInput{name: name}
			for _, r := range v.Refs {
				given.on = joinEvents(given.on, taint.ValuePartOn(r, v.WrittenValueOn, x.workflow))
				if len(r.EveryRunOn) > 0 {
					pl := x.inputPlace()
					w.refs = append(w.refs, withRef{name: name, ref: pl.exprRef(r, text[r.Span.Start:r.Span.End], pl.span(v.Value, r.Span)), r: r})
				}
			}
			if len(given.on) > 0 {
				w.inputs = append(w.inputs, given)
			}
			withs[at] = w
		}
		var out []*AgentStep
		add := func(at stepAt, j *workflow.Job, steps []workflow.Step, evs []analysis.EventActivity, ifs ...attacker.PlacedIf) {
			if a, ok := agent.Of(steps[at.step]); ok {
				env := x.agentEnv(j, a)
				o := x.projectAgentStep(x.inputPlace(), a, evs, ifs, prompts[at], settings[at], env, x.outerEnv(j), nil)
				o.automaticApproval = x.automaticApprovalOf(agent.Supported(a.Action, evs), j, ifs...)
				x.projectLater(x.inputPlace(), o, a, j, j, steps, at.step, evs, env)
				out = append(out, o)
			}
		}
		// the privileged events of the workflow's on, and when it can be
		// called, of its callers when they decide them, else any (unlike
		// the IfSites, which keep their own: here that would be a miss)
		if w := x.workflow; w != nil {
			evs := taint.EventsOf(w, job.Privileged())
			if got, cov := x.callersOf().Events(x.name, job.Privileged(), false); cov == analysis.CallerCoverageAll {
				evs = got
			}
			for _, je := range w.Jobs.Value.Entries {
				if je.Value.Status != workflow.Present {
					continue
				}
				j := je.Value.Value
				for i, s := range j.Steps.Value.Items {
					add(stepAt{j.ID.AsString(), i}, &j, j.Steps.Value.Items, evs, append(attacker.JobIfs(w, &j), attacker.StepIf(w, &j, s.If))...)
					out = append(out, x.remoteAgentSteps(&j, j.Steps.Value.Items, i, evs, withs[stepAt{j.ID.AsString(), i}], append(attacker.JobIfs(w, &j), attacker.StepIf(w, &j, s.If))...)...)
				}
			}
		}
		if a := x.action; a != nil {
			evs := taint.EventsAll(job.Privileged())
			if got, cov := x.callersOf().Events(x.name, job.Privileged(), false); cov == analysis.CallerCoverageAll {
				evs = got
			}
			for i, s := range a.Runs.Value.Steps.Value.Items {
				add(stepAt{step: i}, nil, a.Runs.Value.Steps.Value.Items, evs, attacker.StepIf(nil, nil, s.If))
				out = append(out, x.remoteAgentSteps(nil, a.Runs.Value.Steps.Value.Items, i, evs, withs[stepAt{step: i}], attacker.StepIf(nil, nil, s.If))...)
			}
		}
		x.agentSteps = out
	})
	return x.agentSteps
}

// remoteAgentSteps are the steps that run an AI agent in the composite
// actions of other repositories that the step at of steps runs (of the job
// j, or of the action when j is nil), on evs past ifs, read from the
// answers of action.definition (actions/composite): at the uses of the
// step, with the values of the step of the composite action in the file of
// the action. The values of the composite action are read without
// callers, so that a reference to its inputs is inconclusive
// (taint.Callers); the ifs of the composite steps between the step and
// the agent's, at a depth over 1, are not read. with is what the with of
// the step gives the action of a variable or a secret the attacker writes
// in every run, when the step uses an action of another repository (a
// composite action of the repository reads its own with): the events on
// which it may give one to an input that reaches the agent's step are the
// agent's WrittenValueOn (when the agent's step is a step of that action,
// an input that the prompt of the agent's step refers to, directly or
// through an env of the step, and any input when the with is one ${{ }} or
// the prompt has a value, directly or through an env of the step, that is
// not analyzed and is not an input; any input at a depth over 1); when the
// agent's step is
// a step of that action, the references of the with whose value the
// attacker chooses in every run, given to an input that a value of the
// agent's step refers to, are the agent's EveryRunRefs, by the route of an
// input of a composite action. The ifs of the composite steps keep both.
func (x *IR) remoteAgentSteps(j *workflow.Job, steps []workflow.Step, at int, evs []analysis.EventActivity, with withValues, ifs ...attacker.PlacedIf) []*AgentStep {
	s := &steps[at]
	if x.composites == nil || s.Uses.Status != workflow.Present {
		return nil
	}
	var out []*AgentStep
	for _, in := range x.composites.Expand(x.ctx, s, j == nil).Steps {
		if in.Origin.Query == nil {
			continue // an action of the inputs reports its own steps
		}
		a, ok := agent.Of(*in.Step)
		if !ok {
			continue
		}
		inner := in.Action.Runs.Value.Steps.Value.Items
		idx := -1
		for i := range inner {
			if &inner[i] == in.Step {
				idx = i
			}
		}
		pick := func(want func(workflow.Step) []taint.Pick) []taint.StepValue {
			var vals []taint.StepValue
			for _, v := range taint.StepValues(nil, calls.Node{}, nil, in.Action, want) {
				if v.StepIndex == idx {
					vals = append(vals, v)
				}
			}
			return vals
		}
		prompts := pick(func(t workflow.Step) []taint.Pick {
			pa, ok := agent.Of(t)
			if !ok {
				return nil
			}
			var picks []taint.Pick
			for _, p := range agent.Prompts(t, pa.Action) {
				picks = append(picks, taint.Pick{Value: p.Value, InEnv: p.Route == analysis.PromptRouteEnv})
			}
			return picks
		})
		settings := pick(func(t workflow.Step) []taint.Pick {
			pa, ok := agent.Of(t)
			if !ok {
				return nil
			}
			var picks []taint.Pick
			for _, sv := range agent.Settings(t, pa.Action) {
				picks = append(picks, taint.Pick{Value: sv.Value})
			}
			return picks
		})
		origin := in.Origin
		pl := place{x: x, origin: &origin}
		all := append(append(slices.Clone(ifs), stepIfs(in.Ifs)...), attacker.StepIf(nil, nil, in.Step.If))
		// the env of the workflow and of the job hold in the steps of a
		// composite action too; a step's own env does not
		var env []workflow.Field[workflow.Map[workflow.String]]
		if j != nil {
			if j.Kind != workflow.JobCall {
				env = append(env, x.workflow.Env)
			}
			env = append(env, j.Env)
		}
		env = append(env, a.Step.Env)
		// the ifs of the composite steps keep the events of the with, as
		// they keep the events of the step (all)
		innerIfs := append(stepIfs(in.Ifs), attacker.StepIf(nil, nil, in.Step.If))
		var composite []EveryRunRef
		var withOn []analysis.EventActivity
		switch {
		case s.Uses.Value.HasLocalPath:
			// a composite action of the repository between the step and the
			// action reads its own with with its callers (its own IR), so the
			// with of the step gives nothing here
		case len(in.Chain) > 1:
			// the agent's step is in an action that the action the step uses
			// runs: which input of the step's action reaches it is not read
			withOn = with.on(func(workflow.InputName) bool { return true })
		default:
			// the agent's step is a step of the action the step uses: an input
			// that a ${{ }} of the with or the env of the agent's step refers to
			// (inputs.<id>, or env.<name> of an env of the step whose value
			// does) reaches the agent
			envs := pick(func(t workflow.Step) []taint.Pick {
				var picks []taint.Pick
				for _, v := range job.MapValues(t.Env) {
					picks = append(picks, taint.Pick{Value: v})
				}
				return picks
			})
			stepEnv := envRefs(in.Step.Env, envs)
			refers, every := referredInputs(stepEnv, prompts, settings)
			// the events of the with on which a value of the with may reach a
			// reference of the prompt that the rules do not analyze (the
			// value-unknown of ai-action-prompt-injection): of an input that the
			// prompt refers to, and of every input when the with is one ${{ }}
			// (it may give any input) or when the prompt has a value that the
			// rules do not analyze and that is not an input (an output of a step
			// of the action, an env that a step writes), directly or through an
			// env of the step, which may come from any input, as a value that
			// the rules do not analyze in a workflow may come from any variable
			promptRefers, promptEvery := referredInputs(stepEnv, prompts)
			opaque := opaqueRefs(stepEnv, prompts)
			withOn = with.on(func(n workflow.InputName) bool {
				return opaque || promptEvery || n == (workflow.InputName{}) || promptRefers[expr.FoldName(n.String())]
			})
			// a with that is one ${{ }} as a whole names no input: the
			// EveryRunRefs do not count it, as the with of an agent's step
			// that is one ${{ }}
			for _, w := range with.refs {
				if w.name == (workflow.InputName{}) || !every && !refers[expr.FoldName(w.name.String())] {
					continue
				}
				on := agent.Supported(a.Action, taint.FilterEventOnly(slices.Clone(w.r.EveryRunOn), innerIfs...))
				if len(on) == 0 {
					continue
				}
				e := everyRunRefOf(analysis.AgentValueRouteCompositeInput, analysis.AgentInputUnset, workflow.EnvName{}, w.ref, on, w.r)
				e.CompositeInput, e.Composite = w.name, s.Uses.Value.Text()
				composite = append(composite, e)
			}
		}
		o := x.projectAgentStep(pl, a, evs, all, prompts, settings, env, nil, composite)
		o.writtenValueOn = joinEvents(o.writtenValueOn, agent.Supported(a.Action, taint.FilterEventOnly(slices.Clone(withOn), innerIfs...)))
		o.key, o.at, o.chain = keyOf(x.paths, x.input, x.tree, s.Uses.Value.Base), x.handleOf(s.Uses.Value.Base), in.Chain
		o.automaticApproval = x.automaticApprovalOf(agent.Supported(a.Action, evs), j, all...)
		x.projectLater(pl, o, a, j, nil, inner, idx, evs, env)
		// and the steps after the step of the input that runs the action
		var w *workflow.Workflow
		if j != nil {
			w = x.workflow
		}
		x.appendLater(x.inputPlace(), o, agent.LaterSteps(x.table(), w, j, j, steps, at, a, o.attackerOn, o.everyRunEvents(), x.scripts))
		o.substituted = in.Substituted
		o.innerAt = pl.handle(in.Step.Base)
		out = append(out, o)
	}
	return out
}

// withValues are what the with of a step that uses an action gives the
// action in a run whose attacker writes vars or secrets: inputs, the inputs
// that it may give a variable or a secret, and refs, its references whose
// value the attacker chooses in every run.
type withValues struct {
	inputs []withInput
	refs   []withRef
}

// withInput is an input that the with of a step may give a variable or a
// secret, on the events on (taint.ValuePartOn of the references of its
// value): the zero InputName for a with that is a ${{ }} as a whole.
type withInput struct {
	name workflow.InputName
	on   []analysis.EventActivity
}

// on are the events of the inputs of w that keep keeps.
func (w withValues) on(keep func(workflow.InputName) bool) []analysis.EventActivity {
	var out []analysis.EventActivity
	for _, in := range w.inputs {
		if keep(in.name) {
			out = joinEvents(out, in.on)
		}
	}
	return out
}

// withRef is a reference of the with of a step whose value the attacker
// chooses in every run: in the value of the input name (the zero InputName
// for a with that is a ${{ }} as a whole), with its handle in the input.
type withRef struct {
	name workflow.InputName
	ref  ExprRef
	r    taint.ExprRef
}

// referredInputs are the inputs, folded, that the references of vals
// refer to as inputs.<id>, directly or through env.<name> of an env of the
// step whose references (env, by the folded name) do, and whether one
// refers to the inputs as a whole (inputs, inputs[x]).
func referredInputs(env map[string][]taint.ExprRef, vals ...[]taint.StepValue) (map[string]bool, bool) {
	out, every := map[string]bool{}, false
	var add func(r taint.ExprRef, viaEnv bool)
	add = func(r taint.ExprRef, viaEnv bool) {
		if len(r.Path) == 0 {
			return
		}
		switch expr.FoldName(r.Path[0].Name) {
		case "inputs":
			if len(r.Path) < 2 || r.Path[1].Name == "" {
				every = true
				return
			}
			out[expr.FoldName(r.Path[1].Name)] = true
		case "env":
			if !viaEnv && len(r.Path) >= 2 && r.Path[1].Name != "" {
				for _, e := range env[expr.FoldName(r.Path[1].Name)] {
					add(e, true)
				}
			}
		}
	}
	for _, vs := range vals {
		for _, v := range vs {
			for _, r := range v.Refs {
				add(r, false)
			}
		}
	}
	return out, every
}

// opaqueRefs reports whether a reference of vals is inconclusive and not
// an input of the action (inputs.<id> read without callers), directly or,
// for env.<name> of an env of the step, in the references env of the value
// of that env (by the folded name).
func opaqueRefs(env map[string][]taint.ExprRef, vals []taint.StepValue) bool {
	opaque := func(r taint.ExprRef) bool {
		return r.Verdict == analysis.Inconclusive && r.InconclusiveKind != analysis.InconclusiveRefInputCall
	}
	for _, v := range vals {
		for _, r := range v.Refs {
			if opaque(r) {
				return true
			}
			if len(r.Path) >= 2 && r.Path[1].Name != "" && expr.FoldName(r.Path[0].Name) == "env" && slices.ContainsFunc(env[expr.FoldName(r.Path[1].Name)], opaque) {
				return true
			}
		}
	}
	return false
}

// envRefs are the references of the values vals of the env f of a step
// (in the order of job.MapValues), by the folded name of the env.
func envRefs(f workflow.Field[workflow.Map[workflow.String]], vals []taint.StepValue) map[string][]taint.ExprRef {
	out := map[string][]taint.ExprRef{}
	if f.Status != workflow.Present {
		return out
	}
	var names []string
	for _, e := range f.Value.Entries {
		if e.Value.Status == workflow.Present {
			names = append(names, expr.FoldName(e.Key.AsString()))
		}
	}
	for _, v := range vals {
		if v.Index < len(names) {
			out[names[v.Index]] = append(out[names[v.Index]], v.Refs...)
		}
	}
	return out
}

// withInputs are the names of the inputs of the with f, in the order of
// its values (job.MapValues): one zero InputName for a with that is a
// ${{ }} as a whole.
func withInputs(f workflow.Field[workflow.Map[workflow.String]]) []workflow.InputName {
	if f.Status == workflow.Dynamic && f.Expr != nil {
		return []workflow.InputName{{}}
	}
	if f.Status != workflow.Present {
		return nil
	}
	var out []workflow.InputName
	for _, e := range f.Value.Entries {
		if e.Value.Status == workflow.Present {
			n, _ := workflow.InputNameOf(e.Key.AsString())
			out = append(out, n)
		}
	}
	return out
}

// stepAt is where a step is: the ID of its job (none in an action.yml) and
// its index, as a step shared through an alias is read in each job it is
// in.
type stepAt struct {
	job  string
	step int
}

// agentEnv is the env of the workflow (but of a called one), of the job j
// and of the step of a, the nearest last; the step's alone in an action
// metadata file (j nil).
func (x *IR) agentEnv(j *workflow.Job, a agent.Step) []workflow.Field[workflow.Map[workflow.String]] {
	var env []workflow.Field[workflow.Map[workflow.String]]
	if j != nil {
		if j.Kind != workflow.JobCall {
			env = append(env, x.workflow.Env)
		}
		env = append(env, j.Env)
	}
	return append(env, a.Step.Env)
}

// outerEnv are the env around a step of the job j, inner first, that the
// agent's process gets: the job's, and the workflow's but in a job that
// calls a workflow; none in an action.yml.
func (x *IR) outerEnv(j *workflow.Job) []workflow.Field[workflow.Map[workflow.String]] {
	if j == nil {
		return nil
	}
	out := []workflow.Field[workflow.Map[workflow.String]]{j.Env}
	if j.Kind != workflow.JobCall && x.workflow != nil {
		out = append(out, x.workflow.Env)
	}
	return out
}

// projectAgentStep is the projection of a, whose step runs on evs past
// ifs under env and whose values that reach the agent are vals (read with
// outer, the env around the step, agent.Prompts): its values
// without their positions, which the handles keep. The subprocess env
// scrub of env decides what claude's modes allow (agent.ScrubOf).
func (x *IR) projectAgentStep(pl place, a agent.Step, evs []analysis.EventActivity, ifs []attacker.PlacedIf, vals []taint.StepValue, sets []taint.StepValue, env, outer []workflow.Field[workflow.Map[workflow.String]], composite []EveryRunRef) *AgentStep {
	evs = agent.Supported(a.Action, evs)
	scrub, scrubSrc := agent.ScrubOf(a, env)
	a = a.UnderScrub(scrub, scrubSrc)
	o := &AgentStep{
		key:        keyOf(x.paths, x.input, x.tree, a.Step.Base),
		at:         pl.handle(a.Step.Uses.Value.Base),
		action:     a.Action,
		attackerOn: taint.Filter(x.table(), evs, ifs...),
		usesText:   a.Step.Uses.Value.Text(),
	}
	for _, e := range evs {
		if !slices.ContainsFunc(ifs, func(c attacker.PlacedIf) bool { return !x.table().KeptActor(c, e) }) {
			o.actorOn = append(o.actorOn, e)
		}
	}
	for _, g := range a.OpenGates {
		o.openGates = append(o.openGates, OpenGate{Gate: g.Gate, Input: g.Input, Text: g.Text, OpenOn: slices.Clone(o.actorOn), At: pl.handle(g.At)})
	}
	for _, g := range a.GateInputs {
		open, undecided := gateOn(x.table(), a.Action, g, o.actorOn, ifs)
		if len(open) > 0 {
			o.openGates = append(o.openGates, OpenGate{Gate: g.Gate, Input: g.Input, Text: g.Value.Text(), OpenOn: open, At: pl.handle(g.At)})
		}
		if len(undecided) > 0 {
			o.inconclusiveSettings = append(o.inconclusiveSettings, InconclusiveSetting{Kind: analysis.InconclusiveAgentGate, Input: g.Input, Text: g.Value.Text(), UndecidedOn: undecided, At: pl.handle(g.At)})
		}
	}
	for _, u := range a.UnsafeSettings {
		o.unsafeSettings = append(o.unsafeSettings, UnsafeSetting{Layer: u.Layer, Input: u.Input, Value: u.Value, At: pl.handle(u.At)})
	}
	for _, g := range a.Inconclusive {
		s := InconclusiveSetting{Kind: g.Kind, Input: g.Input, Text: g.Text, At: pl.handle(g.At)}
		if g.Kind == analysis.InconclusiveAgentGate {
			s.UndecidedOn = slices.Clone(o.actorOn) // the whole with
		}
		o.inconclusiveSettings = append(o.inconclusiveSettings, s)
	}
	ps := agent.Prompts(a.Step, a.Action, outer...)
	for _, v := range vals {
		p := ps[v.Index]
		text := v.Value.Text()
		o.writtenValueOn = joinEvents(o.writtenValueOn, agent.Supported(a.Action, v.WrittenValueOn))
		for _, r := range v.Refs {
			pr := x.promptRefOf(pl, p, r, text[r.Span.Start:r.Span.End], pl.span(v.Value, r.Span), evs, ifs)
			pr.EveryRunOn = everyRunOn(a.Action, r)
			o.promptRefs = append(o.promptRefs, pr)
			if len(pr.EveryRunOn) > 0 {
				route := analysis.AgentValueRoutePromptInput
				if p.Route == analysis.PromptRouteEnv {
					route = analysis.AgentValueRouteStepEnv
				}
				o.everyRunRefs = append(o.everyRunRefs, everyRunRefOf(route, p.Input, p.Env, pr.Ref, pr.EveryRunOn, r))
			}
		}
	}
	if len(taint.Filter(x.table(), x.ownEventsOn([]workflow.EventName{workflow.EventNameWorkflowDispatch}), ifs...)) > 0 {
		o.promptDispatch = slices.ContainsFunc(o.promptRefs, func(p PromptRef) bool {
			return p.Ref.Verdict == analysis.Inconclusive && p.Ref.InconclusiveKind == analysis.InconclusiveRefInputDispatch
		})
	}
	// a run of another's whose payload has what the attacker wrote: a path
	// not below github is theirs in every run (attacker.Table.KeptOthers)
	for _, e := range o.attackerOn {
		if !slices.ContainsFunc(ifs, func(c attacker.PlacedIf) bool { return !x.table().KeptOthers(c, e, nil) }) {
			o.othersOn = append(o.othersOn, e)
		}
	}
	ss := agent.Settings(a.Step, a.Action)
	for _, v := range sets {
		p := ss[v.Index]
		text := v.Value.Text()
		o.writtenValueOn = joinEvents(o.writtenValueOn, agent.Supported(a.Action, v.WrittenValueOn))
		for _, r := range v.Refs {
			on, others := x.reachOf(r, evs, ifs)
			sr := SettingRef{Input: p.Input, Ref: pl.exprRef(r, text[r.Span.Start:r.Span.End], pl.span(v.Value, r.Span)), On: on, OthersOn: others, EveryRunOn: everyRunOn(a.Action, r)}
			o.settingRefs = append(o.settingRefs, sr)
			if len(sr.EveryRunOn) > 0 {
				o.everyRunRefs = append(o.everyRunRefs, everyRunRefOf(analysis.AgentValueRouteSettingInput, p.Input, workflow.EnvName{}, sr.Ref, sr.EveryRunOn, r))
			}
		}
	}
	// the inputs of a composite action of another repository that the with
	// of the step that uses it gives (remoteAgentSteps)
	o.everyRunRefs = append(o.everyRunRefs, composite...)
	// the permissions, by the modes of the events the attacker's text reaches
	// the agent on: also those of a variable or a secret they write
	grants, undecided := agent.Grants(a.Step, a.Action, joinEvents(slices.Clone(evs), o.everyRunEvents()), scrub, scrubSrc)
	for _, g := range grants {
		c := CapabilityGrant{Capability: g.Capability, Input: g.Permission.Input, Permission: g.Permission.Text, At: pl.textAt(g.Permission.At)}
		if p := g.Partner; p != nil {
			c.Partner, c.PartnerAt = p.Text, pl.textAt(p.At)
		}
		o.capabilityGrants = append(o.capabilityGrants, c)
	}
	for _, u := range undecided {
		o.undecidedPermissions = append(o.undecidedPermissions, UndecidedPermission{Kind: u.Kind, Input: u.Permission.Input, Permission: u.Permission.Text, At: pl.textAt(u.Permission.At)})
	}
	return o
}

// everyRunEvents are the events of the EveryRunOn of o's everyRunRefs:
// those on which a variable or a secret the attacker writes reaches the
// agent in a run anyone starts.
func (o *AgentStep) everyRunEvents() []analysis.EventActivity {
	var out []analysis.EventActivity
	for _, r := range o.everyRunRefs {
		out = joinEvents(out, r.EveryRunOn)
	}
	return out
}

// everyRunOn are the events of the EveryRunOn of r that the action a runs
// on: not only the privileged events, as the attacker who writes vars or
// secrets chooses their values in a run of any event.
func everyRunOn(a analysis.AgentAction, r taint.ExprRef) []analysis.EventActivity {
	if len(r.EveryRunOn) == 0 {
		return nil
	}
	out := agent.Supported(a, slices.Clone(r.EveryRunOn))
	if len(out) == 0 {
		return nil
	}
	return out
}

// everyRunRefOf is the EveryRunRef of the reference ref, by route (of the
// input in or the env env), the attacker's in every run on on, read from
// r: the reference of vars or secrets its value comes from.
func everyRunRefOf(route analysis.AgentValueRoute, in analysis.AgentInput, env workflow.EnvName, ref ExprRef, on []analysis.EventActivity, r taint.ExprRef) EveryRunRef {
	out := EveryRunRef{Route: route, Ref: ref, EveryRunOn: on}
	if route == analysis.AgentValueRouteStepEnv {
		out.Env = env
	} else {
		out.Input = in
	}
	if src := r.Source; len(src) >= 2 && src[1].Name != "" && (expr.FoldName(src[0].Name) == "vars" || expr.FoldName(src[0].Name) == "secrets") {
		out.Source, out.SourceName = expr.PathString(src), src[1].Name
		out.SourceSecret = expr.FoldName(src[0].Name) == "secrets"
		out.Direct = out.Source == expr.PathString(r.Path)
	}
	return out
}

// joinEvents are the events of a, then those of b not in a.
func joinEvents(a, b []analysis.EventActivity) []analysis.EventActivity {
	for _, e := range b {
		if !slices.Contains(a, e) {
			a = append(a, e)
		}
	}
	return a
}

// projectLater fills in o, the projection of a, the step at of steps (of
// the job j, of the action when j is nil, or of a composite action that a
// step of j runs) that runs on evs under env: whom its agent runs as, the
// runner's sudo, whether its edits may write .git, its auto mode, the mode
// claude starts in, and the steps after it (agent.LaterSteps, with stepJob,
// the job whose steps steps are: j, or nil for the steps of an action).
func (x *IR) projectLater(pl place, o *AgentStep, a agent.Step, j, stepJob *workflow.Job, steps []workflow.Step, at int, evs []analysis.EventActivity, env []workflow.Field[workflow.Map[workflow.String]]) {
	var w *workflow.Workflow
	if j != nil {
		w = x.workflow
		o.runnerSudo = job.HostedSudo(*j)
	}
	evs = joinEvents(agent.Supported(a.Action, slices.Clone(evs)), o.everyRunEvents())
	o.agentUser = agent.UserOf(a)
	o.gitWrite = agent.GitWriteOf(a, evs, env)
	o.autoMode = agent.AutoMode(a, evs, env)
	o.scrubDecides = agent.ScrubDecides(a, evs, env)
	if m, ok := agent.StartModeOf(a, evs, env); ok {
		o.startModes = append(o.startModes, StartMode{Mode: m.Mode, Source: m.Source, On: m.On, At: pl.textAt(m.At)})
	}
	x.appendLater(pl, o, agent.LaterSteps(x.table(), w, j, stepJob, steps, at, a, o.attackerOn, o.everyRunEvents(), x.scripts))
}

// appendLater appends the later steps ls, in the file of pl, to o.
func (x *IR) appendLater(pl place, o *AgentStep, ls []agent.LaterStep) {
	for _, l := range ls {
		h := pl.handle(l.Step.Base)
		switch {
		case l.Step.Run.Status == workflow.Present:
			h = pl.handle(l.Step.Run.Value.Base)
		case l.Step.Uses.Status == workflow.Present:
			h = pl.handle(l.Step.Uses.Value.Base)
		}
		o.laterSteps = append(o.laterSteps, LaterStep{
			Name: l.Name, On: l.On, Secrets: l.Secrets.Names, AllSecrets: l.Secrets.All, Token: l.Secrets.Token,
			CodeRuns: pl.codeRunSteps(l.CodeRuns), GitRuns: pl.codeRunSteps(l.GitRuns), At: h,
		})
	}
}

// gateOn are the events of actorOn on which g lets the attacker in, in the
// attacker run table tab, and
// those on which that is not decided. claude-code-action checks the actor
// of the run before workflow_run too, whom the attacker run does not hold,
// unless g is '*' (as read on 2026-10-12).
func gateOn(tab attacker.Table, a analysis.AgentAction, g agent.GateInput, actorOn []analysis.EventActivity, ifs []attacker.PlacedIf) (open, undecided []analysis.EventActivity) {
	for _, e := range actorOn {
		t, anyone := tab.ActorListed(ifs, e, g.Value)
		if t == expr.TruthTrue && !anyone && a == analysis.AgentActionClaudeCode && e.Name() == workflow.EventNameWorkflowRun {
			t = expr.TruthUnknown
		}
		switch t {
		case expr.TruthTrue:
			open = append(open, e)
		case expr.TruthUnknown:
			undecided = append(undecided, e)
		}
	}
	return open, undecided
}

// promptRefOf is the projection of r, a reference of the value p, whose
// step runs on evs (those the action runs on) past ifs.
func (x *IR) promptRefOf(pl place, p agent.PromptValue, r taint.ExprRef, text string, at Handle, evs []analysis.EventActivity, ifs []attacker.PlacedIf) PromptRef {
	out := PromptRef{Route: p.Route, Input: p.Input, Env: p.Env, Ref: pl.exprRef(r, text, at)}
	out.On, out.OthersOn = x.reachOf(r, evs, ifs)
	return out
}

// reachOf are the events of evs (those the action runs on) on which r is
// Controlled, and of them those on which a run whose actor is not the
// attacker, in which it is theirs, gets past ifs.
func (x *IR) reachOf(r taint.ExprRef, evs []analysis.EventActivity, ifs []attacker.PlacedIf) (on, others []analysis.EventActivity) {
	if r.Verdict != analysis.Controlled {
		return nil, nil
	}
	for _, e := range r.ControlledOn {
		if !slices.Contains(evs, e) {
			continue // the action does not run on it
		}
		on = append(on, e)
		if !slices.ContainsFunc(ifs, func(c attacker.PlacedIf) bool { return !x.table().KeptOthers(c, e, r.Path) }) {
			others = append(others, e)
		}
	}
	return on, others
}
