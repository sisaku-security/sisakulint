package workflow

import (
	"strings"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// ActionMetadata is an action.yml (action:action-root). The runner reads it, not
// GitHub's server.
type ActionMetadata struct {
	Base
	Name        Field[String]
	Description Field[String]
	Inputs      Field[Map[ActionInput]]
	Outputs     Field[Map[ActionOutput]]
	Runs        Field[Runs]
}

// ActionInput is an input of an action. Only default is a property of
// action:input; the others are its loose keys, which the runner does not
// check.
type ActionInput struct {
	Base
	Description        Field[String]
	Required           Field[String]
	Default            Field[String]
	DeprecationMessage Field[String]
}

// ActionOutput is an output of an action (action:output-definition).
type ActionOutput struct {
	Base
	Description Field[String]
	Value       Field[String]
}

// RunsKind is how an action runs, by its using (ConvertRuns).
type RunsKind uint8

const (
	RunsComposite       RunsKind = iota // using: composite, with steps
	RunsJavaScript                      // using: node12, node16, node20 or node24, with main
	RunsDockerContainer                 // using: docker, with image
	RunsPlugin                          // no using, and plugin: plugin is a name of the internals of actions/runner, not of the docs
	RunsInvalid                         // the runner rejects it (reported)
)

var runsKindNames = [...]string{"RunsComposite", "RunsJavaScript", "RunsDockerContainer", "RunsPlugin", "RunsInvalid"}

func (k RunsKind) String() string { return runsKindNames[k] }

// Runs is how the action runs (action:runs). Which fields there are
// depends on Kind: Steps for composite, Main, Pre and Post for node,
// Image, Entrypoint, PreEntrypoint, PostEntrypoint, Args and Env for
// docker.
type Runs struct {
	Base
	Kind           RunsKind
	Using          Field[String]
	Steps          Field[List[Step]]
	Main           Field[String]
	Pre            Field[String]
	Post           Field[String]
	Image          Field[String]
	Entrypoint     Field[String]
	PreEntrypoint  Field[String]
	PostEntrypoint Field[String]
	Args           Field[List[String]]
	Env            Field[Map[String]]
	PreIf          Field[String]
	PostIf         Field[String]
	Plugin         Field[String]
}

// usings are the values of using that ConvertRuns accepts, compared
// ignoring the case, and the key each needs.
var usings = []struct {
	using string
	kind  RunsKind
	needs string
}{
	{"docker", RunsDockerContainer, "image"},
	{"node12", RunsJavaScript, "main"},
	{"node16", RunsJavaScript, "main"},
	{"node20", RunsJavaScript, "main"},
	{"node24", RunsJavaScript, "main"},
	{"composite", RunsComposite, "steps"},
}

// ParseActionMetadata reads the action.yml in t, which should be read with
// cst.ModeGitHub. Like Parse, it reads the first document only and never
// fails.
func ParseActionMetadata(t *cst.Tree) (*ActionMetadata, []Diagnostic) {
	a := &ActionMetadata{Runs: Field[Runs]{Value: Runs{Kind: RunsInvalid}}}
	// The runner requires runs after the schema (ActionManifestManager.Load).
	r := readDocument(t, true, dActionActionRoot, []string{"runs"}, func(r *reader, content cst.Node) { r.readAction(a, content) })
	return a, r.diags
}

func (r *reader) readAction(a *ActionMetadata, content cst.Node) {
	v := r.value(content, pos{}, dActionActionRoot)
	if v.st != Present {
		return
	}
	ents, _, _ := r.mapping(v, dActionActionRoot)
	p := v.p
	a.Base = Base{Node: v.n, Via: p.via}
	a.Name = r.str(get(ents, "name"), p)
	a.Description = r.str(get(ents, "description"), p)
	a.Inputs = readMap(r, get(ents, "inputs"), p, r.actionInput)
	a.Outputs = readMap(r, get(ents, "outputs"), p, r.actionOutput)
	runs := get(ents, "runs")
	if runs == nil {
		r.report(MissingKey, v.n.ContentSpan(), p, `"runs" is required`)
	}
	a.Runs = r.runs(runs, p)
}

func (r *reader) actionInput(e *entry, p pos) Field[ActionInput] {
	v, ents := r.object(e, p)
	f := field[ActionInput](e, v)
	f.Value = ActionInput{
		Base:               Base{Node: v.n, Via: v.p.via},
		Description:        r.str(getAny(ents, "description"), v.p),
		Required:           r.str(getAny(ents, "required"), v.p),
		Default:            r.str(getFold(ents, "default"), v.p),
		DeprecationMessage: r.str(getFold(ents, "deprecationMessage"), v.p),
	}
	return f
}

// getFold is the entry named name ignoring the case, as ConvertInputs
// compares the keys of an input (OrdinalIgnoreCase). Only default is a
// property; Default is a loose key, whose value allows no expression.
func getFold(ents []entry, name string) *entry {
	for i := range ents {
		if !ents[i].dup && !ents[i].exprKey && strings.EqualFold(ents[i].name, name) {
			return &ents[i]
		}
	}
	return nil
}

func (r *reader) actionOutput(e *entry, p pos) Field[ActionOutput] {
	v, ents := r.object(e, p)
	f := field[ActionOutput](e, v)
	f.Value = ActionOutput{
		Base:        Base{Node: v.n, Via: v.p.via},
		Description: r.str(get(ents, "description"), v.p),
		Value:       r.str(get(ents, "value"), v.p),
	}
	return f
}

func (r *reader) runs(e *entry, p pos) Field[Runs] {
	if e == nil {
		return Field[Runs]{Value: Runs{Kind: RunsInvalid}}
	}
	v, ents := r.object(e, p)
	f := field[Runs](e, v)
	f.Value = Runs{Base: Base{Node: v.n, Via: v.p.via}, Kind: RunsInvalid}
	if v.st != Present || v.kind != valMapping {
		return f
	}
	p = v.p
	u := &f.Value
	u.Using = r.str(get(ents, "using"), p)
	u.Steps = r.steps(get(ents, "steps"), p)
	u.Main = r.str(get(ents, "main"), p)
	u.Pre = r.str(get(ents, "pre"), p)
	u.Post = r.str(get(ents, "post"), p)
	u.Image = r.str(get(ents, "image"), p)
	u.Entrypoint = r.str(get(ents, "entrypoint"), p)
	u.PreEntrypoint = r.str(get(ents, "pre-entrypoint"), p)
	u.PostEntrypoint = r.str(get(ents, "post-entrypoint"), p)
	u.Args = r.strList(get(ents, "args"), p)
	u.Env = r.strMap(get(ents, "env"), p)
	u.PreIf = r.str(get(ents, "pre-if"), p)
	u.PostIf = r.str(get(ents, "post-if"), p)
	u.Plugin = r.str(get(ents, "plugin"), p)
	u.Kind = r.runsKind(u, p)
	return f
}

// runsKind is what ConvertRuns makes of u: using chooses the kind, which
// needs a key; without using, plugin is enough.
func (r *reader) runsKind(u *Runs, p pos) RunsKind {
	switch u.Using.Status {
	case Absent:
		if u.Plugin.Status == Present {
			return RunsPlugin
		}
		r.report(MissingKey, u.Node.ContentSpan(), p, `"using" is required: composite, docker, node12, node16, node20 or node24`)
		return RunsInvalid
	case Present:
	default:
		return RunsInvalid // reported
	}
	using := u.Using.Value.AsString()
	for _, k := range usings {
		if !strings.EqualFold(using, k.using) {
			continue
		}
		need := map[string]Status{"image": u.Image.Status, "main": u.Main.Status, "steps": u.Steps.Status}[k.needs]
		if need == Absent {
			r.report(MissingKey, u.Node.ContentSpan(), p, "%q is required with using: %s", k.needs, using)
			return RunsInvalid
		}
		if need != Present {
			return RunsInvalid // reported
		}
		return k.kind
	}
	r.report(InvalidValue, u.Using.Value.Node.ContentSpan(), u.Using.Value.pos(p), "using: %s is not supported: composite, docker, node12, node16, node20 or node24", using)
	return RunsInvalid
}
