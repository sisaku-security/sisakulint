package workflow

import (
	"strings"

	"github.com/gh-intel/sisakulint/actions/expr"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// JobKind is what a job is, by the definition of job its keys chose.
type JobKind uint8

const (
	JobRunner  JobKind = iota // job-factory: runs-on and steps
	JobCall                   // workflow-job: calls a reusable workflow with uses
	JobUnknown                // not a mapping, or its keys do not tell (reported)
)

var jobKindNames = [...]string{"JobRunner", "JobCall", "JobUnknown"}

func (k JobKind) String() string { return jobKindNames[k] }

// RunsOnForm is how runs-on is written: GitHub drops the white space around
// a label of a string or of a mapping's labels, and not around an item of a
// sequence or a value of the matrix.
type RunsOnForm uint8

const (
	RunsOnFormUnset    RunsOnForm = iota
	RunsOnFormString              // runs-on: x
	RunsOnFormSequence            // runs-on: [x, y]
	RunsOnFormMapping             // runs-on: {group: g, labels: …}
)

var runsOnFormNames = [...]string{"RunsOnFormUnset", "RunsOnFormString", "RunsOnFormSequence", "RunsOnFormMapping"}

func (f RunsOnForm) String() string { return runsOnFormNames[f] }

// Job is one job. Uses, With, Secrets and InheritSecrets are of a JobCall.
type Job struct {
	Base
	ID             String
	Kind           JobKind
	Name           Field[String]
	Needs          Field[List[String]]
	If             Field[If]
	Permissions    Field[Permissions]
	CacheMode      Field[String] // cache-mode, as written: the schema checks the value
	TimeoutMinutes Field[String] // timeout-minutes, as written: the schema checks the value
	// CancelTimeoutMinutes, ContinueOnError, FailFast and MaxParallel
	// (of strategy), EnvironmentURL (environment.url) and
	// DefaultWorkingDirectory (defaults.run.working-directory) are as
	// written: the schema checks the values
	CancelTimeoutMinutes    Field[String]
	ContinueOnError         Field[String]
	FailFast                Field[String]
	MaxParallel             Field[String]
	EnvironmentURL          Field[String]
	DefaultWorkingDirectory Field[String]
	Concurrency             Field[Concurrency]
	Env                     Field[Map[String]]
	Outputs                 Field[Map[String]]
	Steps                   Field[List[Step]]
	Matrix                  Field[cst.Node]     // strategy.matrix; Dynamic also when the strategy is
	MatrixVariables         []MatrixVariable    // of strategy.matrix, when Matrix is Present
	RunsOn                  Field[List[String]] // the labels: runs-on, or its labels
	RunsOnForm              RunsOnForm          // how runs-on is written
	DefaultShell            Field[String]       // defaults.run.shell
	Environment             Field[String]       // environment, or the name of its mapping
	Container               Field[Container]
	Services                Field[Map[Container]]
	Uses                    Field[Uses]
	With                    Field[Map[String]]
	Secrets                 Field[Map[String]] // Present without entries for secrets: inherit
	InheritSecrets          bool
}

// MatrixVariable is a name strategy.matrix gives values to: a key of the matrix, or a
// key of an entry of include. Values are the scalars written for it, in
// the order written. Types are the types of all the values written for it,
// mappings and sequences too, in the order written, as GitHub keeps them in
// the matrix context: a plain scalar by its YAML type, a quoted one a
// string, a mapping an object, a sequence an array, and ValueTypeUnset for
// a scalar with a ${{ }}; none when the
// matrix may give the name values not written (a key or include, or an
// entry of include, is a ${{ }}). Known is false when a value of it is not known before
// the run: its sequence is a ${{ }}, a value is a mapping or a sequence,
// or include or an entry of it is a ${{ }} (then no variable is Known).
// exclude only takes combinations away, so its values are not given.
type MatrixVariable struct {
	Name   string
	Values []String
	Types  []expr.ValueType
	Known  bool
}

func (r *reader) job(e *entry, p pos) Field[Job] {
	if id := e.key.AsString(); !e.exprKey && e.key.lit != litNumber && !validID(id) {
		r.report(InvalidValue, e.key.Node.ContentSpan(), e.key.pos(p), "the job id %q is invalid: a job id must start with a letter or _, contain only letters, digits, _ and -, be shorter than 100 characters, and not start with __", id)
	}
	v := r.value(e.value, p, e.def)
	f := field[Job](e, v)
	j := Job{Base: Base{Node: v.n, Via: v.p.via}, ID: e.key, Kind: JobUnknown}
	if v.st != Present || v.kind != valMapping {
		f.Value = j
		return f
	}
	ents, chosen, ambiguous := r.mapping(v, e.def)
	if !ambiguous {
		j.Kind = JobRunner
		if chosen == dWorkflowJob {
			j.Kind = JobCall
		}
	}
	p = v.p
	j.Name = r.str(get(ents, "name"), p)
	j.Needs = r.strList(get(ents, "needs"), p)
	j.If = r.condition(get(ents, "if"), p)
	j.Permissions = r.permissions(get(ents, "permissions"), p)
	j.CacheMode = r.str(get(ents, "cache-mode"), p)
	j.TimeoutMinutes = r.str(get(ents, "timeout-minutes"), p)
	j.CancelTimeoutMinutes = r.str(get(ents, "cancel-timeout-minutes"), p)
	j.ContinueOnError = r.str(get(ents, "continue-on-error"), p)
	j.Concurrency = r.concurrency(get(ents, "concurrency"), p)
	j.Env = r.strMap(get(ents, "env"), p)
	j.Outputs = r.strMap(get(ents, "outputs"), p)
	j.Steps = r.steps(get(ents, "steps"), p)
	r.checkStepIDs(j.Steps)
	r.checkStepTargets(j.Steps)
	j.Matrix, j.MatrixVariables, j.FailFast, j.MaxParallel = r.strategy(get(ents, "strategy"), p)
	j.RunsOn, j.RunsOnForm = r.runsOn(get(ents, "runs-on"), p)
	j.DefaultShell, j.DefaultWorkingDirectory = r.defaultRun(get(ents, "defaults"), p)
	j.Environment, j.EnvironmentURL = r.environment(get(ents, "environment"), p)
	j.Container = r.container(get(ents, "container"), p)
	j.Services = r.services(get(ents, "services"), p)
	j.Uses = r.jobUses(get(ents, "uses"), p)
	j.With = r.strMap(get(ents, "with"), p)
	j.Secrets, j.InheritSecrets = r.secrets(get(ents, "secrets"), p)
	f.Value = j
	return f
}

// jobUses reads the uses of a JobCall: a reusable workflow, which is a file
// under .github/workflows/ of the same repository (./ or $/, without a ref)
// or of another (owner/repo/.github/workflows/file@ref).
func (r *reader) jobUses(e *entry, p pos) Field[Uses] {
	f := r.uses(e, p)
	if f.Status != Present {
		return f
	}
	u := f.Value
	ok := false
	k := u.Kind
	if k == UsesFolded {
		k = u.Folded // GitHub folds a literal ${{ }} and calls what it is
	}
	switch k {
	case UsesLocal:
		ok = strings.HasPrefix(u.Path.Text, "./.github/workflows/") && !strings.Contains(u.Path.Text, "@")
	case UsesRemote, UsesSelf:
		ok = strings.HasPrefix(u.Path.Text, ".github/workflows/")
	}
	if (k == UsesRemote || k == UsesLocal) && !plainParts(u.written) {
		ok = false
	}
	if !ok {
		r.report(InvalidValue, u.Node.ContentSpan(), u.pos(p), "a job's uses %q is no reusable workflow: ./.github/workflows/file, $/.github/workflows/file or owner/repo/.github/workflows/file@ref", u.Text())
		f.Status, f.Value = Invalid, Uses{String: u.String}
	}
	return f
}

// plainParts is whether the uses v, owner/repo/path@ref or ./path, has no
// part . or .., and no empty part but at its end: GitHub refuses those in
// a job's uses, where a step's is read past them. A $/ uses, a
// backslash and an empty last part were not tried, and are read as before.
func plainParts(v string) bool {
	v = strings.TrimPrefix(v, "./")
	if at := strings.IndexByte(v, '@'); at >= 0 {
		v = v[:at]
	}
	parts := strings.Split(v, "/")
	for i, p := range parts {
		if p == "." || p == ".." || p == "" && i < len(parts)-1 {
			return false
		}
	}
	return true
}

// strategy reads strategy.matrix: whether it is there, whether it is known
// before the run, and the values it gives each name; and fail-fast and
// max-parallel, as written.
func (r *reader) strategy(e *entry, p pos) (matrix Field[cst.Node], vars []MatrixVariable, failFast, maxParallel Field[String]) {
	if e == nil {
		return
	}
	v, ents := r.object(e, p)
	if v.st != Present {
		return field[cst.Node](e, v), nil, failFast, maxParallel
	}
	failFast = r.str(get(ents, "fail-fast"), v.p)
	maxParallel = r.str(get(ents, "max-parallel"), v.p)
	m := get(ents, "matrix")
	if m == nil {
		return
	}
	mv := r.value(m.value, v.p, m.def)
	if mv.st == Present && mv.kind == valMapping {
		ments, _, _ := r.mapping(mv, m.def)
		vars = r.matrixVariables(ments, mv.p)
	}
	matrix = field[cst.Node](m, mv)
	matrix.Value = mv.n
	return
}

// matrixVariables are the names the entries ents of a matrix give values to.
func (r *reader) matrixVariables(ents []entry, p pos) []MatrixVariable {
	var out []MatrixVariable
	at := map[string]int{} // by expr.FoldName
	add := func(name string, vals []String, types []expr.ValueType, known bool) {
		f := expr.FoldName(name)
		i, ok := at[f]
		if !ok {
			i = len(out)
			at[f] = i
			out = append(out, MatrixVariable{Name: name, Known: true})
		}
		out[i].Values = append(out[i].Values, vals...)
		out[i].Types = append(out[i].Types, types...)
		out[i].Known = out[i].Known && known
	}
	open := false
	for i := range ents {
		e := &ents[i]
		switch {
		case e.exprKey:
			open = true
		case e.dup:
		case e.prop && e.name == "include":
			if !r.include(e, p, add) {
				open = true
			}
		case e.prop: // exclude takes combinations away; its entries are read as include's, for their diagnostics
			r.include(e, p, func(string, []String, []expr.ValueType, bool) {})
		default:
			vals, types, known := r.scalars(e, p)
			add(e.name, vals, types, known)
		}
	}
	if open {
		for i := range out {
			out[i].Known = false
			out[i].Types = nil // include or a key adds values not known
		}
	}
	return out
}

// scalars reads the value of e, a sequence, as its scalars and the types
// of its items (matrixValueType); known is false when it is not a sequence
// or an item is not a scalar.
func (r *reader) scalars(e *entry, p pos) ([]String, []expr.ValueType, bool) {
	v := r.value(e.value, p, e.def)
	if v.st != Present || v.kind != valSequence {
		return nil, []expr.ValueType{expr.ValueTypeUnset}, false // values not known
	}
	item := schemaDefs[ofKind(e.def, nil, kindSequence)[0]].item
	seq, _ := v.n.Sequence()
	var out []String
	var types []expr.ValueType
	known := true
	for n := range seq.Items() {
		iv := r.value(n, v.p, item)
		types = append(types, matrixValueType(iv))
		if iv.st == Present && iv.kind == valScalar {
			out = append(out, iv.s)
		} else {
			known = false
		}
	}
	return out, types, known
}

// matrixValueType is the type of v, a value of the matrix, in the matrix
// context (MatrixVariable.Types).
func matrixValueType(v val) expr.ValueType {
	if v.st != Present {
		return expr.ValueTypeUnset
	}
	switch v.kind {
	case valMapping:
		return expr.ValueObject
	case valSequence:
		return expr.ValueArray
	}
	if v.s.HasExpr() {
		return expr.ValueTypeUnset
	}
	return [...]expr.ValueType{litNull: expr.ValueNull, litBool: expr.ValueBoolean, litNumber: expr.ValueNumber, litString: expr.ValueString}[v.s.lit]
}

// include gives add the value of each key of each entry of include; it is
// false when include or an entry is not written out.
func (r *reader) include(e *entry, p pos, add func(string, []String, []expr.ValueType, bool)) bool {
	v := r.value(e.value, p, e.def)
	if v.st != Present || v.kind != valSequence {
		return false
	}
	item := schemaDefs[ofKind(e.def, nil, kindSequence)[0]].item
	seq, _ := v.n.Sequence()
	ok := true
	for n := range seq.Items() {
		iv := r.value(n, v.p, item)
		if iv.st != Present || iv.kind != valMapping {
			ok = false
			continue
		}
		ents, _, _ := r.mapping(iv, item)
		for i := range ents {
			x := &ents[i]
			switch {
			case x.exprKey:
				ok = false
			case x.dup:
			default:
				xv := r.value(x.value, iv.p, x.def)
				known := xv.st == Present && xv.kind == valScalar
				var vals []String
				if known {
					vals = []String{xv.s}
				}
				add(x.name, vals, []expr.ValueType{matrixValueType(xv)}, known)
			}
		}
	}
	return ok
}

// runsOn reads the labels of runs-on: one, a list of them, or the labels
// of a group's mapping (Absent when it has none); and how it is written.
func (r *reader) runsOn(e *entry, p pos) (Field[List[String]], RunsOnForm) {
	if e == nil {
		return Field[List[String]]{}, RunsOnFormUnset
	}
	n := r.peek(e.value)
	if _, ok := n.Mapping(); !ok {
		form := RunsOnFormString
		if _, ok := n.Sequence(); ok {
			form = RunsOnFormSequence
		}
		return r.strList(e, p), form
	}
	v, ents := r.object(e, p)
	if v.st != Present {
		return field[List[String]](e, v), RunsOnFormMapping
	}
	return r.strList(get(ents, "labels"), v.p), RunsOnFormMapping
}

// environment reads a job's environment: its name, or the name of its
// mapping (Absent when it has none), and the url of its mapping.
func (r *reader) environment(e *entry, p pos) (name, url Field[String]) {
	if e == nil {
		return
	}
	if _, ok := r.peek(e.value).Mapping(); !ok {
		return r.str(e, p), url
	}
	v, ents := r.object(e, p)
	if v.st != Present {
		return field[String](e, v), url
	}
	return r.str(get(ents, "name"), v.p), r.str(get(ents, "url"), v.p)
}

// defaultRun reads defaults.run.shell and defaults.run.working-directory
// only, of a job or of the workflow; when defaults or run is not a mapping,
// both have its status.
func (r *reader) defaultRun(e *entry, p pos) (shell, workingDirectory Field[String]) {
	if e == nil {
		return
	}
	v, ents := r.object(e, p)
	if v.st != Present {
		return field[String](e, v), field[String](e, v)
	}
	run := get(ents, "run")
	if run == nil {
		return
	}
	rv, rents := r.object(run, v.p)
	if rv.st != Present {
		return field[String](run, rv), field[String](run, rv)
	}
	return r.str(get(rents, "shell"), rv.p), r.str(get(rents, "working-directory"), rv.p)
}

// secrets reads the secrets of a JobCall: a mapping, or inherit.
func (r *reader) secrets(e *entry, p pos) (Field[Map[String]], bool) {
	if e == nil {
		return Field[Map[String]]{}, false
	}
	if r.peek(e.value).Kind() == cst.NodeScalar {
		s := r.str(e, p)
		f := Field[Map[String]]{Status: s.Status, Key: s.Key, Expr: s.Expr}
		f.Value.Base = s.Value.Base
		return f, s.Status == Present && s.Value.AsString() == "inherit"
	}
	return r.strMap(e, p), false
}

// Concurrency is the concurrency of a job or of the workflow; the string
// form is its Group. Its values are as written: the schema checks them.
type Concurrency struct {
	Base
	Group            Field[String]
	CancelInProgress Field[String]
}

// concurrency reads concurrency: a string, or a mapping of group and
// cancel-in-progress.
func (r *reader) concurrency(e *entry, p pos) Field[Concurrency] {
	if e == nil {
		return Field[Concurrency]{}
	}
	if _, ok := r.peek(e.value).Mapping(); !ok {
		g := r.str(e, p)
		f := Field[Concurrency]{Status: g.Status, Key: g.Key, Expr: g.Expr}
		f.Value = Concurrency{Base: g.Value.Base, Group: g}
		return f
	}
	v, ents := r.object(e, p)
	f := field[Concurrency](e, v)
	f.Value = Concurrency{Base: Base{Node: v.n, Via: v.p.via}, Group: r.str(get(ents, "group"), v.p), CancelInProgress: r.str(get(ents, "cancel-in-progress"), v.p)}
	return f
}
