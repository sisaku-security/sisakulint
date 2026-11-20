package job

import (
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/taint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// SecretsContextRead is a ${{ }} with a reference that reads the secrets
// context and names no secret (readsWholeContext), the first if it has
// several. GitHub then sends the
// job's runner every secret it may read, not only those it names, before
// it evaluates any if.
type SecretsContextRead struct {
	Value workflow.String // the value the ${{ }} is in
	Part  int             // the index of the ${{ }} in Value.Parts
	Text  string          // the reference as written: secrets, secrets.*, secrets[x]
}

// SecretsContextReads are the reads of the secrets context that name no
// secret, in the values a job reads the secrets in: the env of the workflow once,
// when a job of it is not a call, then each job's (jobValues).
func SecretsContextReads(w *workflow.Workflow) []SecretsContextRead {
	var out []SecretsContextRead
	if runsAJob(w) {
		for _, v := range MapValues(w.Env) {
			out = append(out, SecretsContextReadsIn(v)...)
		}
	}
	for _, je := range w.Jobs.Value.Entries {
		if je.Value.Status == workflow.Present {
			for _, v := range jobValues(je.Value.Value) {
				out = append(out, SecretsContextReadsIn(v)...)
			}
		}
	}
	return out
}

// SecretsContextReadsIn are the reads of the secrets context that name no
// secret in the ${{ }} of v, one for each ${{ }}: its first reference.
func SecretsContextReadsIn(v workflow.String) []SecretsContextRead {
	var out []SecretsContextRead
	for i, p := range v.Parts {
		if !p.Expr || p.Tree == nil {
			continue
		}
		var first expr.Node
		contextReads(p.Tree, func(n expr.Node) {
			if first == nil {
				first = n
			}
		})
		if first != nil {
			sp := p.InValue(first.Span())
			out = append(out, SecretsContextRead{Value: v, Part: i, Text: v.Text()[sp.Start:sp.End]})
		}
	}
	return out
}

// contextReads calls f with each reference in n that reads the secrets
// context and names no secret. It does not look into a reference to
// secrets, and looks into the indexes of the other references, as Secrets
// does (env[toJSON(secrets)]).
func contextReads(n expr.Node, f func(expr.Node)) {
	if p, ok := expr.AccessPath(n); ok && expr.EqualName(p[0].Name, "secrets") {
		if readsWholeContext(p) {
			f(n)
		}
		return
	}
	for _, c := range expr.Children(n) {
		contextReads(c, f)
	}
}

// runsAJob is whether a job of w is not a call: the env of w is that
// job's (a called workflow does not get it).
func runsAJob(w *workflow.Workflow) bool {
	if w.Jobs.Status != workflow.Present {
		return false
	}
	return slices.ContainsFunc(w.Jobs.Value.Entries, func(je workflow.Entry[workflow.Job]) bool {
		return je.Value.Status == workflow.Present && je.Value.Value.Kind != workflow.JobCall
	})
}

// SecretPart is a ${{ }} whose value has a value taken out of a secret by
// fromJSON, which the runner does not mask, in a place whose value the
// runner prints in the log before any code of the job reads the value.
type SecretPart struct {
	Value   workflow.String // the value the ${{ }} is in
	Part    int             // the index of the ${{ }} in Value.Parts
	Secrets []string        // the names of the secrets it is taken out of, once each by expr.FoldName; * for one not named
	Via     []OutputPart    // the ${{ }} of the outputs of the jobs that the value comes through by needs, nearest first
}

// OutputPart is a ${{ }} of an output of a job, which a later job reads
// with needs.
type OutputPart struct {
	Job, Output string          // the ID of the job and the name of the output, as written
	Value       workflow.String // the value of the output
	Part        int             // the index of the ${{ }} in Value.Parts
}

// SecretParts are the ${{ }} of w that have a value taken out of a secret,
// in the places the runner prints: the env of the workflow, when a job of
// it is not a call, the env of a job that is not a call, the username of
// the credentials (with a password) and the env of its container and of
// its services, which the runner prints at the start of the job in the
// docker login and the docker create commands, and the name, the env, the
// with and the run of a step. In a job, a value of an output of a job it needs, read by needs,
// is the value of the output, and a variable of the env, read by env, is
// the value of the variable (secretReader.envValue).
func SecretParts(w *workflow.Workflow) []SecretPart {
	var out []SecretPart
	r := newSecretReader(w)
	var add func(v workflow.String)
	addIn := func(r secretReader) func(workflow.String) {
		return func(v workflow.String) {
			for i, p := range v.Parts {
				if !p.Expr || p.Tree == nil {
					continue
				}
				if sv := r.of(p.Tree); sv.has&hasPart != 0 {
					out = append(out, SecretPart{Value: v, Part: i, Secrets: sv.names, Via: sv.via})
				}
			}
		}
	}
	if runsAJob(w) {
		add = addIn(r)
		for _, v := range MapValues(w.Env) {
			add(v)
		}
	}
	for _, je := range w.Jobs.Value.Entries {
		if je.Value.Status != workflow.Present || je.Value.Value.Kind == workflow.JobCall {
			continue
		}
		j := je.Value.Value
		jr := r.in(j)
		add = addIn(jr.withoutEnv()) // GitHub allows no env context in the env of a job
		for _, v := range MapValues(j.Env) {
			add(v)
		}
		add = addIn(jr)
		containers := []workflow.Field[workflow.Container]{j.Container}
		if j.Services.Status == workflow.Present {
			for _, e := range j.Services.Value.Entries {
				containers = append(containers, e.Value)
			}
		}
		for _, c := range containers {
			if c.Status != workflow.Present {
				continue
			}
			// the runner logs in only with both a username and a password
			if c.Value.Username.Status == workflow.Present && (c.Value.Password.Status == workflow.Present || c.Value.Password.Status == workflow.Dynamic) {
				add(c.Value.Username.Value)
			}
			for _, v := range MapValues(c.Value.Env) {
				add(v)
			}
		}
		if j.Steps.Status != workflow.Present {
			continue
		}
		for _, st := range j.Steps.Value.Items {
			// the runner evaluates the env of a step with the env of the
			// job, then the name, the with and the run with the env of
			// the step too
			add = addIn(jr)
			for _, v := range MapValues(st.Env) {
				add(v)
			}
			add = addIn(jr.atStep(st.Env))
			if st.Name.Status == workflow.Present {
				add(st.Name.Value)
			}
			for _, v := range MapValues(st.With) {
				add(v)
			}
			if st.Run.Status == workflow.Present {
				add(st.Run.Value)
			}
		}
	}
	return out
}

// secretHas is what a value has of the secrets, as bits.
type secretHas uint8

const (
	hasContext     secretHas = 1 << iota // the secrets context
	hasContextJSON                       // its toJSON, which fromJSON gives back
	hasWhole                             // a whole secret, which the runner masks
	hasParsed                            // a secret read by fromJSON: an object, an array
	hasPart                              // a value taken out of a parsed secret, which the runner does not mask
	hasHolding                           // an object or an array of the env with a hasMust value among its values
	hasMust                              // in every run, a value the runner masks (a whole secret, hasContextJSON) is in the value written as a string
)

// secretValue is what the value of an expression has of the secrets, the
// names of the secrets it is of, and the outputs of jobs it comes through
// by needs.
type secretValue struct {
	has   secretHas
	names []string
	via   []OutputPart
}

// union is v and o.
func (v secretValue) union(o secretValue) secretValue {
	out := secretValue{has: v.has | o.has, names: slices.Clone(v.names), via: slices.Clone(v.via)}
	for _, n := range o.names {
		if !slices.ContainsFunc(out.names, func(m string) bool { return expr.FoldName(m) == expr.FoldName(n) }) {
			out.names = append(out.names, n)
		}
	}
	for _, p := range o.via {
		if !slices.ContainsFunc(out.via, func(q OutputPart) bool {
			return expr.FoldName(q.Job) == expr.FoldName(p.Job) && expr.FoldName(q.Output) == expr.FoldName(p.Output) && q.Part == p.Part
		}) {
			out.via = append(out.via, p)
		}
	}
	return out
}

// either is the value of one of v and o, as || and case give: a value
// the runner masks is in it in every run only when it is in both.
func (v secretValue) either(o secretValue) secretValue {
	out := v.union(o)
	if v.has&o.has&hasMust == 0 {
		out.has &^= hasMust
	}
	if out.has&hasHolding != 0 && v.has&o.has&hasHolding == 0 {
		// an object of the env in some runs: its whole secrets are not
		// in every run
		out.has = out.has&^hasHolding | hasWhole
	}
	return out
}

// asString is v written in a string, as format writes it: an object
// Object, an array Array.
func (v secretValue) asString() secretValue {
	return v.as(v.has &^ (hasParsed | hasContext | hasHolding))
}

// as is v with what it has replaced by has, keeping the names and the
// outputs.
func (v secretValue) as(has secretHas) secretValue {
	if has == 0 {
		return secretValue{}
	}
	return secretValue{has: has, names: v.names, via: v.via}
}

// secretReader reads what the value of an expression has of the secrets.
// In a job, it reads needs.<job>.outputs.<name> as the value of that
// output of a job the job needs, and env.<name> as the value of the
// variable of the env the expression sees.
type secretReader struct {
	*jobOutputs
	needs map[string]bool                                 // the jobs the job needs, by expr.FoldName; nil outside a job
	envs  []workflow.Field[workflow.Map[workflow.String]] // the env the expression sees, the nearest first; none where GitHub allows no env context
	fold  bool                                            // whether the names of the env match in any case: the job runs on Windows
	// whether the names of the env may match in any case: the runs-on of
	// the job decides neither Windows nor Linux or macOS
	caseUnknown bool
}

// jobOutputs are the jobs of a workflow by expr.FoldName of their IDs,
// what each output read so far has of the secrets, and the env of the
// workflow.
type jobOutputs struct {
	jobs map[string]workflow.Job
	read map[[2]string]secretValue // by expr.FoldName of the job and of the output; nothing while it is read
	env  workflow.Field[workflow.Map[workflow.String]]
}

// newSecretReader reads outside a job of w.
func newSecretReader(w *workflow.Workflow) secretReader {
	o := &jobOutputs{jobs: map[string]workflow.Job{}, read: map[[2]string]secretValue{}, env: w.Env}
	for _, je := range w.Jobs.Value.Entries {
		if je.Value.Status != workflow.Present {
			continue
		}
		k := expr.FoldName(je.Value.Value.ID.AsString())
		if _, ok := o.jobs[k]; !ok { // the first of a duplicate ID
			o.jobs[k] = je.Value.Value
		}
	}
	return secretReader{jobOutputs: o}
}

// in is r reading in the job j, where the env is the job's and the
// workflow's: in the container, the services and the outputs of j, and in
// the env of its steps.
func (r secretReader) in(j workflow.Job) secretReader {
	needs := map[string]bool{}
	if j.Needs.Status == workflow.Present {
		for _, n := range j.Needs.Value.Items {
			needs[expr.FoldName(n.AsString())] = true
		}
	}
	fold := taint.WindowsRunner(&j)
	return secretReader{jobOutputs: r.jobOutputs, needs: needs, envs: []workflow.Field[workflow.Map[workflow.String]]{j.Env, r.env}, fold: fold, caseUnknown: !fold && !linuxOrMacOS(j)}
}

// linuxOrMacOS is whether the runs-on of j picks a GitHub-hosted Linux or
// macOS runner, whose env context matches names in their own case: every
// label, as written or as the matrix gives it, is one of theirs.
func linuxOrMacOS(j workflow.Job) bool {
	if j.RunsOnForm == workflow.RunsOnFormMapping {
		return false
	}
	labels, inconclusive := runnerLabelsOf(nil, j)
	if len(labels) == 0 || len(inconclusive) > 0 {
		return false
	}
	for _, l := range labels {
		if !slices.ContainsFunc(hostedSudoLabels, l.Label.Equal) {
			return false
		}
	}
	return true
}

// atStep is r reading in a step whose env is env: the env of the step
// first.
func (r secretReader) atStep(env workflow.Field[workflow.Map[workflow.String]]) secretReader {
	s := r
	s.envs = append([]workflow.Field[workflow.Map[workflow.String]]{env}, r.envs...)
	return s
}

// withoutEnv is r where GitHub allows no env context.
func (r secretReader) withoutEnv() secretReader {
	s := r
	s.envs = nil
	return s
}

// output is what the output name of the job id has of the secrets, as a
// later job reads it: a value taken out of a secret, or nothing. The
// runner drops an output whose value has a value it masks, a whole secret
// or the secrets context; the reading takes the output as dropped only
// when the value has one in every run (hasMust), and the reading of an output that comes back to
// itself gives nothing. Only needs that GitHub rejects as a cycle come
// back, so what such a reading keeps depends on the order the outputs
// are read in.
func (r secretReader) output(id, name string) secretValue {
	k := [2]string{expr.FoldName(id), expr.FoldName(name)}
	if v, ok := r.read[k]; ok {
		return v // nothing while it is read: a cycle
	}
	r.read[k] = secretValue{}
	j, ok := r.jobs[k[0]]
	if !ok || j.Kind == workflow.JobCall || j.Outputs.Status != workflow.Present {
		return secretValue{}
	}
	e, ok := j.Outputs.Value.Lookup(name)
	if !ok || e.Value.Status != workflow.Present {
		return secretValue{}
	}
	jr := r.in(j)
	s := e.Value.Value
	var all secretValue
	var parts []OutputPart
	for i, p := range s.Parts {
		if !p.Expr || p.Tree == nil {
			continue
		}
		pv := jr.of(p.Tree)
		if pv.has&hasPart != 0 {
			parts = append(parts, OutputPart{Job: j.ID.AsString(), Output: e.Key.AsString(), Value: s, Part: i})
		}
		all = all.union(pv)
	}
	if all.has&hasMust != 0 || all.has&hasPart == 0 {
		return secretValue{}
	}
	v := secretValue{has: hasPart, names: all.names, via: slices.Clip(append(parts, all.via...))}
	r.read[k] = v
	return v
}

// needsValue is what p, a reference that starts at needs, has of the
// secrets: an output of a job the job needs, or an object or an array of
// them, which has a value taken out of a secret when one of them does.
// The outputs of several jobs come in the order of the IDs of the jobs.
func (r secretReader) needsValue(p []expr.PathElem) secretValue {
	if r.needs == nil || len(p) > 4 {
		return secretValue{} // outside a job, or a property of a string
	}
	// needs, needs.<job> and needs.<job>.outputs are objects, a star
	// makes an array
	whole := len(p) < 4 || slices.ContainsFunc(p, func(e expr.PathElem) bool { return e.Star })
	var ids []string
	switch {
	case len(p) == 1 || p[1].Name == "":
		for id := range r.needs {
			ids = append(ids, id)
		}
		slices.Sort(ids)
	case r.needs[expr.FoldName(p[1].Name)]:
		ids = []string{expr.FoldName(p[1].Name)}
	}
	if len(p) > 2 && p[2].Name != "" && !expr.EqualName(p[2].Name, "outputs") {
		return secretValue{} // result
	}
	var out secretValue
	for _, id := range ids {
		j, ok := r.jobs[id]
		if !ok || j.Outputs.Status != workflow.Present {
			continue
		}
		for _, e := range j.Outputs.Value.Entries {
			name := e.Key.AsString()
			if len(p) == 4 && p[3].Name != "" && !expr.EqualName(p[3].Name, name) {
				continue
			}
			out = out.union(r.output(id, name))
		}
	}
	if whole && out.has&hasPart != 0 {
		return out.as(hasParsed)
	}
	return out
}

// envValue is what p, a reference that starts at env, has of the secrets:
// a variable of the env the expression sees, the nearest level's of each
// name, or an object or an array of them, which has a value taken out of a
// secret when one of them does. The value of a variable is read with the
// levels above its own, as the runner evaluates the env of a level with
// the env of the levels above it. A name matches in any case in a job
// that runs on Windows, and only in its own case elsewhere, as the env
// context of the runner does on Windows and on Linux and macOS.
func (r secretReader) envValue(p []expr.PathElem) secretValue {
	if len(p) > 2 {
		return secretValue{} // a property of a string: null
	}
	// env is an object, a star makes an array; a name not written is
	// one of the variables
	whole := len(p) == 1 || p[1].Star
	named := len(p) == 2 && p[1].Name != ""
	key := func(name string) string {
		if r.fold {
			return expr.FoldName(name)
		}
		return name
	}
	var out secretValue
	first := true
	seen := map[string]bool{}
	for lvl, e := range r.envs {
		if e.Status != workflow.Present {
			continue
		}
		for _, x := range e.Value.Entries {
			name := key(x.Key.AsString())
			if seen[name] || named && name != key(p[1].Name) {
				continue
			}
			seen[name] = true
			var v secretValue
			if x.Value.Status == workflow.Present {
				above := r
				above.envs = r.envs[lvl+1:]
				v = above.stringValue(x.Value.Value)
			}
			if !r.sure(lvl, x.Key.AsString()) {
				v.has &^= hasMust
			}
			switch {
			case whole:
				out = out.union(v)
			case first:
				out = v
			default:
				out = out.either(v)
			}
			first = false
		}
	}
	if !whole {
		return out
	}
	var has secretHas
	if out.has&hasPart != 0 {
		has |= hasParsed
	}
	if out.has&hasMust != 0 {
		has |= hasHolding
	}
	return out.as(has)
}

// sure is whether env.name reads the variable name of the level lvl of the
// env in every run: no nearer level is an env written as one ${{ }}, and,
// where the names may match in any case, no nearer level has the name in
// another case.
func (r secretReader) sure(lvl int, name string) bool {
	for _, e := range r.envs[:lvl] {
		switch {
		case e.Status == workflow.Dynamic:
			return false
		case e.Status != workflow.Present || !r.caseUnknown:
			continue
		}
		for _, x := range e.Value.Entries {
			if n := x.Key.AsString(); n != name && expr.EqualName(n, name) {
				return false
			}
		}
	}
	return true
}

// stringValue is what the string v has of the secrets: each of its ${{ }}
// written in it.
func (r secretReader) stringValue(v workflow.String) secretValue {
	var out secretValue
	for _, p := range v.Parts {
		if p.Expr && p.Tree != nil {
			out = out.union(r.of(p.Tree))
		}
	}
	return out.asString()
}

// of is what the value of n has of the secrets, by what the runner was
// seen to print of values made of secrets.
func (r secretReader) of(n expr.Node) secretValue {
	if p, ok := expr.AccessPath(n); ok {
		switch {
		case expr.EqualName(p[0].Name, "needs"):
			return r.needsValue(p)
		case expr.EqualName(p[0].Name, "env"):
			return r.envValue(p)
		case len(p) == 2 && expr.EqualName(p[0].Name, "github") && expr.EqualName(p[1].Name, "token"):
			return secretValue{has: hasWhole | hasMust} // the job's token, which the runner masks as secrets.GITHUB_TOKEN
		case !expr.EqualName(p[0].Name, "secrets"):
			return secretValue{}
		case len(p) == 1:
			return secretValue{has: hasContext}
		case len(p) == 2 && p[1].Name == "":
			return secretValue{has: hasWhole | hasMust, names: []string{"*"}}
		case len(p) == 2:
			return secretValue{has: hasWhole | hasMust, names: []string{p[1].Name}}
		}
		return secretValue{} // a property of a string: null
	}
	switch x := n.(type) {
	case *expr.Group:
		return r.of(x.X)
	case *expr.Property:
		return deref(r.of(x.X))
	case *expr.Index:
		return deref(r.of(x.X))
	case *expr.Star:
		// an array, which a string makes Array: a value only through
		// join, toJSON or an index
		v := r.of(x.X)
		if v.has&(hasParsed|hasPart|hasHolding) != 0 {
			var has secretHas
			if v.has&(hasParsed|hasPart) != 0 {
				has |= hasParsed
			}
			return v.as(has | v.has&hasHolding) // the values of an object of the env are the values of the array
		}
		return deref(v)
	case *expr.Logical:
		if x.Op == expr.OpAnd {
			// a falsy operand or the last (the runner's And.cs): a value
			// taken out of a secret only as the last
			return r.of(x.Xs[len(x.Xs)-1])
		}
		out := r.of(x.Xs[0])
		for _, c := range x.Xs[1:] {
			out = out.either(r.of(c))
		}
		return out
	case *expr.Call:
		return r.call(x)
	}
	return secretValue{} // a literal, a comparison, a not: no value of a secret
}

// deref is what .y, [i] or .* of a value v gives.
func deref(v secretValue) secretValue {
	var out secretValue
	switch {
	case v.has&(hasParsed|hasPart) != 0:
		out = v.as(hasPart)
	case v.has&hasContext != 0:
		out = secretValue{has: hasWhole | hasMust, names: []string{"*"}}
	}
	if v.has&hasHolding != 0 {
		// a property not named may be any of the values: a whole secret
		// in some runs
		out = out.union(v.as(hasWhole))
	}
	return out
}

// holdingWhole is the whole secrets that v, an object or an array of the
// env, has among its values (hasHolding), which toJSON and join write in
// every run.
func holdingWhole(v secretValue) secretValue {
	if v.has&hasHolding == 0 {
		return secretValue{}
	}
	return v.as(hasWhole | hasMust)
}

// call is what the value of the call x has of the secrets.
func (r secretReader) call(x *expr.Call) secretValue {
	arg := func(i int) secretValue {
		if i < len(x.Args) {
			return r.of(x.Args[i])
		}
		return secretValue{}
	}
	switch strings.ToLower(x.Name) {
	case "fromjson":
		a := arg(0)
		switch {
		case a.has&(hasWhole|hasPart) != 0:
			return a.as(hasParsed)
		case a.has&hasContextJSON != 0:
			return secretValue{has: hasContext}
		}
	case "tojson":
		a := arg(0)
		var out secretValue
		switch {
		case a.has&(hasParsed|hasPart) != 0:
			out = a.as(hasPart) // written anew: neither the whole nor a line of it
		case a.has&hasContext != 0:
			out = secretValue{has: hasContextJSON | hasMust, names: []string{"*"}}
		case a.has&hasWhole != 0:
			out = a.as(hasWhole)
		}
		out.has |= a.has & hasMust // a masked value written in JSON is masked
		return out.union(holdingWhole(a))
	case "join":
		var out secretValue
		a := arg(0)
		switch {
		case a.has&(hasParsed|hasPart) != 0:
			out = a.as(hasPart)
		case a.has&hasWhole != 0:
			out = a.as(hasWhole)
		}
		out.has |= a.has & hasMust
		out = out.union(holdingWhole(a))
		if sep := arg(1); sep.has&hasPart != 0 { // written between the items
			out = out.union(sep.as(hasPart))
		}
		return out
	case "format":
		// each argument as a string: an object Object, an array Array
		var out secretValue
		for i := range x.Args {
			out = out.union(arg(i))
		}
		return out.asString()
	case "case":
		// case(p1, v1, p2, v2, ..., default): the values, not the predicates
		var vals []int
		for i := 1; i < len(x.Args); i += 2 {
			vals = append(vals, i)
		}
		if len(x.Args)%2 == 1 {
			vals = append(vals, len(x.Args)-1)
		}
		var out secretValue
		for k, i := range vals {
			if k == 0 {
				out = arg(i)
			} else {
				out = out.either(arg(i))
			}
		}
		return out
	}
	return secretValue{}
}
