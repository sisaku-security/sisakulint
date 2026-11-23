package workflow

import (
	"fmt"
	"strings"

	"github.com/gh-intel/sisakulint/actions/expr"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// What GitHub's reader rejects beyond the schema: the ids of steps, the
// graph of needs, the calls of reusable workflows (CheckCall), and the
// steps that run alongside others (parallel, wait-all, wait and cancel).
// Most are checked after the typed reading; a parallel group in a group,
// an empty group, wait-all: false, and wait, wait-all and cancel in a group
// are checked as the step is read, since the steps read keep none of them.
// A ${{ }} that is exactly a string literal is folded to its string by
// GitHub, in an id, a need and a job's key alike, and is judged by that
// string (AsString).

// validID is the rule of the converter's IdBuilder for job and step ids:
// [A-Za-z_][A-Za-z0-9_-]*, shorter than 100, and __ is reserved.
func validID(id string) bool {
	if id == "" || len(id) >= 100 || strings.HasPrefix(id, "__") {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case i > 0 && (c >= '0' && c <= '9' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// checkStepIDs reports the ids of the steps of a job that GitHub rejects:
// one not of the form of an id, and one that is already
// the id of an earlier step of the job, compared without case. The steps
// of parallel groups are in the job's scope. An id with a ${{ }} that is
// not a string literal GitHub folds, which the schema does not allow, is
// left to that diagnostic; a folded literal is judged by its string
// (AsString). An id YAML reads as a number is not judged: GitHub writes a
// number as a string its own way (an infinity is Infinity, which AsString
// writes +Inf).
func (r *reader) checkStepIDs(steps Field[List[Step]]) {
	if steps.Status != Present {
		return
	}
	seen := map[string]bool{}
	for _, s := range steps.Value.Items {
		if s.ID.Status != Present || s.ID.Value.HasExpr() || s.ID.Value.lit == litNumber {
			continue
		}
		id, b := s.ID.Value.AsString(), s.ID.Value.Base
		switch k := expr.FoldName(id); {
		case !validID(id):
			r.report(InvalidValue, b.Node.ContentSpan(), pos{via: b.Via}, "the step id %q is invalid: a step id must start with a letter or _, contain only letters, digits, _ and -, be shorter than 100 characters, and not start with __", id)
		case seen[k]:
			r.report(InvalidValue, b.Node.ContentSpan(), pos{via: b.Via}, "the step id %q is already the id of an earlier step of the job (step ids are compared without case)", id)
		default:
			seen[k] = true
		}
	}
}

// checkStepTargets reports the names a wait or a cancel step gives that are
// not the id of an earlier step of the job, which GitHub rejects (a later
// step and the step itself are rejected too). Names are compared without
// case, and an earlier step counts whether it runs in the background or not,
// and when it is in a parallel group. A wait or a cancel in a group is
// reported by checkInGroup, not here. When the id of an earlier step is not
// known (an id with a ${{ }} GitHub does not fold, or one YAML reads as a
// number, as checkStepIDs; an id not read; a step not read; a parallel group
// in a group, whose steps are not read), nothing more is reported; nor is a
// name with such a ${{ }}, one that is not a string, or an empty one.
func (r *reader) checkStepTargets(steps Field[List[Step]]) {
	if steps.Status != Present {
		return
	}
	ids := map[string]bool{}
	own := "" // expr.FoldName of the id of the step whose names are checked
	check := func(key string, name String) {
		if name.HasExpr() || name.Parts == nil && name.lit != litString {
			return
		}
		id := name.AsString()
		if id == "" || ids[expr.FoldName(id)] {
			return
		}
		msg := fmt.Sprintf("GitHub rejects the workflow: %s: refers to the step id %q, but no step before this %s step has the id %q. Write the id of a step before this %s step in %s:", key, id, key, id, key, key)
		// giving the id to an earlier step would be rejected in turn: an id
		// starting with __ is reserved, and two steps cannot share an id
		if !strings.HasPrefix(id, "__") && expr.FoldName(id) != own {
			msg += fmt.Sprintf(", or give the id %q to a step before this %s step", id, key)
		}
		r.report(InvalidValue, name.Node.ContentSpan(), pos{via: name.Via}, "%s", msg)
	}
	for _, s := range steps.Value.Items {
		if s.nested || s.Kind == StepInvalid {
			return
		}
		own = ""
		if s.ID.Status == Present && !s.ID.Value.HasExpr() {
			own = expr.FoldName(s.ID.Value.AsString())
		}
		if _, inGroup := s.Place.Parallel(); !inGroup {
			if s.Wait.Status == Present {
				for _, name := range s.Wait.Value.Items {
					check("wait", name)
				}
			}
			if s.Cancel.Status == Present {
				check("cancel", s.Cancel.Value)
			}
		}
		switch s.ID.Status {
		case Absent:
			continue
		case Present:
		default:
			return
		}
		if s.ID.Value.HasExpr() || s.ID.Value.lit == litNumber {
			return
		}
		ids[expr.FoldName(s.ID.Value.AsString())] = true
	}
}

// checkInGroup reports e, a wait, a wait-all or a cancel of a step in a
// parallel group, which GitHub rejects.
func (r *reader) checkInGroup(e *entry, p pos) {
	r.report(InvalidValue, e.keyNode.ContentSpan(), p, "GitHub rejects the workflow: %s: cannot be written in a step of a parallel group; write the %s step after the parallel group", e.name, e.name)
}

// checkNestedGroup reports a parallel group in a parallel group, whose
// key is e, which GitHub rejects.
func (r *reader) checkNestedGroup(e *entry, p pos) {
	r.report(InvalidValue, e.keyNode.ContentSpan(), p, "GitHub rejects the workflow: a parallel group is written inside another parallel group; write the steps of the inner parallel group in the outer parallel group, or move the inner parallel group after the outer parallel group")
}

// checkEmptyGroup reports v, the steps of a parallel group, which are
// none: GitHub rejects an empty group.
func (r *reader) checkEmptyGroup(v val) {
	r.report(InvalidValue, v.n.ContentSpan(), v.p, "GitHub rejects the workflow: a parallel group must contain at least one step; add steps to the parallel group, or remove the empty parallel group")
}

// checkWaitAll reports the value of wait-all when it is the boolean
// literal false, which GitHub rejects; true and an empty
// value wait for all background steps.
func (r *reader) checkWaitAll(f Field[String]) {
	if f.Status != Present || f.Value.Parts != nil || f.Value.lit != litBool || f.Value.AsString() != "false" {
		return
	}
	b := f.Value.Base
	r.report(InvalidValue, b.Node.ContentSpan(), pos{via: b.Via}, "GitHub rejects the workflow: wait-all cannot be false. To wait for all background steps, write wait-all: true, or wait-all: with nothing after the colon; to wait for only some background steps, write wait: with the ids of the background steps to wait for, instead of wait-all:")
}

// checkNeeds reports what GitHub's reader rejects of the needs of jobs
// (jobs.ts validateNeeds): a job that is not in the
// workflow, a need on a cycle, and no job without needs. Job ids are
// looked up without case, and a job named twice in needs is fine. Unlike
// jobs.ts, a need of a job after a cycle that is not on it is not
// reported. A job id or a need with a ${{ }} GitHub does not fold leaves
// what the job id or the need would decide unchecked, and so do a job of
// no known kind and a job whose key the reader could not read.
func (r *reader) checkNeeds(jobs Field[Map[Job]]) {
	if jobs.Status != Present {
		return
	}
	ents := jobs.Value.Entries
	index := map[string]int{}
	for i, e := range ents {
		if e.Key.HasExpr() {
			return
		}
		k := expr.FoldName(e.Key.AsString())
		if _, ok := index[k]; !ok {
			index[k] = i
		}
	}
	type edge struct {
		to   int
		need String
	}
	edges := make([][]edge, len(ents))
	read, start, known := 0, false, true
	for i, e := range ents {
		// a job of no known kind, already reported, is left out, as the
		// converter leaves out a job it cannot read
		if e.Value.Status != Present || e.Value.Value.Kind == JobUnknown {
			known = false
			continue
		}
		read++
		needs := e.Value.Value.Needs
		switch needs.Status {
		case Absent:
			start = true
			continue
		case Present:
		default:
			known = false
			continue
		}
		if len(needs.Value.Items) == 0 {
			start = true
		}
		for _, n := range needs.Value.Items {
			if n.HasExpr() || n.lit == litNumber { // as checkStepIDs
				known = false
				continue
			}
			to, ok := index[expr.FoldName(n.AsString())]
			if !ok {
				r.report(InvalidValue, n.Node.ContentSpan(), pos{via: n.Via}, "the job %q needs the job %q, which is not in the workflow", e.Key.AsString(), n.AsString())
				continue
			}
			edges[i] = append(edges[i], edge{to, n})
		}
	}
	adj := make([][]int, len(ents))
	for i, es := range edges {
		for _, x := range es {
			adj[i] = append(adj[i], x.to)
		}
	}
	comp := components(adj)
	for i, es := range edges {
		for _, x := range es {
			if comp[i] == comp[x.to] {
				r.report(InvalidValue, x.need.Node.ContentSpan(), pos{via: x.need.Via}, "the job %q needs the job %q, and the job %q needs the job %q, directly or through other jobs: the needs form a cycle", ents[i].Key.AsString(), ents[x.to].Key.AsString(), ents[x.to].Key.AsString(), ents[i].Key.AsString())
			}
		}
	}
	// a job whose key the reader could not read (a ${{ }} where it is not
	// allowed, a key that is not a scalar, an alias without an anchor) is
	// not in ents, and may be the job with no needs
	if m, ok := jobs.Value.Base.Node.Mapping(); ok {
		n := 0
		for range m.Entries() {
			n++
		}
		known = known && n == len(ents)
	}
	if read > 0 && !start && known {
		b := jobs.Value.Base
		r.report(InvalidValue, b.Node.ContentSpan(), pos{via: b.Via}, "the workflow must contain at least one job with no needs")
	}
}

// components are the strongly connected components of the graph adj, by
// node (Tarjan's algorithm, without recursion): two nodes have the same
// component when each can reach the other. A node on no cycle has a
// component of its own, so an edge between two nodes of one component is
// on a cycle, an edge of a node to itself included.
func components(adj [][]int) []int {
	n := len(adj)
	index, low, comp := make([]int, n), make([]int, n), make([]int, n)
	for i := range index {
		index[i], comp[i] = -1, -1
	}
	onStack := make([]bool, n)
	var stack []int
	next, ncomp := 0, 0
	type frame struct{ v, e int }
	for root := range adj {
		if index[root] >= 0 {
			continue
		}
		call := []frame{{root, 0}}
		index[root], low[root] = next, next
		next++
		stack = append(stack, root)
		onStack[root] = true
		for len(call) > 0 {
			f := &call[len(call)-1]
			if f.e < len(adj[f.v]) {
				w := adj[f.v][f.e]
				f.e++
				switch {
				case index[w] < 0:
					index[w], low[w] = next, next
					next++
					stack = append(stack, w)
					onStack[w] = true
					call = append(call, frame{w, 0})
				case onStack[w]:
					low[f.v] = min(low[f.v], index[w])
				}
				continue
			}
			v := f.v
			call = call[:len(call)-1]
			if len(call) > 0 {
				p := call[len(call)-1].v
				low[p] = min(low[p], low[v])
			}
			if low[v] == index[v] {
				for {
					w := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					onStack[w] = false
					comp[w] = ncomp
					if w == v {
						break
					}
				}
				ncomp++
			}
		}
	}
	return comp
}

// CheckCall is what GitHub's reader rejects of job, a job that calls a
// reusable workflow, against called, the workflow its uses names: called
// without workflow_call, a required input or secret not
// given (a default does not count), an input or a secret called does not
// define, and a value of a boolean or a number input that is a literal of
// another type. Names are compared without case. A value with a ${{ }} is
// decided when the run is made and is not checked, nor a null; the
// secrets of secrets: inherit are the repository's, and are not checked.
// What of job or called was not read is not checked.
func CheckCall(job Job, called *Workflow) []Diagnostic {
	if job.Kind != JobCall || job.Uses.Status != Present || called == nil || called.On.Status != Present {
		return nil
	}
	uses := job.Uses.Value.Base
	ev, ok := called.On.Value.Event(EventNameWorkflowCall)
	if !ok {
		return []Diagnostic{diagnosticAt(InvalidValue, uses, "the called workflow has no workflow_call event, so it cannot be called")}
	}
	ds := checkPassed(job.With, ev.Inputs, uses, "input", "with",
		func(in Input) bool { return isTrue(in.Required) }, inputValueError)
	if !job.InheritSecrets {
		ds = append(ds, checkPassed(job.Secrets, ev.Secrets, uses, "secret", "secrets",
			func(s Secret) bool { return isTrue(s.Required) }, nil)...)
	}
	return ds
}

// checkPassed checks given, the with or the secrets of a job, against
// defs, the inputs or the secrets of workflow_call: what (input or
// secret) is required, defined, and of the type (wrong; nil for secrets).
// A missing one is reported at the key of given (named key), or at uses
// without it.
func checkPassed[D any](given Field[Map[String]], defs Field[Map[D]], uses Base, what, key string, required func(D) bool, wrong func(D, String) string) []Diagnostic {
	if given.Status != Present && given.Status != Absent || defs.Status != Present && defs.Status != Absent {
		return nil
	}
	// each side is indexed once, so that a call of n names is checked in
	// time linear in n (Map.Lookup scans)
	givenNames := map[string]bool{}
	for _, e := range given.Value.Entries {
		givenNames[expr.FoldName(e.Key.AsString())] = true
	}
	defined := map[string]Entry[D]{}
	for _, d := range defs.Value.Entries {
		k := expr.FoldName(d.Key.AsString())
		if _, ok := defined[k]; !ok {
			defined[k] = d
		}
	}
	var ds []Diagnostic
	for _, d := range defs.Value.Entries {
		if d.Key.Parts != nil || d.Value.Status != Present || !required(d.Value.Value) {
			continue
		}
		if givenNames[expr.FoldName(d.Key.AsString())] {
			continue
		}
		at := uses
		if given.Status == Present {
			at = Base{Node: given.Key}
		}
		ds = append(ds, diagnosticAt(MissingKey, at, "the called workflow requires the %s %q, which %s does not give", what, d.Key.AsString(), key))
	}
	for _, e := range given.Value.Entries {
		if e.Key.Parts != nil {
			continue
		}
		d, ok := defined[expr.FoldName(e.Key.AsString())]
		if !ok {
			ds = append(ds, diagnosticAt(UnknownKey, e.Key.Base, "the called workflow defines no %s %q", what, e.Key.AsString()))
			continue
		}
		if wrong == nil || d.Value.Status != Present || e.Value.Status != Present {
			continue
		}
		if msg := wrong(d.Value.Value, e.Value.Value); msg != "" {
			ds = append(ds, diagnosticAt(InvalidValue, e.Value.Value.Base, "%s", msg))
		}
	}
	return ds
}

// inputValueError is why v is not a value of the type of the input in,
// or "" when it is, or is not known before the run: a ${{ }} other than a
// string literal GitHub folds (AsString), and a null.
func inputValueError(in Input, v String) string {
	if in.Type.Status != Present || v.HasExpr() || v.Parts == nil && v.lit == litNull {
		return ""
	}
	_, folded := v.literal()
	switch t := in.Type.Value.AsString(); {
	case t == "boolean" && (folded || v.lit != litBool):
		return fmt.Sprintf("the input is a boolean, and %q is not a boolean (a quoted true is a string)", v.AsString())
	case t == "number" && (folded || v.lit != litNumber):
		return fmt.Sprintf("the input is a number, and %q is not a number (a quoted number is a string)", v.AsString())
	}
	return ""
}

// isTrue is whether f is the boolean literal true.
func isTrue(f Field[String]) bool {
	return f.Status == Present && f.Value.Parts == nil && f.Value.lit == litBool && f.Value.AsString() == "true"
}

// diagnosticAt is a diagnostic about the element at b: where it is used
// (the outermost alias), with the shared content as Related, as
// reader.report makes one.
func diagnosticAt(c Code, b Base, format string, args ...any) Diagnostic {
	d := Diagnostic{Code: c, Span: b.Node.ContentSpan(), Msg: fmt.Sprintf(format, args...)}
	if len(b.Via) > 0 {
		d.Span = b.Via[0].ContentSpan()
		d.Related = []cst.Span{b.Node.ContentSpan()}
	}
	return d
}
