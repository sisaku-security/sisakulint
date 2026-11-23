package workflow

import (
	"strconv"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// StepKind is what a step does, by the definition of steps-item its keys
// chose.
type StepKind uint8

const (
	StepRun     StepKind = iota // run-step
	StepAction                  // regular-step
	StepOther                   // wait-step, wait-all-step, cancel-step, and a parallel-step in a parallel group
	StepInvalid                 // not a mapping, or its keys do not tell (reported)
)

var stepKindNames = [...]string{"StepRun", "StepAction", "StepOther", "StepInvalid"}

func (k StepKind) String() string { return stepKindNames[k] }

// StepPlace is where a step is written: its index in steps, and in the
// parallel group of the step at that index when it is in one.
type StepPlace struct {
	Steps int
	inner int // the index in the parallel group, plus 1; 0 when not in one
}

// InGroup is a place in the parallel group of the step at index steps.
func InGroup(steps, index int) StepPlace { return StepPlace{Steps: steps, inner: index + 1} }

// Parallel is the index in the parallel group, if the step is in one.
func (p StepPlace) Parallel() (int, bool) { return p.inner - 1, p.inner > 0 }

// String is the place as a path below the job or the action: steps[2], or
// steps[2].parallel[0].
func (p StepPlace) String() string {
	s := "steps[" + strconv.Itoa(p.Steps) + "]"
	if i, ok := p.Parallel(); ok {
		s += ".parallel[" + strconv.Itoa(i) + "]"
	}
	return s
}

// Step is one step of a job or of the runs of a composite action. The steps
// of a parallel group stand in place of the group, which is not a step of
// its own; a parallel group in a group, which GitHub rejects, stays a
// StepOther.
// Place is where the step is written; Order is its index in the list.
type Step struct {
	Base
	Place StepPlace
	Order int
	Kind  StepKind
	ID    Field[String]
	Name  Field[String]
	If    Field[If]
	Run   Field[String]
	Shell Field[String]
	Uses  Field[Uses]
	With  Field[Map[String]]
	Env   Field[Map[String]]
	// TimeoutMinutes, ContinueOnError and WorkingDirectory are as written:
	// the schema checks the values
	TimeoutMinutes   Field[String]
	ContinueOnError  Field[String]
	WorkingDirectory Field[String]
	Background       bool                // background: true, or a value that is not false
	Wait             Field[List[String]] // the ids a wait step waits for
	Cancel           Field[String]       // the id a cancel step stops
	WaitAll          bool                // a wait-all step
	nested           bool                // a parallel group in a parallel group, whose steps are not read
}

// steps reads the value of e as the steps of a job. It does not depend on
// the job, so that the runs.steps of an action.yml can be read the same
// way.
func (r *reader) steps(e *entry, p pos) Field[List[Step]] {
	if e == nil {
		return Field[List[Step]]{}
	}
	v := r.value(e.value, p, e.def)
	f := field[List[Step]](e, v)
	if v.st != Present || v.kind != valSequence {
		return f
	}
	f.Value.Base = Base{Node: v.n, Via: v.p.via}
	item := schemaDefs[ofKind(e.def, nil, kindSequence)[0]].item
	seq, _ := v.n.Sequence()
	i := 0
	for range seq.Items() {
		i++
	}
	f.Value.Items = make([]Step, 0, i)
	i = 0
	add := func(s Step) {
		s.Order = len(f.Value.Items)
		f.Value.Items = append(f.Value.Items, s)
	}
	for n := range seq.Items() {
		s, group, gp := r.step(n, v.p, item, StepPlace{Steps: i})
		if group == nil {
			add(s)
		} else {
			for k, gn := range r.group(group, gp) {
				g, _, _ := r.step(gn.n, gn.p, gn.d, InGroup(i, k))
				add(g)
			}
		}
		i++
	}
	matchOutside(f.Value.Items)
	return f
}

// groupItem is an item of a parallel group, with where and how to read it.
type groupItem struct {
	n cst.Node
	p pos
	d defID
}

// group are the items of the parallel group of e.
func (r *reader) group(e *entry, p pos) []groupItem {
	v := r.value(e.value, p, e.def)
	if v.st != Present || v.kind != valSequence {
		return nil
	}
	item := schemaDefs[ofKind(e.def, nil, kindSequence)[0]].item
	seq, _ := v.n.Sequence()
	var out []groupItem
	for n := range seq.Items() {
		out = append(out, groupItem{n, v.p, item})
	}
	if len(out) == 0 {
		r.checkEmptyGroup(v)
	}
	return out
}

// step reads the step n at place. A parallel-step not in a group gives the
// entry of its group, whose steps stand in its place, and where it is.
func (r *reader) step(n cst.Node, p pos, d defID, place StepPlace) (Step, *entry, pos) {
	v := r.value(n, p, d)
	s := Step{Base: Base{Node: v.n, Via: v.p.via}, Place: place, Kind: StepInvalid}
	if v.st != Present || v.kind != valMapping {
		return s, nil, p
	}
	ents, chosen, ambiguous := r.mapping(v, d)
	if !ambiguous {
		switch chosen {
		case dRunStep, dActionRunStep:
			s.Kind = StepRun
		case dRegularStep, dActionUsesStep:
			s.Kind = StepAction
		default:
			s.Kind = StepOther
		}
	}
	p = v.p
	if !ambiguous && chosen == dParallelStep {
		if _, inGroup := place.Parallel(); !inGroup {
			return s, get(ents, "parallel"), p
		}
		s.nested = true
		r.checkNestedGroup(get(ents, "parallel"), p)
	}
	s.ID = r.str(get(ents, "id"), p)
	s.Name = r.str(get(ents, "name"), p)
	s.If = r.condition(get(ents, "if"), p)
	s.Run = r.str(get(ents, "run"), p)
	s.Shell = r.str(get(ents, "shell"), p)
	s.Uses = r.uses(get(ents, "uses"), p)
	s.With = r.strMap(get(ents, "with"), p)
	s.Env = r.strMap(get(ents, "env"), p)
	s.TimeoutMinutes = r.str(get(ents, "timeout-minutes"), p)
	s.ContinueOnError = r.str(get(ents, "continue-on-error"), p)
	s.WorkingDirectory = r.str(get(ents, "working-directory"), p)
	if bg := r.str(get(ents, "background"), p); bg.Status != Absent {
		s.Background = !(bg.Status == Present && bg.Value.lit == litBool && bg.Value.AsString() == "false")
	}
	s.Wait = r.strList(get(ents, "wait"), p)
	s.Cancel = r.str(get(ents, "cancel"), p)
	_, inGroup := place.Parallel()
	if e := get(ents, "wait-all"); e != nil {
		s.WaitAll = true
		if !inGroup {
			r.checkWaitAll(r.str(e, p))
		}
	}
	if inGroup && !ambiguous {
		switch chosen {
		case dWaitStep:
			r.checkInGroup(get(ents, "wait"), p)
		case dWaitAllStep:
			r.checkInGroup(get(ents, "wait-all"), p)
		case dCancelStep:
			r.checkInGroup(get(ents, "cancel"), p)
		}
	}
	if inGroup {
		s.Background = true // every step of a group runs as a background step
	}
	return s, nil, p
}
