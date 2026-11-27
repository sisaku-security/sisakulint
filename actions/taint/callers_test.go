package taint

import (
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/callerstest"
)

func callersOf(t *testing.T, complete bool, files ...[2]string) *Callers {
	t.Helper()
	return NewCallers(callerstest.Graph(t, complete, false, files...))
}

func inputName(s string) calls.Node { return calls.InputNode(facts.MustCleanInputPath(s)) }

// eventNames are the names of evs, each once.
func eventNames(evs []analysis.EventActivity) []string {
	var out []string
	for _, e := range evs {
		if !slices.Contains(out, e.Name().String()) {
			out = append(out, e.Name().String())
		}
	}
	return out
}

const calledEcho = "on:\n  workflow_call:\n    inputs:\n      t: {type: string}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.t }}\"\n"

func TestCallersEventsOnlyCallers(t *testing.T) {
	c := callersOf(t, true,
		[2]string{".github/workflows/called.yml", calledEcho},
		[2]string{".github/workflows/ci.yml", "on: push\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n"})
	evs, cov := c.Events(inputName(".github/workflows/called.yml"), TableEvents(), false)
	if cov != analysis.CallerCoverageAll || !slices.Equal(eventNames(evs), []string{"push"}) {
		t.Fatalf("events = %v, coverage = %v", eventNames(evs), cov)
	}
}

func TestCallersEventsOwnPlusCallers(t *testing.T) {
	own := "on:\n  issues:\n  workflow_call:\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n"
	c := callersOf(t, true,
		[2]string{".github/workflows/called.yml", own},
		[2]string{".github/workflows/ci.yml", "on: push\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n"})
	evs, _ := c.Events(inputName(".github/workflows/called.yml"), TableEvents(), false)
	if !slices.Equal(eventNames(evs), []string{"issues", "push"}) {
		t.Fatalf("events = %v", eventNames(evs))
	}
}

func TestCallersEventsCallerIf(t *testing.T) {
	c := callersOf(t, true,
		[2]string{".github/workflows/called.yml", calledEcho},
		[2]string{".github/workflows/ci.yml", "on: [push, issues]\njobs:\n  c:\n    if: github.event_name == 'push'\n    uses: ./.github/workflows/called.yml\n"})
	evs, _ := c.Events(inputName(".github/workflows/called.yml"), TableEvents(), false)
	if !slices.Equal(eventNames(evs), []string{"push"}) {
		t.Fatalf("events = %v", eventNames(evs))
	}
}

func TestCallersEventsStepIf(t *testing.T) {
	ci := "on: [push, issues]\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - if: github.event_name == 'issues'\n        uses: ./x\n"
	c := callersOf(t, true, [2]string{"x/action.yml", "runs:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n"}, [2]string{".github/workflows/ci.yml", ci})
	evs, _ := c.Events(inputName("x/action.yml"), TableEvents(), false)
	if !slices.Equal(eventNames(evs), []string{"issues"}) {
		t.Fatalf("events = %v", eventNames(evs))
	}
}

// TestCallersEventsStepIfNeeds: the if of the step of the caller's job
// reads the results of the jobs that the job needs, which succeeded when
// the job runs (attacker.StepIf), but not in a job whose if is always().
func TestCallersEventsStepIfNeeds(t *testing.T) {
	ci := func(jobIf string) string {
		return "on: [push, issues]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n  j:\n    needs: build\n" + jobIf + "    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - if: needs.build.result == 'failure' || github.event_name == 'issues'\n        uses: ./x\n"
	}
	for _, c := range []struct {
		jobIf string
		want  []string
	}{
		{"", []string{"issues"}},
		{"    if: always()\n", []string{"issues", "push"}},
	} {
		cl := callersOf(t, true, [2]string{"x/action.yml", "runs:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n"}, [2]string{".github/workflows/ci.yml", ci(c.jobIf)})
		evs, _ := cl.Events(inputName("x/action.yml"), TableEvents(), false)
		if !slices.Equal(eventNames(evs), c.want) {
			t.Errorf("%q: events = %v, want %v", c.jobIf, eventNames(evs), c.want)
		}
	}
}

func TestCallersEventsNested(t *testing.T) {
	mid := "on:\n  workflow_call:\njobs:\n  n:\n    uses: ./.github/workflows/called.yml\n"
	c := callersOf(t, true,
		[2]string{".github/workflows/called.yml", calledEcho},
		[2]string{".github/workflows/mid.yml", mid},
		[2]string{".github/workflows/ci.yml", "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/mid.yml\n"})
	evs, _ := c.Events(inputName(".github/workflows/called.yml"), TableEvents(), false)
	if !slices.Equal(eventNames(evs), []string{"issues"}) {
		t.Fatalf("events = %v", eventNames(evs))
	}
}

func TestCallersEventsWorstCase(t *testing.T) {
	for _, tc := range []struct {
		name     string
		complete bool
		files    [][2]string
	}{
		{"none", true, [][2]string{{".github/workflows/called.yml", calledEcho}}},
		{"partial", false, [][2]string{{".github/workflows/called.yml", calledEcho}, {".github/workflows/ci.yml", "on: push\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := callersOf(t, tc.complete, tc.files...)
			evs, _ := c.Events(inputName(".github/workflows/called.yml"), TableEvents(), false)
			if !slices.Equal(evs, EventsAll(TableEvents())) {
				t.Fatalf("events = %v", eventNames(evs))
			}
		})
	}
}

func TestCallersEventsCycle(t *testing.T) {
	a := "on:\n  workflow_call:\njobs:\n  n:\n    uses: ./.github/workflows/b.yml\n"
	b := "on:\n  workflow_call:\njobs:\n  n:\n    uses: ./.github/workflows/a.yml\n"
	c := callersOf(t, true, [2]string{".github/workflows/a.yml", a}, [2]string{".github/workflows/b.yml", b})
	evs, _ := c.Events(inputName(".github/workflows/a.yml"), TableEvents(), false)
	if len(evs) != 0 {
		t.Fatalf("events = %v", eventNames(evs))
	}
}

func TestCallersNil(t *testing.T) {
	var c *Callers
	evs, cov := c.Events(inputName(".github/workflows/called.yml"), TableEvents(), false)
	if cov != analysis.CallerCoverageNone || evs != nil || c.Graph() != nil {
		t.Fatalf("events = %v, coverage = %v", evs, cov)
	}
}

// sinkRef is the first reference of the first sink of the input name,
// analyzed with c.
func sinkRef(t *testing.T, c *Callers, name string) ExprRef {
	t.Helper()
	f, _ := c.Graph().File(inputName(name))
	a := AnalyzeIn(c, f.Node(), f.Workflow, f.Action, nil)
	if len(a.Sinks) == 0 || len(a.Sinks[0].Refs) == 0 {
		t.Fatalf("no reference in %s", name)
	}
	return a.Sinks[0].Refs[0]
}

const issueTitleCaller = "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      t: ${{ github.event.issue.title }}\n"

func TestCallersInputControlled(t *testing.T) {
	c := callersOf(t, true, [2]string{".github/workflows/called.yml", calledEcho}, [2]string{".github/workflows/ci.yml", issueTitleCaller})
	r := sinkRef(t, c, ".github/workflows/called.yml")
	if r.Verdict != analysis.Controlled || !slices.Equal(eventNames(r.ControlledOn), []string{"issues"}) || len(r.With) != 1 || r.With[0].Node.String() != ".github/workflows/ci.yml" {
		t.Fatalf("ref = %+v", r)
	}
}

// TestCallersInputPageName: a caller's name of a wiki page keeps its
// PathCommands in the callee.
func TestCallersInputPageName(t *testing.T) {
	c := callersOf(t, true, [2]string{".github/workflows/called.yml", calledEcho}, [2]string{".github/workflows/ci.yml", "on: gollum\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      t: ${{ github.event.pages[0].page_name }}\n"})
	r := sinkRef(t, c, ".github/workflows/called.yml")
	if r.Verdict != analysis.Controlled || !slices.Equal(eventNames(r.PathCommands), []string{"gollum"}) || !slices.Equal(eventNames(r.LeadingDash), []string{"gollum"}) {
		t.Fatalf("ref = %+v", r)
	}
}

func TestCallersInputFixed(t *testing.T) {
	c := callersOf(t, true,
		[2]string{".github/workflows/called.yml", calledEcho},
		[2]string{".github/workflows/ci.yml", "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      t: fixed\n"})
	if r := sinkRef(t, c, ".github/workflows/called.yml"); r.Verdict != analysis.NotControlled {
		t.Fatalf("ref = %+v", r)
	}
}

func TestCallersInputNoCaller(t *testing.T) {
	c := callersOf(t, true, [2]string{".github/workflows/called.yml", calledEcho})
	if r := sinkRef(t, c, ".github/workflows/called.yml"); r.Verdict != analysis.Inconclusive || r.InconclusiveKind != analysis.InconclusiveRefInputCall {
		t.Fatalf("ref = %+v", r)
	}
}

func TestCallersInputPartialKeepsGap(t *testing.T) {
	c := callersOf(t, false,
		[2]string{".github/workflows/called.yml", calledEcho},
		[2]string{".github/workflows/ci.yml", "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      t: fixed\n"})
	if r := sinkRef(t, c, ".github/workflows/called.yml"); r.Verdict != analysis.Inconclusive || r.InconclusiveKind != analysis.InconclusiveRefInputCall {
		t.Fatalf("ref = %+v", r)
	}
}

func TestCallersInputPartialControlled(t *testing.T) {
	c := callersOf(t, false, [2]string{".github/workflows/called.yml", calledEcho}, [2]string{".github/workflows/ci.yml", issueTitleCaller})
	if r := sinkRef(t, c, ".github/workflows/called.yml"); r.Verdict != analysis.Controlled {
		t.Fatalf("ref = %+v", r)
	}
}

func TestCallersInputNested(t *testing.T) {
	mid := "on:\n  workflow_call:\n    inputs:\n      t: {type: string}\njobs:\n  n:\n    uses: ./.github/workflows/called.yml\n    with:\n      t: ${{ inputs.t }}\n"
	c := callersOf(t, true,
		[2]string{".github/workflows/called.yml", calledEcho},
		[2]string{".github/workflows/mid.yml", mid},
		[2]string{".github/workflows/ci.yml", "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/mid.yml\n    with:\n      t: ${{ github.event.issue.title }}\n"})
	r := sinkRef(t, c, ".github/workflows/called.yml")
	if r.Verdict != analysis.Controlled || len(r.With) != 2 || r.With[0].Node.String() != ".github/workflows/ci.yml" || r.With[1].Node.String() != ".github/workflows/mid.yml" {
		t.Fatalf("ref = %+v", r)
	}
}

func TestCallersInputDefault(t *testing.T) {
	called := "on:\n  workflow_call:\n    inputs:\n      t: {type: string, default: \"${{ github.event.issue.title }}\"}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.t }}\"\n"
	c := callersOf(t, true,
		[2]string{".github/workflows/called.yml", called},
		[2]string{".github/workflows/ci.yml", "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n"})
	r := sinkRef(t, c, ".github/workflows/called.yml")
	if r.Verdict != analysis.Controlled || len(r.With) != 1 || r.With[0].Node.String() != ".github/workflows/called.yml" {
		t.Fatalf("ref = %+v", r)
	}
}

func TestCallersInputCallerInconclusive(t *testing.T) {
	ci := "on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    outputs: {o: x}\n    steps: [{run: 'true'}]\n  c:\n    needs: a\n    uses: ./.github/workflows/called.yml\n    with:\n      t: ${{ needs.a.outputs.o }}\n"
	c := callersOf(t, true, [2]string{".github/workflows/called.yml", calledEcho}, [2]string{".github/workflows/ci.yml", ci})
	if r := sinkRef(t, c, ".github/workflows/called.yml"); r.Verdict != analysis.Inconclusive || r.InconclusiveKind != analysis.InconclusiveRefJob {
		t.Fatalf("ref = %+v", r)
	}
}

func TestCallersInputCycle(t *testing.T) {
	a := "on:\n  workflow_call:\n    inputs: {t: {type: string}}\njobs:\n  n:\n    uses: ./.github/workflows/b.yml\n    with: {t: \"${{ inputs.t }}\"}\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.t }}\"\n"
	b := "on:\n  workflow_call:\n    inputs: {t: {type: string}}\njobs:\n  n:\n    uses: ./.github/workflows/a.yml\n    with: {t: \"${{ inputs.t }}\"}\n"
	c := callersOf(t, true, [2]string{".github/workflows/a.yml", a}, [2]string{".github/workflows/b.yml", b})
	// GitHub refuses the loop: no run reaches the step, so
	// the reference stops, and is not controlled
	if r := sinkRef(t, c, ".github/workflows/a.yml"); r.Verdict == analysis.Controlled {
		t.Fatalf("ref = %+v", r)
	}
}

// TestCallersInputFoldedName: a key of with names the input whatever its
// case.
func TestCallersInputFoldedName(t *testing.T) {
	c := callersOf(t, true,
		[2]string{".github/workflows/called.yml", calledEcho},
		[2]string{".github/workflows/ci.yml", "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      T: ${{ github.event.issue.title }}\n"})
	if r := sinkRef(t, c, ".github/workflows/called.yml"); r.Verdict != analysis.Controlled {
		t.Fatalf("ref = %+v", r)
	}
}

// TestCallersInputTyped: a boolean or number input cannot hold what an
// attacker writes: the caller's run fails before the called one runs.
func TestCallersInputTyped(t *testing.T) {
	for _, typ := range []string{"boolean", "number"} {
		called := "on:\n  workflow_call:\n    inputs:\n      t: {type: " + typ + "}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.t }}\"\n"
		c := callersOf(t, true, [2]string{".github/workflows/called.yml", called}, [2]string{".github/workflows/ci.yml", issueTitleCaller})
		if r := sinkRef(t, c, ".github/workflows/called.yml"); r.Verdict != analysis.NotControlled {
			t.Fatalf("%s: ref = %+v", typ, r)
		}
	}
}

func TestCallersInputComposite(t *testing.T) {
	ci := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./x\n        with:\n          t: ${{ github.event.issue.title }}\n"
	c := callersOf(t, true, [2]string{"x/action.yml", "runs:\n  using: composite\n  steps:\n    - run: echo \"${{ inputs.t }}\"\n      shell: bash\n"}, [2]string{".github/workflows/ci.yml", ci})
	if r := sinkRef(t, c, "x/action.yml"); r.Verdict != analysis.Controlled || len(r.With) != 1 {
		t.Fatalf("ref = %+v", r)
	}
}

// TestCallersInputCompositeDynamicWith: a with that is one ${{ }} may
// give the input any part of the expression's value.
func TestCallersInputCompositeDynamicWith(t *testing.T) {
	ci := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./x\n        with: ${{ fromJSON(github.event.issue.body) }}\n"
	action := "inputs:\n  t:\n    default: ''\nruns:\n  using: composite\n  steps:\n    - run: echo \"${{ inputs.t }}\"\n      shell: bash\n"
	c := callersOf(t, true, [2]string{"x/action.yml", action}, [2]string{".github/workflows/ci.yml", ci})
	if r := sinkRef(t, c, "x/action.yml"); r.Verdict != analysis.Controlled || len(r.With) != 1 {
		t.Fatalf("ref = %+v", r)
	}
}

// TestCallersInputStepIf: the events of the called step's if narrow what
// the caller gives.
func TestCallersInputStepIf(t *testing.T) {
	called := "on:\n  workflow_call:\n    inputs:\n      t: {type: string}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.event_name == 'push'\n        run: echo \"${{ inputs.t }}\"\n"
	c := callersOf(t, true, [2]string{".github/workflows/called.yml", called}, [2]string{".github/workflows/ci.yml", issueTitleCaller})
	if r := sinkRef(t, c, ".github/workflows/called.yml"); r.Verdict == analysis.Controlled {
		t.Fatalf("ref = %+v", r)
	}
}

// TestCallersInputDispatch: a workflow of workflow_dispatch and
// workflow_call: Controlled from a caller, else the dispatch's.
func TestCallersInputDispatch(t *testing.T) {
	called := "on:\n  workflow_dispatch:\n    inputs: {t: {type: string}}\n  workflow_call:\n    inputs: {t: {type: string}}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.t }}\"\n"
	c := callersOf(t, true, [2]string{".github/workflows/called.yml", called}, [2]string{".github/workflows/ci.yml", issueTitleCaller})
	if r := sinkRef(t, c, ".github/workflows/called.yml"); r.Verdict != analysis.Controlled {
		t.Fatalf("caller: ref = %+v", r)
	}
	c = callersOf(t, true, [2]string{".github/workflows/called.yml", called})
	if r := sinkRef(t, c, ".github/workflows/called.yml"); r.InconclusiveKind != analysis.InconclusiveRefInputDispatch {
		t.Fatalf("none: ref = %+v", r)
	}
}

func TestCallersInputThroughEnv(t *testing.T) {
	called := "on:\n  workflow_call:\n    inputs:\n      t: {type: string}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env: {T: \"${{ inputs.t }}\"}\n    steps:\n      - run: echo \"${{ env.T }}\"\n"
	c := callersOf(t, true, [2]string{".github/workflows/called.yml", called}, [2]string{".github/workflows/ci.yml", issueTitleCaller})
	if r := sinkRef(t, c, ".github/workflows/called.yml"); r.Verdict != analysis.Controlled || len(r.With) != 1 || len(r.Env) != 1 {
		t.Fatalf("ref = %+v", r)
	}
}

// TestCallersConcurrent: a chain of called workflows asked at once from
// goroutines gives each the same answer as asked alone.
func TestCallersConcurrent(t *testing.T) {
	const n = 30
	files := [][2]string{{".github/workflows/w00.yml", "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/w01.yml\n    with:\n      t: ${{ github.event.issue.title }}\n"}}
	for i := 1; i < n; i++ {
		next := ""
		if i+1 < n {
			next = fmt.Sprintf("  c:\n    uses: ./.github/workflows/w%02d.yml\n    with:\n      t: ${{ inputs.t }}\n", i+1)
		}
		files = append(files, [2]string{fmt.Sprintf(".github/workflows/w%02d.yml", i), "on:\n  workflow_call:\n    inputs: {t: {type: string}}\njobs:\n" + next + "  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ inputs.t }}\"\n"})
	}
	for round := 0; round < 20; round++ {
		c := callersOf(t, true, files...)
		var wg sync.WaitGroup
		bad := make(chan string, n*8)
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				for i := n - 1; i >= 1; i-- {
					name := fmt.Sprintf(".github/workflows/w%02d.yml", (i+g)%(n-1)+1)
					f, _ := c.Graph().File(inputName(name))
					for _, s := range AnalyzeIn(c, f.Node(), f.Workflow, nil, nil).Sinks {
						if s.Refs[0].Verdict != analysis.Controlled {
							bad <- name
						}
					}
				}
			}(g)
		}
		wg.Wait()
		close(bad)
		for name := range bad {
			t.Fatalf("round %d: %s is not controlled", round, name)
		}
	}
}

// TestCallersInputNarrowKeepsInconclusive: what one caller gives is kept
// to the events of the step that reads it before the callers are merged,
// so an Inconclusive of another caller stays.
func TestCallersInputNarrowKeepsInconclusive(t *testing.T) {
	called := "on:\n  workflow_call:\n    inputs: {t: {type: string}}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.event_name == 'push'\n        run: echo \"${{ inputs.t }}\"\n"
	a := "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      t: ${{ github.event.issue.title }}\n"
	b := "on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    outputs: {y: z}\n    steps: [{run: 'true'}]\n  c:\n    needs: x\n    uses: ./.github/workflows/called.yml\n    with:\n      t: ${{ needs.x.outputs.y }}\n"
	c := callersOf(t, true, [2]string{".github/workflows/called.yml", called}, [2]string{".github/workflows/a.yml", a}, [2]string{".github/workflows/b.yml", b})
	if r := sinkRef(t, c, ".github/workflows/called.yml"); r.Verdict != analysis.Inconclusive || r.InconclusiveKind != analysis.InconclusiveRefJob {
		t.Fatalf("ref = %+v", r)
	}
}

// TestCallersInputOtherCallersNarrowed: a caller whose events do not reach
// the step is in neither With nor OtherCallers.
func TestCallersInputOtherCallersNarrowed(t *testing.T) {
	called := "on:\n  workflow_call:\n    inputs: {t: {type: string}}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - if: github.event_name == 'issues'\n        run: echo \"${{ inputs.t }}\"\n"
	a := "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      t: ${{ github.event.issue.title }}\n"
	b := "on: issue_comment\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      t: ${{ github.event.comment.body }}\n"
	c := callersOf(t, true, [2]string{".github/workflows/called.yml", called}, [2]string{".github/workflows/a.yml", a}, [2]string{".github/workflows/b.yml", b})
	r := sinkRef(t, c, ".github/workflows/called.yml")
	if r.Verdict != analysis.Controlled || len(r.With) != 1 || r.With[0].Node.String() != ".github/workflows/a.yml" || len(r.OtherCallers) != 0 {
		t.Fatalf("ref = %+v", r)
	}
}

// TestCallersWholeInputsTyped: toJSON(inputs) does not take a boolean
// input.
func TestCallersWholeInputsTyped(t *testing.T) {
	called := "on:\n  workflow_call:\n    inputs: {b: {type: boolean}}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo '${{ toJSON(inputs) }}'\n"
	ci := "on: issues\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      b: ${{ github.event.issue.title }}\n"
	c := callersOf(t, true, [2]string{".github/workflows/called.yml", called}, [2]string{".github/workflows/ci.yml", ci})
	if r := sinkRef(t, c, ".github/workflows/called.yml"); r.Verdict == analysis.Controlled {
		t.Fatalf("ref = %+v", r)
	}
}

// TestCallersDefaultReadsCallerJob: a composite action's default reads
// the matrix of the caller's job.
func TestCallersDefaultReadsCallerJob(t *testing.T) {
	action := "inputs:\n  t: {default: '${{ matrix.x }}'}\nruns:\n  using: composite\n  steps:\n    - run: echo \"${{ inputs.t }}\"\n      shell: bash\n"
	ci := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix: ${{ fromJSON(github.event.issue.body) }}\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./x\n"
	c := callersOf(t, true, [2]string{"x/action.yml", action}, [2]string{".github/workflows/ci.yml", ci})
	if r := sinkRef(t, c, "x/action.yml"); r.Verdict != analysis.Inconclusive || r.InconclusiveKind != analysis.InconclusiveRefMatrix {
		t.Fatalf("ref = %+v", r)
	}
}
