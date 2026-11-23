package shell

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// OutputReading reads what commands write to an output (a pipe, the value
// of a $( )) with readings of descriptors that nest: a reader of outputs
// walks the commands of an output (Begin), and reads the value of a $( ) in
// a word of a command with another walk inside the first. The readings of
// one OutputReading share the guard of a recursion (a function being read is
// not read again where it is called, also in a nested reading) and the limit
// of calls (maxCalls for a reading and the readings nested in it, and
// maxOutputCalls for all the readings of the OutputReading), as procWrites
// shares them with the reading of a >( ).
type OutputReading struct {
	s       string
	vis     *NameVisibility
	notRead *CallsNotRead
	// what every reading of the script reads the same: the names of its
	// literal commands, whether a variable may have the integer attribute,
	// its commands, and the answers of copiesName
	named  map[string]bool
	ints   bool
	list   []Command
	copies map[string]bool
	// the guard of a recursion, shared by the readings
	calling     map[string]bool
	callingDefs map[*FuncDef]bool
	// open are the readings begun and not ended, the innermost last, and
	// where the calls of each started
	open []openReading
	// total is how many calls the readings that ended followed, up to limit
	// (maxOutputCalls)
	total, limit int
	// cuts are the calls whose bodies a reading did not read (Count), and
	// recursions those of them that a reading around was reading
	cuts, recursions int
	// subs are, for BeginSubstitution, where each $( ) is, by where it
	// starts
	subs map[int]substitutionPaths
	// watch are the definitions called since each Watch, the innermost last
	watch []map[*FuncDef]bool
}

type openReading struct {
	r     *fdReading
	start int
}

// maxOutputCalls is how many calls of functions the readings of an
// OutputReading follow into their bodies in all: a function that a $( )
// of its body calls again is read at each outer reading.
const maxOutputCalls = 1 << 16

// NewOutputReading is an OutputReading of the script sc, whose text is
// script: v answers which definitions a call sees, and notRead gets the
// first call whose body a reading does not read past the limits.
func NewOutputReading(script string, sc *Script, v *NameVisibility, notRead *CallsNotRead) *OutputReading {
	o := &OutputReading{s: script, vis: v, notRead: notRead, list: sc.List, ints: intVariables(script, sc), copies: map[string]bool{}, calling: map[string]bool{}, callingDefs: map[*FuncDef]bool{}, limit: maxOutputCalls}
	r := newFdReading(script)
	r.findNames(sc.List)
	o.named = r.named
	return o
}

// Begin is the reading of descriptors for a walk of commands whose
// standard output goes to the output read; End ends it. With from, the
// reading of the command in a word of which the commands are (a $( )), the
// commands start with the descriptors from has before that command's
// redirects (bash expands the words before), their standard output then
// pointing at the output, and in the function bodies and the loops from is
// in: a return, and a break or continue in a loop, ends their paths. Without from, they start as a script does, their
// standard error also pointing at the output when err. A reading begun
// inside another counts its calls on from where that one has counted.
func (o *OutputReading) Begin(from *DescriptorReading, err bool) *DescriptorReading {
	r := newFdReading(o.s)
	r.vis, r.named, r.ints, r.list, r.copies = o.vis, o.named, o.ints, o.list, o.copies
	r.calling, r.callingDefs, r.notReadCalls = o.calling, o.callingDefs, o.notRead
	if n := len(o.open); n > 0 {
		r.calls = o.open[n-1].r.calls
	} else {
		// what is left of the limit of the run, read by the limit of a
		// reading (walker.call)
		r.calls = max(0, maxCalls-(o.limit-o.total))
	}
	if from != nil && from.reading != nil {
		f := from.reading
		r.fds = maps.Clone(f.fds)
		r.inFunc = f.inFunc
		r.blind = f.blind // a $( ) of a command read blind is read blind
		r.outFrom = f.loopAround(f.env)
	}
	if r.fds == nil {
		r.fds = fdMap{}
	}
	out := dests{{pipe: true, output: len(o.open) + 1}}
	r.fds[1] = out
	if from == nil && err {
		r.fds[2] = out
	}
	r.depth = len(o.open) + 1
	o.open = append(o.open, openReading{r, r.calls})
	return &DescriptorReading{reading: r}
}

// End ends the reading d, the innermost begun: the reading around it goes
// on from the calls d counted.
func (o *OutputReading) End(d *DescriptorReading) {
	n := len(o.open) - 1
	if n < 0 || o.open[n].r != d.reading {
		panic("shell: OutputReading.End of a reading that is not the innermost")
	}
	top := o.open[n]
	o.open = o.open[:n]
	if n > 0 {
		o.open[n-1].r.calls = top.r.calls
		return
	}
	o.total += top.r.calls - top.start
}

// Cuts are how many calls the readings did not read the bodies of
// (Count), and how many of those a reading around was reading.
func (o *OutputReading) Cuts() (all, recursions int) { return o.cuts, o.recursions }

// Output is whether the standard output of the simple command x, which the
// walk d reads for gives (Visitor.Command), may go to the output read, or to
// a pipe of a pipeline of the commands read: where it points after the
// redirects of x, |& among them. It is false where every path to x ended
// (return, exit, break, continue) and where a redirect of x fails on every
// path, which bash does not run.
func (d *DescriptorReading) Output(x *Simple) bool {
	own, _ := d.Outputs(x)
	return own
}

// Outputs is where the standard output of the simple command x, which the
// walk d reads for gives, may go: to the output d reads, or to a pipe of a
// pipeline of the commands read (own, Output), and to the outputs of the
// readings around d (their depths, OutputReading.Begin with from): a $( )
// whose commands write to the output of the reading of its command, as
// after x=$(exec 2>&1; y=$(echo v >&2)), writes there, not to its value.
func (d *DescriptorReading) Outputs(x *Simple) (own bool, around []OutputPlace) {
	r := d.reading
	switch {
	case r != nil && r.blind:
		return true, nil
	case r == nil || r.ended:
		return false, nil
	case x == r.writer:
		return true, nil // its output is the write, wherever it points
	}
	saved := r.cmd
	r.cmd = x
	t := r.table(x.Redirects)
	r.cmd = saved
	if _, every := mayFail(t); every {
		return false, nil
	}
	for _, e := range r.at(t, 1) {
		switch {
		case e.pipe && e.output != 0 && e.output != d.Depth():
			if p := (OutputPlace{e.output, e.element}); !slices.Contains(around, p) {
				around = append(around, p) // the output of a reading around, or a pipe of a pipeline of it
			}
		case e.pipe:
			own = true
		}
	}
	return own, around
}

// OutputPlace is an output of a reading of OutputReading: the output it
// reads (Element nil), or the pipe a command of a pipeline of its commands
// writes to the next, whose shell is Element. Depth is the reading's.
type OutputPlace struct {
	Depth   int
	Element *ExecutionEnvironment
}

// Depth is the depth of the reading d among the readings of its
// OutputReading, from 1, which marks its output (Outputs).
func (d *DescriptorReading) Depth() int { return d.reading.depth }

// BeginPipeline is Begin for the commands of a pipeline whose output a
// write gives as one command not known (shell.Writes: a command that reads
// the pipe and writes what is not known): the last command of p writes to
// the write, wherever its own redirects point (cat >>"$GITHUB_ENV").
func (o *OutputReading) BeginPipeline(p *Pipeline) *DescriptorReading {
	d := o.Begin(nil, false)
	if x, ok := p.Commands[len(p.Commands)-1].(*Simple); ok {
		d.reading.writer = x
		return d
	}
	// a last command that is not simple ({ cat; } >>file): the pipeline is
	// read as BeginBlind reads
	d.reading.blind = true
	delete(d.reading.fds, 1)
	return d
}

// BeginBlind is Begin for the command of a piece not known of what a
// simple command writes (shell.Writes: the command, or a call and the
// bodies of its functions): every simple command of it is read as writing
// to the output, wherever its descriptors point, and the bodies Walk gives
// at the calls are not read (Blind), as the reading of such a piece was
// before the readings of descriptors: the piece lists the bodies of a call
// it reads.
func (o *OutputReading) BeginBlind() *DescriptorReading {
	d := o.Begin(nil, false)
	d.reading.blind = true
	// the standard output of the command is not the output read: a redirect
	// of it that copies the standard output from before (4>&1 >>file)
	// points at what the shell inherits, as a $( ) that writes there
	delete(d.reading.fds, 1)
	return d
}

// Count counts the simple command x, which the innermost reading gives and
// has read the words of, as a cut when it calls a function whose body that
// reading will not read: one a reading around is reading (a recursion), or
// past the limit of calls.
func (o *OutputReading) Count(x *Simple) {
	n := len(o.open)
	if n == 0 {
		return
	}
	r := o.open[n-1].r
	_, defs := r.defsAt(x)
	if len(defs) == 0 || r.isExec(x) {
		return
	}
	o.Called(defs)
	for _, d := range defs {
		if o.callingDefs[d] {
			o.cuts++
			o.recursions++
			return
		}
	}
	if r.calls >= maxCalls {
		o.cuts++
	}
}

// substitutionPaths is what a reading of a $( ) started apart from the
// reading of its command keeps of where the $( ) is: in the body of a
// function, where a return ends its script, and in a loop of that function,
// where a break or continue does.
type substitutionPaths struct {
	inFunc, inLoop bool
}

// BeginSubstitution is Begin for the commands of the $( ) or <( ) that
// starts at start, read apart from a reading of its command (the value of
// an assignment, read where the variable is): they start as a script does,
// in the function bodies and the loops the $( ) is in on every path that
// reaches it (one walk of the script, with the bodies of functions given
// where each call runs them).
func (o *OutputReading) BeginSubstitution(start int) *DescriptorReading {
	sp := o.substitutionAt(start)
	d := o.Begin(nil, false)
	if sp.inFunc {
		d.reading.inFunc = 1
	}
	d.reading.outFrom = sp.inLoop
	return d
}

// substitutionAt is where the $( ) that starts at start is (BeginSubstitution).
func (o *OutputReading) substitutionAt(start int) substitutionPaths {
	if o.subs == nil {
		o.subs = map[int]substitutionPaths{}
		r := newFdReading(o.s)
		r.vis, r.named, r.ints, r.list, r.copies = o.vis, o.named, o.ints, o.list, o.copies
		seen := map[int]bool{}
		Walk(o.s, o.list, Enclosing{}, Visitor{Descriptors: &DescriptorReading{reading: r}, Part: func(p *Part, at Enclosing) {
			if p.Sub == nil || p.Kind != PartSubst && p.Kind != PartProcIn && p.Kind != PartProcOut {
				return
			}
			here := substitutionPaths{inFunc: r.inFunc > 0, inLoop: r.loopAround(at.Env)}
			if seen[p.Span.Start] {
				was := o.subs[p.Span.Start]
				here = substitutionPaths{inFunc: was.inFunc && here.inFunc, inLoop: was.inLoop && here.inLoop}
			}
			seen[p.Span.Start] = true
			o.subs[p.Span.Start] = here
		}})
	}
	return o.subs[start]
}

// Calls is how many calls the readings that ended followed into their
// bodies in all.
func (o *OutputReading) Calls() int { return o.total }

// Start is what a reading begun with from (Begin), or with no from at the
// $( ) that starts at start (BeginSubstitution), starts from, as a key of
// the answers of readings: for each descriptor whether it points at an
// output, is not open, or points elsewhere, and the function bodies and
// loops the commands are in.
func (o *OutputReading) Start(from *DescriptorReading, start int) string {
	if from == nil || from.reading == nil {
		sp := o.substitutionAt(start)
		return fmt.Sprintf("sub %v %v", sp.inFunc, sp.inLoop)
	}
	r := from.reading
	depth := len(o.open) + 1 // of the reading begun with from
	var b strings.Builder
	for _, fd := range slices.Sorted(maps.Keys(r.fds)) {
		ds := r.fds[fd]
		switch {
		case toPipe(ds):
			fmt.Fprintf(&b, "%d:o", fd)
			for _, d := range ds {
				switch {
				case d.pipe && d.element != nil:
					fmt.Fprintf(&b, ",p%d", depth-d.output) // a pipe of a pipeline of the reading that many around
				case d.pipe:
					fmt.Fprintf(&b, ",%d", depth-d.output) // the output of the reading that many around
				}
			}
			b.WriteString(" ")
		case !slices.ContainsFunc(ds, func(d dest) bool { return !d.closed && !d.failed }):
			fmt.Fprintf(&b, "%d:c ", fd)
		default:
			fmt.Fprintf(&b, "%d:x ", fd)
		}
	}
	fmt.Fprintf(&b, "%v %v", r.inFunc > 0, r.loopAround(r.env))
	return b.String()
}

// Reading is those of the definitions defs that the readings are reading
// where they are called, as a key: by where each starts. A read that a
// recursion cut depends on them alone (Watch).
func (o *OutputReading) Reading(defs []*FuncDef) string {
	var at []int
	for _, d := range defs {
		if o.callingDefs[d] {
			at = append(at, d.Span().Start)
		}
	}
	slices.Sort(at)
	return fmt.Sprint(at)
}

// Watch starts to keep the definitions the calls the readings count call
// (Count, Called), until Unwatch.
func (o *OutputReading) Watch() { o.watch = append(o.watch, map[*FuncDef]bool{}) }

// Unwatch ends the innermost Watch: the definitions called since, which
// the Watch around also keeps.
func (o *OutputReading) Unwatch() []*FuncDef {
	n := len(o.watch) - 1
	top := o.watch[n]
	o.watch = o.watch[:n]
	var out []*FuncDef
	for d := range top {
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b *FuncDef) int { return a.Span().Start - b.Span().Start })
	o.Called(out)
	return out
}

// Called keeps the definitions defs as called in the innermost Watch: a
// call, or an answer read again from a memo, which called them.
func (o *OutputReading) Called(defs []*FuncDef) {
	if n := len(o.watch); n > 0 {
		for _, d := range defs {
			o.watch[n-1][d] = true
		}
	}
}

// Replay counts again the cuts all, of which recursions by a recursion, that
// a reading met before: an answer of it read again from a memo carries the
// cuts of its reading to the readings around.
func (o *OutputReading) Replay(all, recursions int) {
	o.cuts += all
	o.recursions += recursions
}

// Depth is how many readings are open.
func (o *OutputReading) Depth() int { return len(o.open) }

// Blind is whether d reads as BeginBlind reads: the reader counts every
// simple command, and does not read the bodies Walk gives at calls.
func (d *DescriptorReading) Blind() bool { return d.reading != nil && d.reading.blind }
