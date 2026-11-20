package shell

import (
	"maps"
	"slices"
	"sort"
	"strings"
)

// OutKind is what a piece of what a command writes is.
type OutKind uint8

const (
	OutUnset   OutKind = iota
	OutLit             // bytes as they are written, line breaks included
	OutHole            // a range the caller fills before the script runs (a ${{ }}), written as it is
	OutParam           // the value of a parameter: $NAME, ${NAME}, ${NAME<op>...}; Part.Kind tells
	OutSubst           // what $( ) writes: Part.Sub is its script
	OutOpaque          // a value not read: ` `, $(( )), <( ), >( )
	OutUnknown         // what a command writes that is not known: Cmd
)

var outKindNames = [...]string{"OutUnset", "OutLit", "OutHole", "OutParam", "OutSubst", "OutOpaque", "OutUnknown"}

func (k OutKind) String() string { return outKindNames[k] }

// Out is a piece of what a command writes. Span is where it is in the
// script: for a literal, the bytes it comes from (Exact when Text is them
// as they are); a space or a line break that echo or printf add has an
// empty span or the span of the format. By is the simple command that
// writes it, and Word its word (-1 for a space or a line break, and for a
// heredoc's body); Quote is the quotes it is in, QuoteNone in a heredoc's
// body (InBody).
type Out struct {
	Kind   OutKind
	Span   Span
	Text   string
	Exact  bool
	Part   *Part
	Hole   int
	By     *Simple
	Word   int
	Quote  Quote
	InBody bool
	Cmd    Command
}

// Write is what goes to a file the caller names: what the command At
// writes to its standard output (At has the redirect), or what the command
// before a tee writes (At is the tee). Top is the item of the script's list
// At is in, nil inside a substitution. Exec is exec with the redirect: what
// follows in the script goes to the file, and Out is empty. Log is, when
// WriteOptions.Log asks for it, what At writes to the log of the step: the
// standard output or error the script inherits; Target is then empty.
type Write struct {
	Target Word
	At     Command
	Top    Command
	Exec   bool
	InFunc bool
	Log    bool
	Out    []Out
	fn     string // Log in the body of a function: its name
	atDef  bool   // in the body of a function read where it is defined: its log writes count where a call logs
}

// WriteOptions says what Writes looks for. Target is whether a word names
// a file. Holes are ranges of the script, in order and apart, that the
// caller fills before the script runs; a hole is written as it is.
// EchoEscapes is whether echo reads backslash escapes, as dash's does (sh).
// Log is whether Writes also gives what the simple commands write to the
// log: the standard output and error the script inherits (the runner reads
// both as the log), directly or through /dev/stdout, /dev/stderr,
// /dev/fd/1, /dev/fd/2 or /dev/tty; not what a substitution or the
// command before a pipe takes.
type WriteOptions struct {
	Target      func(Word) bool
	Holes       []Span
	EchoEscapes bool
	Log         bool
	// Visibility is the NameVisibility of the tree, read once for the
	// analyses of an input (Memo.Visibility); nil reads it
	Visibility *NameVisibility
	// NotRead, when not nil, gets the first call whose body Writes did not
	// read past maxCalls.
	NotRead *CallsNotRead
}

// Writes is what the commands of sc, the tree of script, write to the
// files o.Target names, in the order of the script, substitutions too. What
// a command writes is known for echo (with -n or -E), printf of a literal
// format of %s, and cat of a heredoc or a here-string; another command's is
// OutUnknown.
func Writes(script string, sc *Script, o WriteOptions) []Write {
	w := &writer{fdReading: newFdReading(script), o: o, pipes: map[*ExecutionEnvironment]pipeState{}}
	w.target = func(t Word, _ fdLook) bool { return w.o.Target(t) || w.procWrites(t) }
	w.notReadCalls = o.NotRead
	w.vis = o.Visibility
	if w.vis == nil {
		w.vis = NewNameVisibility(script, sc)
	}
	w.ints = intVariables(script, sc)
	w.findNames(sc.List)
	w.findChanges(sc.List)
	w.walk(sc.List, nil, true)
	if o.Log {
		// a function's body writes to the log only where a call of it does
		w.out = slices.DeleteFunc(w.out, func(x Write) bool { return x.Log && x.atDef && x.fn != "" && !w.loggedFuncs[x.fn] })
	}
	return w.out
}

type writer struct {
	*fdReading
	o        WriteOptions
	out      []Write
	pipe     []Command             // the commands of a pipeline up to the one being read, which give it its input
	pipeline *Pipeline             // the pipeline of pipe
	pipeEnv  *ExecutionEnvironment // the shell of pipe
	pipes    map[*ExecutionEnvironment]pipeState
	atDef    int    // how deep in bodies read where they are defined (atDefinition) the command being read is
	fn       string // the function whose body the command being read is in
	// readers are the answers of PipeReaders, by command: each reads its
	// loops ahead
	readers map[Command]pipeRead
	// loggedFuncs are the functions some call of which writes to the log
	loggedFuncs map[string]bool
	// gathers are the places open in the walk that take what the simple
	// commands pointing their standard output at them write (gather), the
	// innermost last; pending, for a call in one, what the call adds where
	// its bodies are not read; elements, what each command of a pipeline
	// but the last writes to its pipe
	gathers  []*gather
	pending  map[*Simple][]pendingCall
	elements map[*Pipeline][][]Out
	// elementCalls are the gathers of the pipes of calls that are commands
	// of pipelines, which end after the bodies
	elementCalls map[*Simple]elementCall
	// muted are, for a call given arguments or input, the gathers that take
	// it as a whole while its bodies run
	muted map[*Simple][]*gather
}

// gather is a place whose writes take what the simple commands that point
// their standard output at it write, where each runs (the paths, exec,
// the redirects of the commands around, and the bodies of functions where
// each call runs them, which the reading of descriptors reads): a compound
// command or a call of a function whose redirect points the standard output
// at a file the caller names, or the pipe of a command of a pipeline.
type gather struct {
	to   dests // where a command that writes to it points its standard output
	out  []Out
	mute int // inside a case, which it takes as a whole
	// a call: the writes it fills where its bodies are read, and what it
	// takes where they are not
	call   *Simple
	writes []int
	unread []Out
}

// pendingCall is what a call in the gather g adds to g where its bodies
// are not read: a command not known.
type pendingCall struct {
	g   *gather
	out []Out
}

// takes is whether a command whose standard output points at one of ds
// writes to g.
func (g *gather) takes(ds dests) bool {
	return g.mute == 0 && slices.ContainsFunc(ds, func(d dest) bool { return slices.ContainsFunc(g.to, d.same) })
}

// reads is whether the command y of a pipeline reads the pipe itself.
func (w *writer) reads(y Command) bool {
	readers, _ := w.pipeReaders(y)
	return slices.ContainsFunc(readers, func(r *Simple) bool { return Command(r) == y })
}

// write adds a write of what At writes; a command not known that reads a
// pipe writes what may be its input, so what it writes is what the whole
// pipeline up to it writes.
func (w *writer) write(x Write) {
	x.InFunc = w.inFunc > 0
	x.atDef = w.atDef > 0
	if x.Log {
		x.fn = w.fn
	}
	x.Out = w.piping(x.At, x.Out)
	w.out = append(w.out, x)
}

// piping is out, what at writes, or, where at reads the pipe of the
// pipeline it is in and writes what is not known, what the whole pipeline
// up to it writes.
func (w *writer) piping(at Command, out []Out) []Out {
	if w.pipe == nil || !slices.ContainsFunc(out, func(o Out) bool { return o.Kind == OutUnknown }) {
		return out
	}
	p, i := w.pipeline, len(w.pipe)-1
	readers, unread := w.pipeReaders(p.Commands[i])
	reads := (len(readers) > 0 || unread) && (at == p.Commands[i] || unread || slices.ContainsFunc(readers, func(r *Simple) bool { return Command(r) == at }))
	if from := PipeSources(w.s, p, i); len(from) > 0 && reads {
		return w.piped(p, from[len(from)-1].Element, i+1)
	}
	return out
}

// piped is what the commands from to to (not included) of the pipeline p
// write, as one command not known: a pipeline of them, with their |&.
func (w *writer) piped(p *Pipeline, from, to int) []Out {
	cs := p.Commands[from:to]
	q := &Pipeline{span: Span{cs[0].Span().Start, cs[len(cs)-1].Span().End}, Commands: cs}
	if from < len(p.Stderr) {
		q.Stderr = p.Stderr[from:min(to, len(p.Stderr))]
	}
	return []Out{{Kind: OutUnknown, Span: q.span, Word: -1, Cmd: q}}
}

// logged adds, when the options ask for it, what the simple command x
// writes to the log. A function's call is not one: its body's commands
// are read where it is called.
func (w *writer) logged(x *Simple, top Command) {
	if !w.o.Log || len(x.Words) == 0 || !w.logs(x.Redirects) {
		return
	}
	if name, defs := w.defsAt(x); len(defs) > 0 {
		if w.loggedFuncs == nil {
			w.loggedFuncs = map[string]bool{}
		}
		w.loggedFuncs[name] = true
		return
	}
	if out := w.simple(x); len(out) > 0 {
		w.write(Write{At: x, Top: top, Log: true, Out: out})
	}
}

// files are the files the caller names that a descriptor of t may point
// at.
func files(t fdLook) dests {
	var out dests
	for _, fd := range t.keys() {
		ds, _ := t.get(fd)
		for _, d := range ds {
			if d.file && !d.call {
				out = out.with(d)
			}
		}
	}
	return out
}

// hasFd is whether the table t holds the descriptor fd.
func hasFd(t fdLook, fd int) bool {
	_, ok := t.get(fd)
	return ok
}

// procWrites is whether the word is >( ) whose commands write to a file
// the caller names: a tee of it, or a write of their own.
func (w *writer) procWrites(x Word) bool {
	for _, p := range x.Parts {
		if p.Kind != PartProcOut || p.Sub == nil {
			continue
		}
		so := w.o
		so.Log = false // only whether its commands write to a file the caller names
		r := newFdReading(w.s)
		r.fds, r.inFunc, r.vis, r.ints, r.varFds, r.fd, r.named, r.changing, r.ahead, r.calling, r.callingDefs, r.calls = maps.Clone(w.fds), w.inFunc, w.vis, w.ints, w.varFds, w.fd, w.named, w.changing, w.ahead, w.calling, w.callingDefs, w.calls // the same guard of calls; a subshell's descriptors
		r.list, r.copies = w.list, w.copies                                                                                                                                                                                                           // copies of a name anywhere in the script
		sub := &writer{fdReading: r, o: so, pipes: map[*ExecutionEnvironment]pipeState{}}
		sub.target = func(t Word, _ fdLook) bool { return sub.o.Target(t) || sub.procWrites(t) }
		if slices.ContainsFunc(p.Sub.List, func(c Command) bool { return len(sub.tee(c)) > 0 }) {
			return true
		}
		sub.walk(p.Sub.List, nil, false)
		if len(sub.out) > 0 {
			return true
		}
	}
	return false
}

// tee is the files of a tee command c that the caller names.
func (w *writer) tee(c Command) []Word {
	x, ok := c.(*Simple)
	if !ok || len(x.Words) < 2 {
		return nil
	}
	if n, ok := w.literal(x.Words[0]); !ok || n != "tee" {
		return nil
	}
	var out []Word
	for _, a := range x.Words[1:] {
		if s, ok := w.literal(a); ok && strings.HasPrefix(s, "-") {
			continue
		}
		if w.o.Target(a) {
			out = append(out, a)
		}
	}
	return out
}

func (w *writer) simple(x *Simple) []Out {
	if len(x.Words) == 0 {
		return nil
	}
	name, ok := w.literal(x.Words[0])
	_, defs := w.defsAt(x)
	if len(defs) > 0 && w.calls >= maxCalls {
		w.notRead(x)
	}
	var out []Out
	switch {
	case !ok:
	case name == "echo":
		out, ok = w.echo(x)
	case name == "printf":
		out, ok = w.printf(x)
	case name == "cat" && len(x.Words) == 1:
		out, ok = w.cat(x)
	case name == "exec" && len(x.Words) == 1:
		return nil // exec of redirects alone writes nothing itself
	case len(defs) > 0:
		// a call given arguments or the input of a pipe, or that sees more
		// than one definition, and a call whose bodies the walk does not read
		// (a recursion, past maxCalls): not known, with the bodies'
		// parameters as what it may write; for the other calls, what the
		// bodies write is gathered (gather)
		body := []Command{x}
		for _, f := range defs {
			body = append(body, f.Body)
		}
		return []Out{{Kind: OutUnknown, Span: x.Span(), By: x, Word: -1, Cmd: &Compound{span: x.Span(), Kind: CompoundBrace, Body: body}}}
	default:
		ok = false
	}
	if !ok {
		return []Out{{Kind: OutUnknown, Span: x.Span(), By: x, Word: -1, Cmd: x}}
	}
	return out
}

func (w *writer) echo(x *Simple) ([]Out, bool) {
	args, nl := x.Words[1:], true
	for len(args) > 0 {
		a, ok := w.literal(args[0])
		if !ok || len(a) < 2 || a[0] != '-' || strings.Trim(a[1:], "neE") != "" {
			break
		}
		if strings.ContainsRune(a, 'e') {
			return nil, false
		}
		if strings.ContainsRune(a, 'n') {
			nl = false
		}
		args = args[1:]
	}
	first := len(x.Words) - len(args)
	var out []Out
	for i, a := range args {
		if i > 0 {
			out = append(out, Out{Kind: OutLit, Span: Span{a.Span.Start, a.Span.Start}, Text: " ", By: x, Word: -1})
		}
		o, ok := w.word(site{by: x, word: first + i}, a.Parts)
		if !ok {
			return nil, false
		}
		out = append(out, o...)
	}
	if w.o.EchoEscapes {
		for _, o := range out {
			if o.Kind != OutLit || strings.Contains(o.Text, `\`) {
				return nil, false // dash's echo reads \n in the value, or in the literal
			}
		}
	}
	if nl {
		end := x.Words[len(x.Words)-1].Span.End
		out = append(out, Out{Kind: OutLit, Span: Span{end, end}, Text: "\n", By: x, Word: -1})
	}
	return out, true
}

func (w *writer) printf(x *Simple) ([]Out, bool) {
	if len(x.Words) < 2 {
		return nil, false
	}
	f, ok := w.literal(x.Words[1])
	if !ok || strings.HasPrefix(f, "-") {
		return nil, false
	}
	type piece struct {
		text string
		spec bool
	}
	var ps []piece
	var b strings.Builder
	flush := func() {
		ps = append(ps, piece{text: b.String()})
		b.Reset()
	}
	n := 0
	for i := 0; i < len(f); i++ {
		c := f[i]
		if c != '%' && c != '\\' {
			b.WriteByte(c)
			continue
		}
		if i+1 == len(f) {
			return nil, false
		}
		i++
		switch d := f[i]; {
		case c == '%' && d == '%':
			b.WriteByte('%')
		case c == '%' && d == 's':
			flush()
			ps = append(ps, piece{spec: true})
			n++
		case c == '\\' && d == 'n':
			b.WriteByte('\n')
		case c == '\\' && d == 't':
			b.WriteByte('\t')
		case c == '\\' && (d == '\\' || d == '"'):
			b.WriteByte(d)
		default:
			return nil, false
		}
	}
	flush()
	args := x.Words[2:]
	if n > 0 {
		for _, a := range args {
			for _, p := range a.Parts {
				if p.Quote == QuoteNone && (p.Kind != PartLiteral || w.hole(p.Span) >= 0) {
					return nil, false // bash splits it into more arguments, and the format repeats
				}
			}
		}
	}
	reps := 1
	if n > 0 && len(args) > n {
		if len(args)%n != 0 {
			return nil, false
		}
		reps = len(args) / n
	}
	fs := x.Words[1].Span
	var out []Out
	k := 0
	for r := 0; r < reps; r++ {
		for _, p := range ps {
			if !p.spec {
				if p.text != "" || n == 0 {
					out = append(out, Out{Kind: OutLit, Span: fs, Text: p.text, By: x, Word: 1})
				}
				continue
			}
			if k < len(args) {
				o, ok := w.word(site{by: x, word: 2 + k}, args[k].Parts)
				if !ok {
					return nil, false
				}
				out = append(out, o...)
			}
			k++
		}
	}
	return out, true
}

func (w *writer) cat(x *Simple) ([]Out, bool) {
	var in *Redirect
	for i := range x.Redirects {
		r := &x.Redirects[i]
		switch r.Op {
		case RedirHeredoc, RedirHeredocStrip, RedirHereString:
			in = r
		case RedirIn, RedirReadWrite, RedirDupIn:
			if r.Fd == -1 || r.Fd == 0 {
				return nil, false // a file: what is in it is not known
			}
		}
	}
	switch {
	case in == nil:
		return nil, false // what comes through a pipe
	case in.Op == RedirHereString:
		out, ok := w.word(site{by: x, word: -1}, in.Target.Parts)
		end := in.Target.Span.End
		return append(out, Out{Kind: OutLit, Span: Span{end, end}, Text: "\n", By: x, Word: -1}), ok
	}
	d := in.Heredoc
	body := w.s[d.Body.Start:d.Body.End]
	if in.Op == RedirHeredocStrip && (strings.HasPrefix(body, "\t") || strings.Contains(body, "\n\t")) {
		return nil, false // <<- takes the tabs away
	}
	if d.Quoted {
		return w.lit(d.Body, QuoteNone, site{by: x, word: -1, inBody: true}, asWritten)
	}
	return w.word(site{by: x, word: -1, inBody: true}, d.Parts)
}

// site is where a piece of what a command writes is: the simple command
// by, the number of its word (-1 for none), and whether it is in a
// heredoc's body.
type site struct {
	by     *Simple
	word   int
	inBody bool
}

// word is what the parts ps of a word (or of a heredoc's body) at s write.
func (w *writer) word(s site, ps []Part) ([]Out, bool) {
	var out []Out
	for pi := range ps {
		p := &ps[pi]
		if p.Kind == PartLiteral {
			o, ok := w.lit(p.Span, p.Quote, s, unescaped)
			if !ok {
				return nil, false
			}
			out = append(out, o...)
			continue
		}
		o := Out{Span: p.Span, Part: p, By: s.by, Word: s.word, Quote: p.Quote, InBody: s.inBody}
		switch h := w.hole(p.Span); {
		case h >= 0:
			o.Kind, o.Hole = OutHole, h
		case p.Kind == PartParam || p.Kind == PartParamOp:
			o.Kind = OutParam
		case p.Kind == PartSubst:
			o.Kind = OutSubst
		default:
			o.Kind = OutOpaque
		}
		out = append(out, o)
	}
	return out, true
}

// litRead is how the shell writes the bytes of a literal.
type litRead uint8

const (
	unescaped litRead = iota // its quotes and escapes taken off
	asWritten                // as they are: a quoted heredoc's body
)

// lit is the literal bytes sp of the script at s, inside the quotes q,
// split at the holes.
func (w *writer) lit(sp Span, q Quote, s site, read litRead) ([]Out, bool) {
	var out []Out
	at := sp.Start
	emit := func(end int) bool {
		if at >= end {
			return true
		}
		b := w.s[at:end]
		t, ok := b, true
		if read == unescaped {
			t, ok = unescape(b, q, s.inBody)
		}
		if ok {
			out = append(out, Out{Kind: OutLit, Span: Span{at, end}, Text: t, Exact: t == b, By: s.by, Word: s.word, Quote: q, InBody: s.inBody})
		}
		return ok
	}
	for h := w.firstHole(sp.Start); h < len(w.o.Holes) && w.o.Holes[h].Start < sp.End; h++ {
		hs := w.o.Holes[h]
		if !emit(max(hs.Start, at)) {
			return nil, false
		}
		out = append(out, Out{Kind: OutHole, Span: hs, Hole: h, By: s.by, Word: s.word, Quote: q, InBody: s.inBody})
		at = min(hs.End, sp.End)
	}
	if !emit(sp.End) {
		return nil, false
	}
	return out, true
}

// firstHole is the first hole that ends after at.
func (w *writer) firstHole(at int) int {
	return sort.Search(len(w.o.Holes), func(i int) bool { return w.o.Holes[i].End > at })
}

// hole is the hole that overlaps sp, or -1.
func (w *writer) hole(sp Span) int {
	if h := w.firstHole(sp.Start); h < len(w.o.Holes) && w.o.Holes[h].Start < sp.End {
		return h
	}
	return -1
}

// literal is the text of a word of literals only, with no hole in it.
func (w *writer) literal(x Word) (string, bool) {
	if w.hole(x.Span) >= 0 {
		return "", false
	}
	return literalOf(w.s, x)
}

// Literal is the text of the word w of script when it is of literals
// only, as the shell makes it: quotes and escapes taken away.
func Literal(script string, w Word) (string, bool) { return literalOf(script, w) }

// literalOf is the text of a word of literals only, as the shell makes it.
func literalOf(s string, x Word) (string, bool) {
	var b strings.Builder
	for _, p := range x.Parts {
		if p.Kind != PartLiteral {
			return "", false
		}
		t, ok := unescape(s[p.Span.Start:p.Span.End], p.Quote, false)
		if !ok {
			return "", false
		}
		b.WriteString(t)
	}
	return b.String(), true
}

// unescape is what the shell makes of the bytes of a literal inside the
// quotes q (body: in the body of a heredoc whose delimiter is not quoted):
// the backslashes that escape taken away. It is false for $'...' with a
// backslash, whose escapes it does not read.
func unescape(text string, q Quote, body bool) (string, bool) {
	if !strings.Contains(text, `\`) {
		return text, true
	}
	var escapes string // after \, what loses the \; every byte outside quotes
	switch {
	case q == QuoteSingle:
		return text, true
	case q == QuoteANSI:
		return "", false
	case body:
		escapes = "$`\\\n"
	case q == QuoteDouble:
		escapes = "$`\"\\\n"
	}
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c == '\\' && i+1 < len(text) && (escapes == "" || strings.IndexByte(escapes, text[i+1]) >= 0) {
			i++
			if text[i] != '\n' {
				b.WriteByte(text[i])
			}
			continue
		}
		b.WriteByte(c)
	}
	return b.String(), true
}

// trDecode is a set of tr as tr reads it: its backslash escapes made the
// bytes they stand for (\\, \n, \t, \r, \NNN in octal); a class ([:space:])
// is kept as it is.
func trDecode(set string) string {
	var b strings.Builder
	for i := 0; i < len(set); i++ {
		c := set[i]
		if c != '\\' || i+1 == len(set) {
			b.WriteByte(c)
			continue
		}
		i++
		switch d := set[i]; {
		case d == 'n':
			b.WriteByte('\n')
		case d == 't':
			b.WriteByte('\t')
		case d == 'r':
			b.WriteByte('\r')
		case d >= '0' && d <= '7':
			v, j := 0, i
			for ; j < len(set) && j < i+3 && set[j] >= '0' && set[j] <= '7'; j++ {
				v = v*8 + int(set[j]-'0')
			}
			b.WriteByte(byte(v))
			i = j - 1
		default:
			b.WriteByte(d)
		}
	}
	return b.String()
}

// LineFree is whether what the part p of script writes has no line break,
// whatever its variables hold: a substitution whose pipeline's first
// command is echo (or echo -n) of one word or printf of %s (or %s and \n)
// and one word, and whose last is a tr that deletes the line break (-d,
// --delete) or turns it into another byte; or a ${ } that removes the
// longest end of the value from the first white-space character or line
// break (${T%%[[:space:]]*}, ${T%%$'\n'*}).
func LineFree(script string, p *Part) bool {
	if p != nil && p.Kind == PartParamOp && p.Param != nil {
		return p.Param.cutsLines(script)
	}
	if p == nil || p.Kind != PartSubst || p.Sub == nil || !p.Sub.Complete || len(p.Sub.List) != 1 {
		return false
	}
	pl, ok := p.Sub.List[0].(*Pipeline)
	if !ok || len(pl.Commands) < 2 {
		return false
	}
	first, ok1 := pl.Commands[0].(*Simple)
	last, ok2 := pl.Commands[len(pl.Commands)-1].(*Simple)
	return ok1 && ok2 && feeds(script, first) && dropsLines(script, last)
}

func feeds(script string, x *Simple) bool {
	var ws []string
	for i, a := range x.Words {
		s, ok := literalOf(script, a)
		if !ok && i != len(x.Words)-1 {
			return false
		}
		ws = append(ws, s)
	}
	switch {
	case len(ws) == 2 && ws[0] == "echo":
		return true
	case len(ws) == 3 && ws[0] == "echo" && ws[1] == "-n":
		return true
	case len(ws) == 3 && ws[0] == "printf" && (ws[1] == "%s" || ws[1] == `%s\n`):
		return true
	}
	return false
}

func dropsLines(script string, x *Simple) bool {
	if len(x.Redirects) > 0 {
		return false
	}
	var args []string
	for _, a := range x.Words {
		s, ok := literalOf(script, a)
		if !ok {
			return false
		}
		args = append(args, s)
	}
	has := func(set string) bool {
		set = trDecode(set)
		return strings.Contains(set, "\n") || strings.Contains(set, "[:space:]") || strings.Contains(set, "[:cntrl:]")
	}
	switch {
	case len(args) != 3 || args[0] != "tr":
		return false
	case args[1] == "-d" || args[1] == "--delete":
		return has(args[2])
	case strings.HasPrefix(args[1], "-"):
		return false
	}
	to := trDecode(args[2])
	return has(args[1]) && to != "" && !strings.ContainsAny(to, "\n[")
}

// PartParams are the parameters of the parts ps, and of their words and
// the scripts of their substitutions, in the order bash expands them
// (Walk).
func PartParams(ps []Part) []*Part {
	var out []*Part
	w := &walker{v: Visitor{Part: func(p *Part, _ Enclosing) {
		if p.Kind == PartParam || p.Kind == PartParamOp {
			out = append(out, p)
		}
	}}}
	w.parts(ps, Enclosing{Env: &ExecutionEnvironment{Kind: ExecutionEnvironmentTop}})
	return out
}

// TextParams are the parameters of the bytes at sp of script, for what the
// tree does not read (the inside of case, a ${ } bash does not read, an
// array's ( )): the bytes are read as tokens of commands, as bash reads
// a script (quotes, comments, operators and heredocs), and the parameters
// of the words, of the heredocs' bodies and of their substitutions are
// given, in the order of the bytes. Bytes that do not make tokens bash
// reads to their end give what was read up to there.
func TextParams(script string, sp Span) []*Part {
	l := &tokenizer{s: script, i: sp.Start, end: sp.End, stack: []lexState{inNormal}, starts: []int{sp.Start}, depths: []int{1}}
	l.frames = []*frame{{wordStart: true}}
	l.run()
	p := &parser{s: script, end: sp.End, err: -1}
	var out []*Part
	read := func(ps []Part) {
		p.subs(ps)
		out = append(out, PartParams(ps)...)
		for _, x := range ps {
			if x.Kind == PartOpaque && x.Span.End-x.Span.Start >= 2 && script[x.Span.Start] == '(' && script[x.Span.End-1] == ')' {
				out = append(out, TextParams(script, Span{x.Span.Start + 1, x.Span.End - 1})...) // the list of X=( ... ), which the tokenizer does not read
			}
		}
	}
	for _, t := range l.frames[0].toks {
		switch {
		case t.w != nil:
			read(t.w.Parts)
		case t.doc != nil:
			read(t.doc.body.Parts)
		}
	}
	if w := l.frames[0].cur; w != nil {
		read(w.Parts) // a word not ended
	}
	return out
}

// Params are the parameters that the commands cs expand, in their words,
// redirects, heredocs' bodies and substitutions, in the order bash expands
// them (Walk).
func Params(cs []Command) []*Part {
	var out []*Part
	Walk("", cs, Enclosing{}, Visitor{Part: func(p *Part, _ Enclosing) {
		if p.Kind == PartParam || p.Kind == PartParamOp {
			out = append(out, p)
		}
	}})
	return out
}

// pipeState is the pipeline a command of a shell gets its input from.
type pipeState struct {
	pipe     []Command
	pipeline *Pipeline
}

// switchPipe makes the pipe state of env the writer's: a subshell starts
// with its parent's where it starts, but a coproc, which reads no pipe of
// a pipeline.
func (w *writer) switchPipe(env *ExecutionEnvironment) {
	if env == w.pipeEnv {
		return
	}
	if w.pipeEnv != nil {
		w.pipes[w.pipeEnv] = pipeState{w.pipe, w.pipeline}
	}
	st, ok := w.pipes[env]
	if !ok {
		st = pipeState{w.pipe, w.pipeline}
		for e := env; e != nil; e = e.Parent {
			if p, seen := w.pipes[e.Parent]; seen && e.Parent != nil {
				st = p
				break
			}
		}
		if env.Kind == ExecutionEnvironmentCoproc {
			st = pipeState{}
		}
	}
	w.pipeEnv = env
	w.pipe, w.pipeline = st.pipe, st.pipeline
}

// walk reads the commands cs: Walk reads the descriptors (fdReading), and
// the writer adds what the commands write. The top command of a command
// (Write.Top) is the command of cs that holds it when tops, else top, and
// nil inside a substitution.
func (w *writer) walk(cs []Command, top Command, tops bool) {
	type frame struct {
		fn       string
		pipe     []Command
		pipeline *Pipeline
		atDef    bool
		// g: the gather of a compound command whose redirect points its
		// standard output; elem: that of the pipe of a command of a
		// pipeline; muted: the gathers a case takes as a whole
		g, elem *gather
		muted   []*gather
	}
	var stack []frame
	var root Command
	topOf := func(at Enclosing) Command {
		for e := at.Env; e != nil; e = e.Parent {
			if substituted(e) {
				return nil
			}
		}
		if !tops {
			return top
		}
		return root
	}
	Walk(w.s, cs, Enclosing{}, Visitor{
		Descriptors: &DescriptorReading{reading: w.fdReading},
		Command: func(c Command, at Enclosing) bool {
			w.switchPipe(at.Env)
			if len(stack) == 0 && at.Call == nil { // not the body of a call, which is in the call's top command
				root = c
			}
			f := frame{fn: w.fn}
			if at.Func != nil {
				w.fn, _ = literalOf(w.s, at.Func.Name)
			}
			if at.Pipeline != nil {
				// a command of a pipeline: what comes before it gives it its
				// input
				f.pipe, f.pipeline = w.pipe, w.pipeline
				w.pipe, w.pipeline = nil, at.Pipeline
				if at.Element > 0 {
					w.pipe = at.Pipeline.Commands[:at.Element+1]
				}
			}
			if x, ok := c.(*FuncDef); ok && w.atDefinition(x) {
				w.atDef++
				f.atDef = true
			}
			if at.Pipeline != nil && at.Pipeline.Commands[at.Element] == c && at.Element < len(at.Pipeline.Commands)-1 && len(w.frames) > 0 {
				// its pipe: where it points the standard output before its redirects
				f.elem = &gather{to: w.at(w.frames[len(w.frames)-1].base, 1)}
				w.gathers = append(w.gathers, f.elem)
			}
			if x, ok := c.(*Compound); ok {
				if w.redirected(x.Redirects) {
					to := w.at(w.fds, 1) // what its redirects point the commands inside at
					if x.Kind == CompoundSubshell || x.Kind == CompoundCoproc {
						to = w.at(w.bodyFds[x.span], 1)
					}
					f.g = &gather{to: to}
					w.gathers = append(w.gathers, f.g)
				}
				if x.Kind == CompoundCase {
					// what a case writes is not read: the tree has no bounds of
					// its arms
					ds := w.at(w.fds, 1)
					for _, g := range w.gathers {
						if g.takes(ds) {
							g.out = append(g.out, Out{Kind: OutUnknown, Span: x.Span(), Word: -1, Cmd: x})
							g.mute++
							f.muted = append(f.muted, g)
						}
					}
				}
			}
			stack = append(stack, f)
			return true
		},
		Leave: func(c Command, at Enclosing) {
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			w.switchPipe(at.Env)
			top := topOf(at)
			switch x := c.(type) {
			case *Simple:
				w.simpleCommand(x, top)
			case *Compound:
				if f.g != nil {
					w.close(f.g)
					if ts := w.targets(x.Redirects); len(ts) > 0 && !w.failsAlways(x.Redirects) {
						for _, t := range ts {
							w.write(Write{Target: t, At: x, Top: top, Out: slices.Clone(f.g.out)})
						}
					}
				}
			}
			for _, g := range f.muted {
				g.mute--
			}
			if f.elem != nil {
				if x, ok := c.(*Simple); ok && w.callsBody(x) {
					// a call: its bodies, which the walk gives after it, write
					// to its pipe too; the gather ends where they end
					if w.elementCalls == nil {
						w.elementCalls = map[*Simple]elementCall{}
					}
					w.elementCalls[x] = elementCall{f.elem, at.Pipeline, at.Element}
				} else {
					w.endElement(f.elem, at.Pipeline, at.Element)
				}
			}
			if f.atDef {
				w.atDef--
			}
			w.fn = f.fn
			if at.Pipeline != nil {
				w.pipe, w.pipeline = f.pipe, f.pipeline
				if at.Element > 0 {
					for _, t := range w.tee(c) {
						var out []Out // what reaches c through the pipe (PipeSources)
						if from := PipeSources(w.s, at.Pipeline, at.Element); len(from) > 0 && w.reads(c) {
							out = w.pipeOut(at.Pipeline, from[len(from)-1].Element, at.Element)
						}
						w.write(Write{Target: t, At: c, Top: top, Out: out})
					}
				}
			}
		},
		LeaveCall: func(x *Simple, _ Enclosing, read bool) {
			for _, g := range w.muted[x] {
				g.mute--
			}
			delete(w.muted, x)
			if !read {
				for _, pc := range w.pending[x] {
					pc.g.out = append(pc.g.out, pc.out...)
				}
			}
			delete(w.pending, x)
			if n := len(w.gathers); n > 0 && w.gathers[n-1].call == x {
				g := w.gathers[n-1]
				w.gathers = w.gathers[:n-1]
				out := g.unread
				if read {
					out = g.out
				}
				for _, i := range g.writes {
					w.out[i].Out = slices.Clone(out)
				}
			}
			if e, ok := w.elementCalls[x]; ok {
				delete(w.elementCalls, x)
				w.endElement(e.g, e.p, e.i)
			}
		},
	})
}

// elementCall is the gather of the pipe of a command of a pipeline that is
// a call, which ends after the bodies of the call (Visitor.LeaveCall).
type elementCall struct {
	g *gather
	p *Pipeline
	i int
}

// callsBody is whether the walk gives bodies after the simple command x and
// then Visitor.LeaveCall: x calls a function, and is no exec.
func (w *writer) callsBody(x *Simple) bool {
	_, defs := w.defsAt(x)
	return len(defs) > 0 && !w.isExec(x)
}

// endElement ends g, the gather of the pipe of the command i of p, and
// keeps what it took (pipeOut).
func (w *writer) endElement(g *gather, p *Pipeline, i int) {
	w.close(g)
	if w.elements == nil {
		w.elements = map[*Pipeline][][]Out{}
	}
	if w.elements[p] == nil {
		w.elements[p] = make([][]Out, len(p.Commands))
	}
	w.elements[p][i] = g.out
}

// close ends the gather g, the innermost open.
func (w *writer) close(g *gather) {
	if n := len(w.gathers); n == 0 || w.gathers[n-1] != g {
		panic("shell: a gather closed out of order")
	}
	w.gathers = w.gathers[:len(w.gathers)-1]
}

// pipeOut is what the commands from to to (not included) of the pipeline p
// write through the pipe after them: what the last of them writes to its
// pipe, or, where it writes what is not known and more than one command is
// in them, the pipeline of them as one command not known.
func (w *writer) pipeOut(p *Pipeline, from, to int) []Out {
	var out []Out
	if es := w.elements[p]; es != nil {
		out = es[to-1]
	}
	if to-from > 1 && slices.ContainsFunc(out, func(o Out) bool { return o.Kind == OutUnknown }) {
		return w.piped(p, from, to)
	}
	return out
}

// simpleCommand reads what the simple command x writes; what it opens and
// where it jumps, Walk reads (fdReading.post).
func (w *writer) simpleCommand(x *Simple, top Command) {
	saved := w.cmd
	w.cmd = x
	defer func() { w.cmd = saved }()
	if w.failsAlways(x.Redirects) {
		return // bash does not run it
	}
	if w.isExec(x) {
		for _, d := range w.execResult(x)[2] {
			if d.file {
				// what the commands after write to the standard error goes
				// to the file
				w.write(Write{Target: d.w, At: x, Top: top, Exec: true})
			}
		}
		for _, t := range w.targets(x.Redirects) {
			w.write(Write{Target: t, At: x, Top: top, Exec: true})
		}
		return
	}
	_, defs := w.defsAt(x)
	// a call writes what its bodies, which the walk gives after it, write;
	// one given arguments or the input of a pipe (a heredoc or a here-string
	// is read as the body reads it), or that sees more than one definition,
	// writes what is not known, with the bodies' parameters as what it may
	// write: the readers of a write do not follow a parameter of the body to
	// the words of the call, or a command of the body to the input of the
	// call
	call := len(defs) > 0
	if call && (len(x.Words) > 1 || len(defs) > 1 || w.pipe != nil) {
		call = false
		if w.muted == nil {
			w.muted = map[*Simple][]*gather{}
		}
	}
	if len(w.gathers) > 0 {
		// the places that gather what it writes, where it points its
		// standard output
		ds := w.at(w.table(x.Redirects), 1)
		var out []Out
		if !call {
			out = w.piping(x, w.simple(x))
		}
		for _, g := range w.gathers {
			switch {
			case !g.takes(ds):
			case call:
				if w.pending == nil {
					w.pending = map[*Simple][]pendingCall{}
				}
				w.pending[x] = append(w.pending[x], pendingCall{g, w.piping(x, w.simple(x))})
			default:
				g.out = append(g.out, out...)
				if len(defs) > 0 {
					g.mute++ // its bodies write what it writes, taken already
					w.muted[x] = append(w.muted[x], g)
				}
			}
		}
	}
	ts := w.targets(x.Redirects)
	switch {
	case len(ts) > 0 && call:
		// the call's writes take what its bodies write, where they run
		// (Visitor.LeaveCall)
		own, _ := w.table(x.Redirects).own[1]
		g := &gather{to: covered(own), call: x, unread: w.piping(x, w.simple(x))}
		for _, t := range ts {
			g.writes = append(g.writes, len(w.out))
			w.write(Write{Target: t, At: x, Top: top})
		}
		w.gathers = append(w.gathers, g)
	case len(ts) > 0:
		out := w.simple(x)
		for _, t := range ts {
			w.write(Write{Target: t, At: x, Top: top, Out: slices.Clone(out)})
		}
	}
	w.logged(x, top) // a call's body is read where it is called
}

// pipeRead is an answer of PipeReaders.
type pipeRead struct {
	readers []*Simple
	unread  bool
}

// pipeReaders is PipeReaders(w.s, c), read once for each command.
func (w *writer) pipeReaders(c Command) ([]*Simple, bool) {
	if r, ok := w.readers[c]; ok {
		return r.readers, r.unread
	}
	readers, unread := PipeReaders(w.s, c)
	if w.readers == nil {
		w.readers = map[Command]pipeRead{}
	}
	w.readers[c] = pipeRead{readers, unread}
	return readers, unread
}
