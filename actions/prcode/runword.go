package prcode

import (
	"path"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// wordBase is where the path of a word of a run starts.
type wordBase uint8

const (
	wordWorkspace  wordBase = iota // the working directory (the workspace), or github.workspace
	wordRunnerTemp                 // runner.temp
	wordAnywhere                   // a ${{ }} whose value is not known: any directory
	wordBeside                     // a directory next to runner.temp or github.workspace, which no Placement holds
)

// runWord is a word of a run as runsTree reads it: the path it names from
// its base, whether what is not known follows that path (open), whether it
// is read at all (known), and its text for shell.LookupCommand, with each
// ${{ }} as letters and $RUNNER_TEMP and $GITHUB_WORKSPACE by name.
type runWord struct {
	base    wordBase
	path    string
	open    bool
	openDir bool // what is not known is an absolute path ($RUNNER_TEMP): path is a directory
	known   bool
	lookup  string
	// relative: a literal path from the directory of the shell, not from
	// a base the word names (runner.temp, github.workspace) and not
	// absolute (join)
	relative bool
	// afterEq, of a word of bash whose first part is a literal outside
	// quotes with an = before any ${{ }}, is what follows that = as a word
	// (the value of --dir=<value>)
	afterEq *runWord
}

// unreadWord is a word with an expansion that is not read.
var unreadWord = runWord{}

// literalWord is the word s, a literal.
func literalWord(s string) runWord {
	var b wordBuilder
	b.literal(s)
	return b.word()
}

// headKind is what a ${{ }} or a parameter at the head of a word is.
type headKind uint8

const (
	headNone         headKind = iota // a literal, or nothing that names a directory
	headRunnerTemp                   // runner.temp
	headWorkspace                    // github.workspace
	headAnywhere                     // a ${{ }} whose value is not known
	headEmpty                        // a ${{ }} whose value is empty (github.action_path outside a composite action)
	headWorkspaceAny                 // a variable of pwsh: read as any directory of the workspace
)

// exprHead is what the ${{ }} p names, in a composite action's step or not.
func exprHead(p workflow.Part, inComposite bool) headKind {
	switch {
	case isRunnerTemp(p):
		return headRunnerTemp
	case p.Tree != nil && expr.IsPath(p.Tree, "github", "workspace"):
		return headWorkspace
	case p.Tree != nil && expr.IsPath(p.Tree, "github", "action_path"):
		if inComposite {
			return headAnywhere // a local action is in the workspace
		}
		return headEmpty
	}
	return headAnywhere
}

// wordBuilder reads the parts of a word in order.
type wordBuilder struct {
	head    headKind
	started bool // a part that adds to the path has been read
	text    strings.Builder
	open    bool
	openDir bool
	lookup  strings.Builder
}

func (b *wordBuilder) literal(s string) {
	b.lookup.WriteString(s)
	if s == "" {
		return
	}
	if !b.open {
		b.text.WriteString(s)
	}
	b.started = true
}

// unknown reads a part that names a directory: at the head, the base of
// the word; elsewhere, what is not known from it on.
func (b *wordBuilder) unknown(h headKind, lookup string) {
	b.lookup.WriteString(lookup)
	if h == headEmpty {
		return
	}
	if !b.started {
		b.head, b.started = h, true
		if h == headAnywhere || h == headWorkspaceAny {
			b.open = true
		}
		return
	}
	if !b.open {
		b.openDir = h == headRunnerTemp || h == headWorkspace
	}
	b.open = true
}

func (b *wordBuilder) word() runWord {
	w := runWord{known: true, open: b.open, openDir: b.openDir, lookup: b.lookup.String()}
	t := b.text.String()
	switch b.head {
	case headNone:
		w.base, w.path = wordWorkspace, t
		if strings.HasPrefix(t, "/") {
			// an absolute path may name the workspace (/home/runner/work/...)
			w.base, w.path, w.open = wordAnywhere, "", true
		}
	case headAnywhere:
		w.base = wordAnywhere
	case headWorkspaceAny:
		w.base = wordWorkspace
	case headRunnerTemp, headWorkspace:
		w.base = wordWorkspace
		if b.head == headRunnerTemp {
			w.base = wordRunnerTemp
		}
		switch {
		case t == "":
			w.path = "."
			if w.open {
				w.path = ""
			}
		case strings.HasPrefix(t, "/"):
			w.path = t[1:]
		default:
			w.base = wordBeside
		}
	}
	if (b.head != headNone || w.open) && (w.base == wordWorkspace || w.base == wordRunnerTemp) {
		if climbs(w.path, w.open) {
			w.base = wordAnywhere
		}
	}
	w.relative = b.head == headNone && w.base == wordWorkspace
	return w
}

// climbs is whether the path p leaves its base by .., in what is known of
// it: the whole of it, or for an open path what is before its last /.
func climbs(p string, open bool) bool {
	if open {
		i := strings.LastIndexByte(p, '/')
		if i < 0 {
			return false
		}
		p = p[:i]
	}
	if p == "" {
		return false
	}
	c := path.Clean(p)
	return c == ".." || strings.HasPrefix(c, "../")
}

// exprsIn are the ${{ }} of v in the bytes sp.
func exprsIn(v workflow.String, sp shell.Span) []workflow.Part {
	var out []workflow.Part
	for _, p := range v.Parts {
		if p.Expr && p.Span.Start >= sp.Start && p.Span.End <= sp.End {
			out = append(out, p)
		}
	}
	return out
}

// wordOf is the word wd of the run v as runsTree reads it. masked is v
// with its ${{ }} as letters, at the same bytes; inComposite is whether
// the step is a composite action's.
func wordOf(v workflow.String, masked string, wd shell.Word, inComposite bool) runWord {
	w := wordParts(v, masked, wd, inComposite)
	if w.known && len(wd.Parts) > 0 && wd.Parts[0].Kind == shell.PartLiteral && wd.Parts[0].Quote == shell.QuoteNone {
		first := wd.Parts[0]
		k := strings.IndexByte(masked[first.Span.Start:first.Span.End], '=')
		exprs := exprsIn(v, first.Span)
		if k >= 0 && (len(exprs) == 0 || first.Span.Start+k < exprs[0].Span.Start) {
			rest := first
			rest.Span.Start += k + 1
			sub := shell.Word{Span: shell.Span{Start: rest.Span.Start, End: wd.Span.End}}
			if rest.Span.Start < rest.Span.End {
				sub.Parts = append(sub.Parts, rest)
			}
			sub.Parts = append(sub.Parts, wd.Parts[1:]...)
			after := wordOf(v, masked, sub, inComposite)
			w.afterEq = &after
		}
	}
	return w
}

// wordParts reads the parts of the word wd in order (wordOf).
func wordParts(v workflow.String, masked string, wd shell.Word, inComposite bool) runWord {
	var b wordBuilder
	for _, p := range wd.Parts {
		switch p.Kind {
		case shell.PartLiteral:
			lit, ok := shell.Literal(masked, shell.Word{Span: p.Span, Parts: []shell.Part{p}})
			if !ok {
				return unreadWord
			}
			exprs := exprsIn(v, p.Span)
			if len(exprs) == 0 {
				b.literal(lit)
				continue
			}
			spans, ok := exprSpans(masked[p.Span.Start:p.Span.End], lit, exprs, p.Span.Start, p.Quote)
			if !ok {
				// the ${{ }} are not found in the literal: they are read
				// as its letters, but runner.temp is not read
				if slices.ContainsFunc(exprs, isRunnerTemp) {
					return unreadWord
				}
				b.literal(lit)
				continue
			}
			at := 0
			for i, e := range exprs {
				b.literal(lit[at:spans[i].Start])
				b.unknown(exprHead(e, inComposite), lit[spans[i].Start:spans[i].End])
				at = spans[i].End
			}
			b.literal(lit[at:])
		case shell.PartParam:
			switch p.Name.String() {
			case "RUNNER_TEMP":
				b.unknown(headRunnerTemp, "$RUNNER_TEMP")
			case "GITHUB_WORKSPACE":
				b.unknown(headWorkspace, "$GITHUB_WORKSPACE")
			default:
				return unreadWord
			}
		default:
			return unreadWord
		}
	}
	return b.word()
}

// inWorkingDir is w as a file of the working directory: ./ before it.
func (w runWord) inWorkingDir() runWord {
	w.lookup = "./" + w.lookup
	if w.base == wordAnywhere {
		return w // a ${{ }} at its head may be an absolute path
	}
	w.path = "./" + w.path
	return w
}

// isPath is whether the shell reads w as a path, not a name it looks up:
// it has a /.
func (w runWord) isPath() bool { return w.known && strings.Contains(w.lookup, "/") }

// mayHold is whether the directory w may hold at: at is w or under it.
func (w runWord) mayHold(at Placement) bool {
	switch w.base {
	case wordAnywhere:
		return true
	case wordWorkspace:
		if !at.InWorkspace() {
			return false
		}
	case wordRunnerTemp:
		if at.InWorkspace() {
			return false
		}
	default:
		return false
	}
	if w.open || !at.dir.known {
		return true
	}
	return under(at.dir.path, w.path)
}

// mayBeUnder is whether the file w names may be under at.
func (w runWord) mayBeUnder(at Placement) bool {
	switch w.base {
	case wordAnywhere:
		return true
	case wordWorkspace:
		if !at.InWorkspace() {
			return false
		}
	case wordRunnerTemp:
		if at.InWorkspace() {
			return false
		}
	default:
		return false
	}
	if !w.open {
		return at.dir.holds(w.path)
	}
	if !at.dir.known || at.dir.path == "." {
		return true
	}
	p := w.path
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	d := at.dir.path
	if w.openDir {
		// p is a directory: an absolute path follows it
		p = strings.TrimSuffix(p, "/")
		return p == "" || p == d || strings.HasPrefix(p, d+"/") || strings.HasPrefix(d, p+"/")
	}
	return p == d || strings.HasPrefix(p, d+"/") || strings.HasPrefix(d+"/", p)
}

// exprSpans are the bytes of the literal lit that the ${{ }} exprs of the
// part with the bytes raw (at start in the script) become. The shell makes
// lit by taking quotes and backslashes out of raw, and a ${{ }} is letters
// (taint.Masked), which it keeps: each byte of raw is found in lit in
// order, or is taken out. It is false when the quote adds bytes ($'\x41')
// or a byte of a ${{ }} is taken out.
func exprSpans(raw, lit string, exprs []workflow.Part, start int, q shell.Quote) ([]shell.Span, bool) {
	if q == shell.QuoteANSI && raw != lit {
		return nil, false // an escape of $'...' makes bytes that raw does not have
	}
	pos := make([]int, len(raw)) // the byte of lit of each byte of raw, or -1
	j := 0
	for i := range raw {
		pos[i] = -1
		if j < len(lit) && raw[i] == lit[j] {
			pos[i] = j
			j++
		}
	}
	if j != len(lit) {
		return nil, false
	}
	out := make([]shell.Span, len(exprs))
	for k, e := range exprs {
		a, z := e.Span.Start-start, e.Span.End-start
		for i := a; i < z; i++ {
			if pos[i] != pos[a]+(i-a) || pos[a] < 0 {
				return nil, false
			}
		}
		out[k] = shell.Span{Start: pos[a], End: pos[a] + (z - a)}
	}
	return out, true
}

// pwshWords are the words of the statement of pwsh in the bytes line of
// masked (the run v with its ${{ }} as letters), as runsTree reads them:
// nil when the statement is an expression, whose first word is a string
// in quotes or a variable, which pwsh evaluates and does not run
// (about_Parsing, Expression mode); after & or . the next word. Each word
// loses the quotes around it; in "..." and outside quotes $env:RUNNER_TEMP
// and $env:GITHUB_WORKSPACE (also ${env:...}) name their directories,
// another variable any directory of the workspace; in '...' nothing
// expands. A \ is a / (the separator of Windows).
func pwshWords(v workflow.String, masked string, line shell.Span, inComposite bool) []runWord {
	fields := pwshFields(masked, line)
	if len(fields) == 0 {
		return nil
	}
	switch first := masked[fields[0].Start:fields[0].End]; {
	case first == "&" || first == ".":
		fields = fields[1:]
	case strings.HasPrefix(first, `"`) || strings.HasPrefix(first, "'") || strings.HasPrefix(first, "$"):
		return nil
	}
	var out []runWord
	for _, f := range fields {
		out = append(out, pwshWord(v, masked, f, inComposite))
	}
	return out
}

// pwshWord is the word of pwsh in the bytes f of masked.
func pwshWord(v workflow.String, masked string, f shell.Span, inComposite bool) runWord {
	single := false
	if t := masked[f.Start:f.End]; len(t) >= 2 && (t[0] == '"' || t[0] == '\'') && t[len(t)-1] == t[0] {
		single = t[0] == '\''
		f = shell.Span{Start: f.Start + 1, End: f.End - 1}
	}
	var b wordBuilder
	exprs := exprsIn(v, f)
	lit := func(seg string) {
		seg = strings.ReplaceAll(seg, `\`, "/")
		for seg != "" {
			i := strings.IndexByte(seg, '$')
			if single || i < 0 {
				b.literal(seg)
				return
			}
			b.literal(seg[:i])
			name, n := pwshVariable(seg[i:])
			switch {
			case strings.EqualFold(name, "env:RUNNER_TEMP"):
				b.unknown(headRunnerTemp, seg[i:i+n])
			case strings.EqualFold(name, "env:GITHUB_WORKSPACE"):
				b.unknown(headWorkspace, seg[i:i+n])
			default:
				b.unknown(headWorkspaceAny, seg[i:i+n])
			}
			seg = seg[i+n:]
		}
	}
	at := f.Start
	for _, e := range exprs {
		lit(masked[at:e.Span.Start])
		b.unknown(exprHead(e, inComposite), masked[e.Span.Start:e.Span.End])
		at = e.Span.End
	}
	lit(masked[at:f.End])
	return b.word()
}

// pwshVariable is the name of the variable that s starts with ($name,
// $env:name, ${name}, ${env:name}), with env: in any case written as
// env:, and how many bytes it takes; a $ with no name takes the rest.
func pwshVariable(s string) (string, int) {
	if strings.HasPrefix(s, "${") {
		if j := strings.IndexByte(s, '}'); j > 0 {
			return pwshName(s[2:j]), j + 1
		}
		return "", len(s)
	}
	j := 1
	if len(s) >= 5 && strings.EqualFold(s[1:5], "env:") {
		j = 5
	}
	k := j
	for k < len(s) && (s[k] == '_' || s[k] >= 'a' && s[k] <= 'z' || s[k] >= 'A' && s[k] <= 'Z' || s[k] >= '0' && s[k] <= '9') {
		k++
	}
	if k == 1 {
		return "", len(s)
	}
	return pwshName(s[1:k]), k
}

// pwshName is the name n with a leading env: in any case written env:.
func pwshName(n string) string {
	if len(n) >= 4 && strings.EqualFold(n[:4], "env:") {
		return "env:" + n[4:]
	}
	return n
}

// pwshFields are the words of the statement in the bytes sp of masked:
// split at spaces and tabs outside quotes.
func pwshFields(masked string, sp shell.Span) []shell.Span {
	var out []shell.Span
	start, quote := -1, byte(0)
	for i := sp.Start; i < sp.End; i++ {
		c := masked[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == ' ' || c == '\t':
			if start >= 0 {
				out = append(out, shell.Span{Start: start, End: i})
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, shell.Span{Start: start, End: sp.End})
	}
	return out
}

// pwshStatements are the statements of the bytes line of masked: split at
// ; outside quotes.
func pwshStatements(masked string, line shell.Span) []shell.Span {
	var out []shell.Span
	start, quote := line.Start, byte(0)
	for i := line.Start; i < line.End; i++ {
		switch c := masked[i]; {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == ';':
			out = append(out, shell.Span{Start: start, End: i})
			start = i + 1
		}
	}
	return append(out, shell.Span{Start: start, End: line.End})
}
