package shell

import (
	"slices"
	"sort"
	"strings"
)

// VariableCode is a variable whose value bash, or a program bash gives the
// value to, reads as code at a place of a script: the expansion ($NAME,
// ${NAME}, ${NAME...}) or, Bare, a name an arithmetic expression reads
// without $.
type VariableCode struct {
	Name    VarName
	Span    Span
	Reading CodeReading
	Bare    bool
}

// maxInnerDepth is how deep VariableCodes reads the scripts inside ` `,
// $(( )), (( )) and the words after the operator of ${ }, each of which it
// parses on its own.
const maxInnerDepth = 8

// VariableCodes are the variables of script, whose tree is sc, that bash or
// a program reads as code, in the order of the script: in an argument a
// command reads as code (the commands and options commands.json gives a
// ValueReading), unquoted at the start of the command word, in what a
// command that runs its input as code reads (InputValueCode: a heredoc
// whose delimiter is not quoted, a here-string, the words of echo, printf
// or cat right before a pipe), and in arithmetic (also the subscript of a
// name ${!NAME} names, and of an array that is not associative). It reads
// the scripts inside $( ), <( ) and >( ), and parses on its own the inside
// of ` ` (when it has no backslash), $(( )), (( )), the subscript of an
// assignment to an array and the words after the operator of ${ }, so that
// the tree Places reads does not change. The value of a command
// substitution is not followed: what eval "$(echo $V)" reads is the output
// of echo.
func VariableCodes(script string, sc *Script) []VariableCode {
	var out []VariableCode
	v := &varCodes{s: script, assoc: assocNames(script, sc), out: &out}
	v.list(sc.List, 0)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Span.Start < out[j].Span.Start })
	limit := len(script)
	if sc.unterminated {
		// bash runs the lines before the line it cannot read to its end,
		// and refuses that line
		limit = strings.LastIndexByte(script[:min(sc.Stop, len(script))], '\n') + 1
	}
	kept := out[:0]
	for i, c := range out {
		if i > 0 && c.Span == out[i-1].Span || c.Span.End > limit {
			continue
		}
		kept = append(kept, c)
	}
	return kept
}

// varCodes reads s, which is the text of the script from off on: a part of
// the script parsed on its own, or the whole script (off 0).
type varCodes struct {
	s     string
	off   int
	assoc map[string]bool // the names a declare, typeset or local declares -A: their subscripts are not arithmetic
	out   *[]VariableCode
	// positional: the positional parameters ($1, ${2}, $@, $*) are read
	// too, as a variable is (readsArgsAsCode)
	positional bool
}

// named is whether the parameter name is read: a name of a variable, or
// with positional a positional parameter.
func (v *varCodes) named(name string) bool {
	return isName(name) || v.positional && positionalParam(name)
}

// positionalParam is whether name is a positional parameter: digits, @ or
// *.
func positionalParam(name string) bool {
	return name == "@" || name == "*" || name != "" && strings.Trim(name, "0123456789") == ""
}

// readsArgsAsCode is whether bash or a program reads, in the commands cs
// of script, a positional parameter as code ($1, ${2}, $@, $*), where
// VariableCodes reads a variable as code: the body of a function that
// does reads its arguments as code.
func readsArgsAsCode(script string, assoc map[string]bool, cs []Command) bool {
	var out []VariableCode
	v := &varCodes{s: script, assoc: assoc, out: &out, positional: true}
	v.list(cs, 0)
	args := argNames(script, cs)
	for _, c := range out {
		if n := c.Name.String(); positionalParam(n) || n == "" || args[n] { // ${@:2} holds its name in the ${ } alone
			return true
		}
	}
	return false
}

// argNames are the names that the commands cs assign a value holding a
// positional parameter, or a name so assigned: an assignment word (i=$1,
// x=("$@")), an assignment of declare, typeset, local, export or readonly,
// and the name of for or select with no in (the positional parameters) or
// with words that hold one.
func argNames(script string, cs []Command) map[string]bool {
	names, _ := argAssignments(script, cs)
	return names
}

// argAssignments are argNames, and whether a word of declare, typeset,
// local, export or readonly that is not an assignment word holds a
// positional parameter or a name of argNames (export "$1"): the word may
// expand to an assignment. The commands are read once: each assignment
// gives the names its value holds and the name it assigns, and the names
// are followed from the positional parameters with a worklist.
func argAssignments(script string, cs []Command) (map[string]bool, bool) {
	from := map[string][]string{} // a name, to the names assigned a value that holds the name
	var seeds []string            // the names assigned a value that holds a positional parameter
	var unnamed [][]string        // the names that the words not an assignment hold
	unnamedArg := false
	params := func(w Word) []string {
		var out []string
		add := func(p *Part) {
			n := p.Name.String()
			if p.Kind == PartParamOp && p.Param != nil {
				n = p.Param.Name.String()
			}
			out = append(out, n)
		}
		for _, p := range PartParams(w.Parts) {
			add(p)
		}
		for _, p := range w.Parts {
			if p.Kind != PartOpaque {
				continue
			}
			for _, q := range TextParams(script, p.Span) { // the ( ) of an array's assignment
				add(q)
			}
		}
		return out
	}
	assign := func(n string, held []string) {
		if n == "" {
			return
		}
		for _, m := range held {
			if positionalParam(m) {
				seeds = append(seeds, n)
				return
			}
		}
		for _, m := range held {
			from[m] = append(from[m], n)
		}
	}
	Walk(script, cs, Enclosing{}, Visitor{Command: func(x Command, _ Enclosing) bool {
		switch y := x.(type) {
		case *Simple:
			ws := y.Assigns
			var args []Word
			if bw, words := builtinWords(script, y); len(bw) > 0 && bw[0].Known {
				switch bw[0].Text {
				case "declare", "typeset", "local", "export", "readonly":
					args = words[1:]
				}
			}
			for _, w := range ws {
				if n, _, _, ok := AssignedName(script, w); ok {
					assign(n, params(w))
				}
			}
			for _, w := range args {
				if n, _, _, ok := AssignedName(script, w); ok {
					assign(n, params(w))
					continue
				}
				held := params(w)
				if slices.ContainsFunc(held, positionalParam) {
					unnamedArg = true
				} else if len(held) > 0 {
					unnamed = append(unnamed, held)
				}
			}
		case *Compound:
			if (y.Kind == CompoundFor || y.Kind == CompoundSelect) && y.Var != nil {
				n, _ := literalOf(script, *y.Var)
				if !y.HasIn {
					assign(n, []string{"@"})
					break
				}
				var held []string
				for _, w := range y.In {
					held = append(held, params(w)...)
				}
				assign(n, held)
			}
		}
		return true
	}})
	names := map[string]bool{}
	for len(seeds) > 0 {
		n := seeds[len(seeds)-1]
		seeds = seeds[:len(seeds)-1]
		if names[n] {
			continue
		}
		names[n] = true
		seeds = append(seeds, from[n]...)
	}
	for _, held := range unnamed {
		unnamedArg = unnamedArg || slices.ContainsFunc(held, func(m string) bool { return names[m] })
	}
	return names, unnamedArg
}

func (v *varCodes) emit(n VarName, sp Span, r CodeReading, bare bool) {
	*v.out = append(*v.out, VariableCode{Name: n, Span: Span{sp.Start + v.off, sp.End + v.off}, Reading: r, Bare: bare})
}

// list reads the commands cs. The scripts of substitutions are read with
// the words that hold them (parts).
func (v *varCodes) list(cs []Command, depth int) {
	Walk(v.s, cs, Enclosing{}, Visitor{
		Command: func(c Command, at Enclosing) bool {
			if at.Env.Kind == ExecutionEnvironmentCommandSubstitution || at.Env.Kind == ExecutionEnvironmentProcessSubstitution {
				return false
			}
			switch x := c.(type) {
			case *Simple:
				v.simple(x, depth)
				return false
			case *Compound:
				for _, w := range Words(x) { // a coproc's name, which bash expands in the shell that starts the coproc
					v.parts(w.Parts, CodeReadingUnset, depth)
				}
				v.compoundArith(x, depth) // (( )) and for (( ; ; ))
			}
			return true
		},
		Leave: func(c Command, at Enclosing) {
			switch x := c.(type) {
			case *Compound:
				if at.Env.Kind == ExecutionEnvironmentCommandSubstitution || at.Env.Kind == ExecutionEnvironmentProcessSubstitution {
					return
				}
				for _, r := range x.Redirects {
					v.redirect(r, depth)
				}
			case *Pipeline:
				v.pipeline(x, depth)
			}
		},
	})
}

// pipeline reads what the commands of p write into a pipe that a command
// after them reads as code: what echo, printf and cat write is their
// arguments and input.
func (v *varCodes) pipeline(p *Pipeline, depth int) {
	for i := 1; i < len(p.Commands); i++ {
		readers, _ := PipeReaders(v.s, p.Commands[i]) // a place the tree does not follow is not read: no Finding on a guess
		if !slices.ContainsFunc(readers, v.readsInput) {
			continue
		}
		for _, src := range PipeSources(v.s, p, i) {
			if src.Passage == PipePassageVerbatim { // what the commands between write is the value as it is
				v.writer(p.Commands[src.Element], depth)
			}
		}
	}
}

// readsInput is whether s runs as code the value its input carries: its
// command, past its wrappers, is declared InputValueCode, and it reads no
// script of its own: no code of -c, and no operand (the operand of source
// and . is /dev/stdin), but after -s.
func (v *varCodes) readsInput(s *Simple) bool {
	words := WordsOf(v.s, s)
	m := LookupCommand(words)
	c := m.Command
	if m.Entry == nil || c < 0 || c >= len(words) || !words[c].Known || !m.Entry.InputValueCode {
		return false
	}
	name := base(words[c].Text)
	stdin := false
	for i := c + 1; i < len(words); i++ {
		w := words[i]
		if !w.Known {
			return stdin
		}
		if w.Text == "-" && name != "source" && name != "." {
			return true // the script is the standard input
		}
		if strings.HasPrefix(w.Text, "-") && w.Text != "-" && w.Text != "--" {
			if w.Text == "-s" {
				stdin = true
			}
			o, holds := m.Entry.option(w.Text)
			switch {
			case o != nil && o.ValueReading != CodeReadingUnset:
				return false // the code of -c
			case o != nil && o.Value && !holds:
				i++
			}
			continue
		}
		if name == "source" || name == "." {
			return w.Text == "/dev/stdin"
		}
		return stdin
	}
	return name != "source" && name != "."
}

// writer reads c, whose output reaches through a pipe a command that runs
// its input as code: what echo, printf and cat write is their arguments
// and input.
func (v *varCodes) writer(c Command, depth int) {
	s, ok := c.(*Simple)
	if !ok || len(s.Words) == 0 {
		return
	}
	name, known := literalOf(v.s, s.Words[0])
	if !known || !identityWriters[base(name)] {
		return
	}
	for _, w := range s.Words[1:] {
		v.parts(w.Parts, CodeReadingCodeInput, depth)
	}
	for _, r := range s.Redirects {
		v.input(r, depth)
	}
}

// identityWriters are the commands that write their arguments or their
// input as they are, read before a pipe.
var identityWriters = map[string]bool{"echo": true, "printf": true, "cat": true}

func (v *varCodes) simple(s *Simple, depth int) {
	if s.isCond {
		for i, w := range s.Words {
			r := CodeReadingUnset
			if s.cond != nil && s.cond[i] == condArith {
				r = CodeReadingArithmetic
				if t, ok := literalOf(v.s, s.Words[max(i-1, 0)]); !ok || t != "-v" {
					v.bareNames(w) // the name of -v is a name, whose value is not read
				}
			}
			v.parts(w.Parts, r, depth)
		}
		return
	}
	for _, w := range s.Assigns {
		v.assignment(w, depth)
	}
	words := WordsOf(v.s, s)
	m := LookupCommand(words)
	readings := make([]CodeReading, len(s.Words))
	handled := make([]bool, len(s.Words))
	var e *CommandEntry
	if c := m.Command; c >= 0 && c < len(s.Words) {
		if v.assignment(s.Words[c], depth) {
			handled[c] = true
		} else {
			readings[c] = CodeReadingCommandWord
		}
		if words[c].Known {
			e = v.arguments(s, words, c, readings)
		}
	}
	for i, w := range s.Words {
		switch {
		case handled[i]:
		case readings[i] == CodeReadingCommandWord:
			v.commandWord(w, depth)
		default:
			if readings[i] == CodeReadingArithmetic && e != nil && e.Has(CommandTraitCodeArguments) {
				v.bareNames(w) // let reads its words as expressions
			}
			v.parts(w.Parts, readings[i], depth)
		}
	}
	code := v.readsInput(s)
	for _, r := range s.Redirects {
		if code {
			v.input(r, depth)
			continue
		}
		v.redirect(r, depth)
	}
}

// commandWord reads the command word w: the value of a variable at its
// start, outside quotes, is split into the program and its arguments.
func (v *varCodes) commandWord(w Word, depth int) {
	for i, p := range w.Parts {
		r := CodeReadingUnset
		if i == 0 && p.Quote == QuoteNone {
			r = CodeReadingCommandWord
		}
		v.parts([]Part{p}, r, depth)
	}
}

// assignment reads w when it is an assignment, NAME=value, or one to an
// element of an array, NAME[subscript]=value or +=, which the tree may give
// as the command word: the subscript is arithmetic, unless NAME is
// associative; the value is data. It is whether w is one.
func (v *varCodes) assignment(w Word, depth int) bool {
	text := v.s[w.Span.Start:w.Span.End]
	n := 0
	for n < len(text) && isNameByte(text[n]) {
		n++
	}
	if n == 0 || !isNameStart(text[0]) || n >= len(text) || text[n] != '[' {
		if n > 0 && isNameStart(text[0]) && n < len(text) && (text[n] == '=' || strings.HasPrefix(text[n:], "+=")) {
			v.parts(w.Parts, CodeReadingUnset, depth)
			return true
		}
		return false
	}
	end := strings.Index(text, "]=")
	if plus := strings.Index(text, "]+="); plus >= 0 && (end < 0 || plus < end) {
		end = plus
	}
	if end < 0 {
		return false
	}
	if !v.assoc[text[:n]] {
		v.arith(Span{w.Span.Start + n + 1, w.Span.Start + end}, depth)
	}
	v.parts(w.Parts, CodeReadingUnset, depth)
	return true
}

// arguments gives readings the readings of the words after the command
// word c: the value of an option with a ValueReading, and the operands of
// an entry with one. It goes down to the subcommand a word names; after a
// wrapper (runs-operand) that LookupCommand did not read past, the word
// after its options, operands and assignments is the command word. It is
// the entry of the command.
func (v *varCodes) arguments(s *Simple, words []CommandWord, c int, readings []CodeReading) *CommandEntry {
	name := base(words[c].Text)
	e := commandNamed(name)
	if e == nil {
		return nil
	}
	operands, skipped := false, 0
	for i := c + 1; i < len(words); i++ {
		w := words[i]
		text := w.Text
		if !w.Known {
			text = literalPrefix(v.s, s.Words[i])
		}
		if !operands && text == "--" && w.Known {
			operands = true
			continue
		}
		if !operands && strings.HasPrefix(text, "-") && text != "-" {
			o, holds := e.option(text)
			switch {
			case o == nil:
			case holds || !w.Known && strings.ContainsRune(text, '='):
				if name != "git" || gitConfigRuns(v.s, s.Words[i], gitOptionLength(text)) {
					readings[i] = o.ValueReading
				}
			case name == "git" && o.Value && i+1 < len(words):
				if gitConfigRuns(v.s, s.Words[i+1], 0) {
					readings[i+1] = o.ValueReading
				}
				i++
			case o.Value && i+1 < len(words):
				j := i + 1
				if o.Cluster && !o.Joined {
					// -c of a shell: the code is the first word after the
					// options and their values (bash -c -x code, bash -c --
					// code, bash -c - code, bash -co pipefail code, bash -c
					// +o pipefail code)
					j += e.optionValues(text, o)
					for j < len(words) && shellOptionWord(words[j]) {
						end := words[j].Text == "--" || words[j].Text == "-"
						j += 1 + e.optionValues(words[j].Text, o)
						if end {
							break
						}
					}
					if j >= len(words) {
						return e
					}
				}
				readings[j] = o.ValueReading
				i = j
				if o.EndsOptions {
					return e // the words after the code are its arguments
				}
			}
			continue
		}
		if e.Has(CommandTraitRunsOperand) {
			switch {
			case skipped < e.Operands:
				skipped++
				continue
			case e.Assignments && w.Known && envAssignment(text):
				continue
			}
			readings[i] = CodeReadingCommandWord // LookupCommand stopped before it
			return e
		}
		if w.Known {
			if sub := subcommandOf(name, e, w.Text); sub != nil {
				e = sub
				continue
			}
		}
		readings[i] = e.ValueReading
	}
	return e
}

// gitConfigRuns is whether git may run the value of the configuration
// that the word w gives to git -c (or --config-env), its key read from the
// byte skip of its literal prefix on: the key is not literal, the word has
// an expansion outside quotes (whose words may add another -c), or the key
// names a program or a command (core.sshCommand, alias.*, *.helper).
// git -c user.name="$V" sets data only.
func gitConfigRuns(script string, w Word, skip int) bool {
	for _, p := range w.Parts {
		if p.Kind != PartLiteral && p.Quote == QuoteNone {
			return true
		}
	}
	prefix := literalPrefix(script, w)
	if skip > len(prefix) {
		return true
	}
	key, _, ok := strings.Cut(prefix[skip:], "=")
	return !ok || gitKeyRuns(key)
}

// gitOptionLength is the length of the option in the word text that holds
// its value too: -ckey=value, --config-env=key=env.
func gitOptionLength(text string) int {
	if strings.HasPrefix(text, "--") {
		return strings.IndexByte(text, '=') + 1
	}
	return 2
}

// gitProgramKeys are the configuration keys, section and last name in
// lower case, whose value git runs or which make git read code from
// elsewhere (include.path, core.hooksPath).
var gitProgramKeys = map[string]bool{
	"core.sshcommand": true, "core.pager": true, "core.editor": true, "core.fsmonitor": true,
	"core.hookspath": true, "core.askpass": true, "core.gitproxy": true, "core.alternaterefscommand": true,
	"core.worktree": true, "sequence.editor": true, "gpg.program": true, "diff.external": true,
	"interactive.difffilter": true, "uploadpack.packobjectshook": true, "web.browser": true,
	"include.path": true, "sendemail.smtpserver": true, "sendemail.tocmd": true, "sendemail.cccmd": true,
	"credential.helper": true,
}

// gitProgramSections are the sections, in lower case, any of whose keys
// may name a program or let git run one (alias.x, pager.log,
// filter.x.smudge, protocol.ext.allow).
var gitProgramSections = map[string]bool{
	"alias": true, "pager": true, "filter": true, "includeif": true, "protocol": true,
	"difftool": true, "mergetool": true, "browser": true, "man": true, "hook": true,
}

// gitProgramNames are the last names, in lower case, of keys in any
// section whose value git runs (credential.<url>.helper,
// diff.<driver>.textconv, remote.<name>.uploadpack).
var gitProgramNames = map[string]bool{
	"helper": true, "command": true, "textconv": true, "driver": true, "program": true,
	"uploadpack": true, "receivepack": true, "proxycommand": true, "cmd": true, "path": true,
}

// gitKeyRuns is whether git may run the value of the configuration key.
func gitKeyRuns(key string) bool {
	section, rest, ok := strings.Cut(key, ".")
	if !ok || section == "" || strings.HasPrefix(key, "-") {
		return true
	}
	section = strings.ToLower(section)
	last := strings.ToLower(rest[strings.LastIndex(rest, ".")+1:])
	return gitProgramSections[section] || gitProgramNames[last] || gitProgramKeys[section+"."+last]
}

// literalPrefix is the text of the literal parts outside quotes at the
// start of w: --eval= of --eval="$V".
func literalPrefix(script string, w Word) string {
	var b strings.Builder
	for _, p := range w.Parts {
		if p.Kind != PartLiteral || p.Quote != QuoteNone {
			break
		}
		b.WriteString(script[p.Span.Start:p.Span.End])
	}
	return b.String()
}

// input reads the heredoc or the here-string of r as what a command that
// runs its input as code reads.
func (v *varCodes) input(r Redirect, depth int) {
	switch {
	case r.Heredoc != nil && !r.Heredoc.Quoted:
		v.parts(r.Heredoc.Parts, CodeReadingCodeInput, depth)
	case r.Op == RedirHereString:
		v.parts(r.Target.Parts, CodeReadingCodeInput, depth)
	default:
		v.redirect(r, depth)
	}
}

func (v *varCodes) redirect(r Redirect, depth int) {
	v.parts(r.Target.Parts, CodeReadingUnset, depth)
	if r.Heredoc != nil && !r.Heredoc.Quoted {
		v.parts(r.Heredoc.Parts, CodeReadingUnset, depth)
	}
}

// parts reads the parts of a word, or of a heredoc's body, read as r (unset:
// as data).
func (v *varCodes) parts(ps []Part, r CodeReading, depth int) {
	for _, p := range ps {
		r := r
		if r == CodeReadingCommandWord && p.Quote != QuoteNone {
			r = CodeReadingUnset // inside quotes, the value names the program
		}
		switch p.Kind {
		case PartParam:
			if r != CodeReadingUnset && v.named(p.Name.String()) {
				v.emit(p.Name, p.Span, r, false)
			}
		case PartParamOp:
			v.paramOp(p, r, depth)
		case PartSubst, PartProcIn, PartProcOut:
			if p.Sub != nil {
				v.list(p.Sub.List, depth)
			}
		case PartArith:
			v.arithmetic(p.Arith, depth)
		}
	}
}

// paramOp reads ${...} by its ParamExpansion: NAME as r where the
// expansion gives the value or a value made from it, but not its length,
// an alternate value (${NAME:+x}) and the transformations by @ that quote
// the value or tell its attributes; the name ${!NAME} names as arithmetic,
// whose subscript bash evaluates; the words that may become the value
// (ParamExpansion.ValueWords) as r, quoted as the ${ } is; the other words
// (a pattern, the message of :?) for what runs in them; and an offset, a
// length or a subscript as arithmetic. A ${ } bash does not read (no
// ParamExpansion) is not read.
func (v *varCodes) paramOp(p Part, r CodeReading, depth int) {
	x := p.Param
	if x == nil || depth >= maxInnerDepth {
		return
	}
	name := x.Name.String()
	if x.Subscript != nil && !v.assoc[name] && isName(name) {
		// the subscript of an array that is not associative is arithmetic,
		// whatever is before the name (${#a[$i]}, ${!a[$i]})
		v.arith(x.Subscript.Span, depth)
	}
	if x.Prefix == ParamPrefixIndirect {
		if x.Subscript == nil && x.All == ParamAllNone && x.Op == ParamOpNone && v.named(name) {
			v.emit(p.Name, p.Span, CodeReadingArithmetic, false)
		}
		return
	}
	if x.Prefix == ParamPrefixLength || !v.named(name) {
		return
	}
	gives := x.Op != ParamOpAlternate
	if x.Op == ParamOpTransform {
		gives = x.Transform == ParamTransformU || x.Transform == ParamTransformLowerU || x.Transform == ParamTransformL || x.Transform == ParamTransformE
	}
	switch {
	case x.Op == ParamOpTransform && x.Transform == ParamTransformP:
		// the value expanded as a prompt string runs its command
		// substitutions (promptvars, on by default), wherever it is
		v.emit(p.Name, p.Span, CodeReadingPromptExpansion, false)
	case r != CodeReadingUnset && gives:
		v.emit(p.Name, p.Span, r, false)
	}
	for _, w := range []*Word{x.Offset, x.Length} {
		if w != nil {
			v.arith(w.Span, depth)
		}
	}
	values := x.ValueWords()
	for _, w := range x.Words {
		wr := CodeReadingUnset
		if len(values) > 0 && w.Span == values[0].Span {
			wr = r
		}
		v.parts(w.Parts, wr, depth+1)
	}
}

// compoundArith reads the expressions of (( )) and for (( ; ; )).
func (v *varCodes) compoundArith(x *Compound, depth int) {
	for _, a := range x.Arith {
		v.arithmetic(a, depth)
	}
}

// arith reads the arithmetic expression at sp: a subscript, or the offset
// or the length of a substring.
func (v *varCodes) arith(sp Span, depth int) {
	v.arithmetic(arithmeticAt(v.s, sp, 0), depth)
}

// arithmetic reads the expression a: its names written without $ as
// arithmetic, but a name that = assigns, whose value is not read; its
// parts as arithmetic, and the scripts of the substitutions in them.
func (v *varCodes) arithmetic(a *Arithmetic, depth int) {
	if a == nil || depth >= maxInnerDepth {
		return
	}
	for _, n := range a.Names {
		if !n.Assigned {
			v.emit(n.Name, n.Span, CodeReadingArithmetic, true)
		}
	}
	v.parts(a.Parts, CodeReadingArithmetic, depth+1)
}

// bareNames reads the names written without $ in the literals of w, which
// arithmetic evaluates as the values of those variables; not a name that
// = assigns (arithNames).
func (v *varCodes) bareNames(w Word) {
	for _, n := range arithNames(v.s, w.Parts) {
		if !n.Assigned {
			v.emit(n.Name, n.Span, CodeReadingArithmetic, true)
		}
	}
}

// assigned is whether what follows a name in arithmetic, after, is an =
// that assigns to the name, whose value is then not read.
func assigned(after string) bool {
	after = strings.TrimLeft(after, " \t")
	return strings.HasPrefix(after, "=") && !strings.HasPrefix(after, "==")
}

// assocNames are the names the declare, typeset and local commands of sc
// declare with -A.
func assocNames(script string, sc *Script) map[string]bool {
	out := map[string]bool{}
	WalkSimple(sc.List, func(s *Simple) {
		ws := WordsOf(script, s)
		if len(ws) == 0 || !ws[0].Known {
			return
		}
		switch ws[0].Text {
		case "declare", "typeset", "local":
		default:
			return
		}
		assoc := false
		for _, w := range ws[1:] {
			switch {
			case !w.Known:
			case strings.HasPrefix(w.Text, "-"):
				assoc = assoc || strings.ContainsRune(w.Text, 'A')
			case assoc:
				n := w.Text
				if i := strings.IndexAny(n, "=["); i >= 0 {
					n = n[:i]
				}
				out[n] = true
			}
		}
	})
	return out
}
