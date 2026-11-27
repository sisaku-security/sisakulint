package shell

import "strings"

// ParamExpansion is a parameter expansion with an operator, ${...}
// (bashref, "Shell Parameter Expansion"): the prefix before the name, the
// name, its subscript, the operator and the words after it. Words are the
// word of :- - := = :? ? :+ + (one, maybe empty), the pattern of # ## % %%
// ^ ^^ , ,, ~ ~~ (none when it is empty), and the pattern and the string
// of / // /# /% (the string is not there without its /). Offset and Length
// are the two words of a substring. The words are read as bash reads them
// inside the ${ }: inside "..." when the ${ } is, with their own quotes and
// expansions; the parts of their substitutions have their Sub.
type ParamExpansion struct {
	Prefix    ParamPrefix
	Name      VarName
	Subscript *Word // the word inside [ ], unless it is @ or * (All)
	All       ParamAll
	Op        ParamOperator
	Colon     bool // :- := :? :+ test for null as well as unset
	Transform ParamTransform
	Words     []Word
	Offset    *Word
	Length    *Word
}

// ParamPrefix is what comes before the name of a ${...}.
type ParamPrefix uint8

const (
	ParamPrefixNone     ParamPrefix = iota
	ParamPrefixLength               // ${#NAME}
	ParamPrefixIndirect             // ${!NAME}, ${!prefix*}, ${!name[@]}
)

var paramPrefixNames = [...]string{"ParamPrefixNone", "ParamPrefixLength", "ParamPrefixIndirect"}

func (p ParamPrefix) String() string { return paramPrefixNames[p] }

// ParamAll is the subscript @ or * of an array, or the * or @ after the
// prefix of ${!prefix*}.
type ParamAll uint8

const (
	ParamAllNone ParamAll = iota
	ParamAllAt
	ParamAllStar
)

var paramAllNames = [...]string{"ParamAllNone", "ParamAllAt", "ParamAllStar"}

func (a ParamAll) String() string { return paramAllNames[a] }

// ParamOperator is the operator of a ${...}.
type ParamOperator uint8

const (
	ParamOpNone                ParamOperator = iota
	ParamOpDefault                           // :- -
	ParamOpAssign                            // := =
	ParamOpError                             // :? ?
	ParamOpAlternate                         // :+ +
	ParamOpSubstring                         // :offset:length
	ParamOpRemovePrefix                      // #
	ParamOpRemoveLongestPrefix               // ##
	ParamOpRemoveSuffix                      // %
	ParamOpRemoveLongestSuffix               // %%
	ParamOpReplace                           // /
	ParamOpReplaceAll                        // //
	ParamOpReplacePrefix                     // /#
	ParamOpReplaceSuffix                     // /%
	ParamOpUpperFirst                        // ^
	ParamOpUpperAll                          // ^^
	ParamOpLowerFirst                        // ,
	ParamOpLowerAll                          // ,,
	ParamOpToggleFirst                       // ~ (not in bashref; bash 5.3 has it)
	ParamOpToggleAll                         // ~~
	ParamOpTransform                         // @ and a letter (Transform)
)

var paramOperatorNames = [...]string{"ParamOpNone", "ParamOpDefault", "ParamOpAssign", "ParamOpError", "ParamOpAlternate", "ParamOpSubstring",
	"ParamOpRemovePrefix", "ParamOpRemoveLongestPrefix", "ParamOpRemoveSuffix", "ParamOpRemoveLongestSuffix",
	"ParamOpReplace", "ParamOpReplaceAll", "ParamOpReplacePrefix", "ParamOpReplaceSuffix",
	"ParamOpUpperFirst", "ParamOpUpperAll", "ParamOpLowerFirst", "ParamOpLowerAll", "ParamOpToggleFirst", "ParamOpToggleAll", "ParamOpTransform"}

func (o ParamOperator) String() string { return paramOperatorNames[o] }

// ParamTransform is the letter after @ in ${NAME@letter}.
type ParamTransform uint8

const (
	ParamTransformUnset ParamTransform = iota
	ParamTransformU
	ParamTransformLowerU // u
	ParamTransformL
	ParamTransformQ
	ParamTransformE
	ParamTransformP
	ParamTransformA
	ParamTransformK
	ParamTransformLowerA // a
	ParamTransformLowerK // k
)

// paramTransformLetters are the letters of ParamTransform, in its order.
const paramTransformLetters = " UuLQEPAKak"

func (t ParamTransform) String() string { return string(paramTransformLetters[t]) }

// paramOps are the operators after the name and its subscript, by how
// they are written, longest first.
var paramOps = []struct {
	s     string
	op    ParamOperator
	colon bool
}{
	{":-", ParamOpDefault, true}, {":=", ParamOpAssign, true}, {":?", ParamOpError, true}, {":+", ParamOpAlternate, true},
	{"-", ParamOpDefault, false}, {"=", ParamOpAssign, false}, {"?", ParamOpError, false}, {"+", ParamOpAlternate, false},
	{":", ParamOpSubstring, false},
	{"##", ParamOpRemoveLongestPrefix, false}, {"#", ParamOpRemovePrefix, false},
	{"%%", ParamOpRemoveLongestSuffix, false}, {"%", ParamOpRemoveSuffix, false},
	{"//", ParamOpReplaceAll, false}, {"/#", ParamOpReplacePrefix, false}, {"/%", ParamOpReplaceSuffix, false}, {"/", ParamOpReplace, false},
	{"^^", ParamOpUpperAll, false}, {"^", ParamOpUpperFirst, false},
	{",,", ParamOpLowerAll, false}, {",", ParamOpLowerFirst, false},
	{"~~", ParamOpToggleAll, false}, {"~", ParamOpToggleFirst, false},
	{"@", ParamOpTransform, false},
}

// maxParamDepth is how deep ${...} nest in the words after their operators,
// and $(( )) in each other (arithmeticAt), before they are no longer read.
const maxParamDepth = 64

// paramExpansion reads the inside of the ${ } at sp (the bytes between ${
// and }), whose part is inside the quote q; nil when it is not an
// expansion with an operator that bash reads.
func (l *tokenizer) paramExpansion(sp Span, q Quote) *ParamExpansion {
	if l.paramDepth >= maxParamDepth {
		return nil
	}
	s := l.s
	p := &ParamExpansion{}
	i := sp.Start
	if i < sp.End && (s[i] == '#' || s[i] == '!') && i+1 < sp.End {
		p.Prefix = ParamPrefixLength
		if s[i] == '!' {
			p.Prefix = ParamPrefixIndirect
		}
		i++
	}
	j := i
	switch {
	case j < sp.End && isNameStart(s[j]):
		for j < sp.End && isNameByte(s[j]) {
			j++
		}
	case j < sp.End && '0' <= s[j] && s[j] <= '9':
		for j < sp.End && '0' <= s[j] && s[j] <= '9' {
			j++
		}
	case j < sp.End && strings.IndexByte("@*#?-$!", s[j]) >= 0:
		j++
	default:
		return nil
	}
	p.Name = VarName{s[i:j]}
	i = j
	if i < sp.End && s[i] == '[' {
		end := topLevel(s, i+1, sp.End, true, func(c byte) bool { return c == ']' })
		if end >= sp.End {
			return nil
		}
		switch inside := s[i+1 : end]; inside {
		case "@":
			p.All = ParamAllAt
		case "*":
			p.All = ParamAllStar
		default:
			w, ok := l.operand(Span{i + 1, end}, QuoteNone, false)
			if !ok {
				return nil
			}
			p.Subscript = &w
		}
		i = end + 1
	}
	if p.Prefix == ParamPrefixIndirect && p.All == ParamAllNone && i < sp.End && (s[i] == '*' || s[i] == '@') && i+1 == sp.End {
		p.All = ParamAllStar // ${!prefix*}, ${!prefix@}
		if s[i] == '@' {
			p.All = ParamAllAt
		}
		i++
	}
	if i == sp.End {
		return p
	}
	rest := s[i:sp.End]
	for _, o := range paramOps {
		if strings.HasPrefix(rest, o.s) {
			p.Op, p.Colon = o.op, o.colon
			i += len(o.s)
			break
		}
	}
	if p.Op == ParamOpNone {
		return nil
	}
	if p.Prefix == ParamPrefixLength {
		return nil // bash refuses ${#NAME:-x}: bad substitution
	}
	ok := true
	// the words of :- := :? :+ read ' as a byte inside "...", and patterns
	// and the string of / read it as a quote (bash 5.3)
	word := func(from, to int, quotes bool) *Word {
		wq := q
		if quotes {
			wq = QuoteNone // a pattern: its quotes and globs as outside "..."
		}
		w, wok := l.operand(Span{from, to}, wq, quotes)
		ok = ok && wok
		return &w
	}
	switch p.Op {
	case ParamOpTransform:
		k := strings.IndexByte(paramTransformLetters[1:], s[min(i, sp.End-1)])
		if i+1 != sp.End || k < 0 {
			return nil
		}
		p.Transform = ParamTransform(k + 1)
	case ParamOpSubstring:
		ternary := 0 // a ? of the offset pairs with the : after it
		colon := topLevel(s, i, sp.End, false, func(c byte) bool {
			switch {
			case c == '?':
				ternary++
			case c == ':' && ternary > 0:
				ternary--
			case c == ':':
				return true
			}
			return false
		})
		if colon == i {
			return nil // bash refuses ${NAME:}: bad substitution
		}
		p.Offset = word(i, min(colon, sp.End), false)
		if colon < sp.End {
			p.Length = word(colon+1, sp.End, false)
		}
	case ParamOpReplace, ParamOpReplaceAll, ParamOpReplacePrefix, ParamOpReplaceSuffix:
		slash := topLevel(s, i, sp.End, false, func(c byte) bool { return c == '/' })
		p.Words = append(p.Words, *word(i, min(slash, sp.End), true))
		if slash < sp.End {
			p.Words = append(p.Words, *word(slash+1, sp.End, true))
		}
	case ParamOpDefault, ParamOpAssign, ParamOpError, ParamOpAlternate:
		p.Words = append(p.Words, *word(i, sp.End, false))
	default: // the patterns of # % ^ , ~
		if i < sp.End {
			p.Words = append(p.Words, *word(i, sp.End, true))
		}
	}
	if !ok {
		return nil
	}
	return p
}

// topLevel is the first index from i up to end whose byte stop takes,
// outside quotes, backslashes and expansions, and outside [ ] when
// brackets (the words of a subscript); end when there is none. bash ends
// the pattern of / at the first / outside these, inside [ ] too.
func topLevel(s string, i, end int, brackets bool, stop func(byte) bool) int {
	depth := 0
	for i < end {
		c := s[i]
		switch {
		case c == '\\':
			i += 2
			continue
		case c == '\'':
			k := strings.IndexByte(s[i+1:end], '\'')
			if k < 0 {
				return end
			}
			i += k + 2
			continue
		case c == '"':
			i = skipDouble(s, i+1, end)
			continue
		case c == '`':
			i = skipBackquote(s, i+1, end)
			continue
		case c == '$' && i+1 < end && (s[i+1] == '(' || s[i+1] == '{'):
			i = skipGroup(s, i+2, end, s[i+1])
			continue
		case brackets && c == '[':
			depth++
		case brackets && c == ']' && depth > 0:
			depth--
		case depth == 0 && stop(c):
			return i
		}
		i++
	}
	return end
}

// skipDouble is the index after the " that closes the "..." whose bytes
// start at i, or end.
func skipDouble(s string, i, end int) int {
	for i < end {
		switch c := s[i]; {
		case c == '\\':
			i += 2
		case c == '"':
			return i + 1
		case c == '`':
			i = skipBackquote(s, i+1, end)
		case c == '$' && i+1 < end && (s[i+1] == '(' || s[i+1] == '{'):
			i = skipGroup(s, i+2, end, s[i+1])
		default:
			i++
		}
	}
	return end
}

// skipBackquote is the index after the ` that closes the ` ` whose bytes
// start at i, or end.
func skipBackquote(s string, i, end int) int {
	for i < end {
		switch s[i] {
		case '\\':
			i += 2
		case '`':
			return i + 1
		default:
			i++
		}
	}
	return end
}

// skipGroup is the index after the ) or } that closes the $( or ${ (open
// is ( or {) whose bytes start at i, or end.
func skipGroup(s string, i, end int, open byte) int {
	closer := byte(')')
	if open == '{' {
		closer = '}'
	}
	depth := 1
	for i < end {
		switch c := s[i]; {
		case c == '\\':
			i += 2
			continue
		case c == '\'':
			k := strings.IndexByte(s[i+1:end], '\'')
			if k < 0 {
				return end
			}
			i += k + 2
			continue
		case c == '"':
			i = skipDouble(s, i+1, end)
			continue
		case c == '`':
			i = skipBackquote(s, i+1, end)
			continue
		case c == '$' && i+1 < end && (s[i+1] == '(' || s[i+1] == '{'):
			i = skipGroup(s, i+2, end, s[i+1])
			continue
		case c == open:
			depth++
		case c == closer:
			depth--
			if depth == 0 {
				return i + 1
			}
		}
		i++
	}
	return end
}

// operand reads the bytes at sp, a word inside a ${ } whose part is inside
// the quote q, as one word: blanks and operators are bytes of it, and its
// quotes and expansions are read as in a word (inside "..." when q is
// QuoteDouble, where ' is a byte unless quotes). $'...' is decoded inside
// "..." too (extquote, on by default). It is false when the bytes do not
// make a word bash reads to its end.
func (l *tokenizer) operand(sp Span, q Quote, quotes bool) (Word, bool) {
	o := &tokenizer{s: l.s, i: sp.Start, end: sp.End, stack: []lexState{inOperand}, starts: []int{sp.Start}, depths: []int{1}, outerQuote: q, singleQuotes: quotes || q == QuoteNone, paramDepth: l.paramDepth + 1}
	f := &frame{wordStart: true}
	o.frames = []*frame{f}
	o.startWord()
	o.run()
	if o.poisoned || len(o.stack) != 1 || f.cur == nil {
		return Word{id: -1, Span: sp}, false
	}
	w := *f.cur
	w.Span = sp
	return w, true
}

// operandByte reads a byte of the word of operand.
func (l *tokenizer) operandByte() {
	switch c := l.s[l.i]; {
	case c == '\\':
		l.lit(2)
	case c == '"':
		l.openQuote(inDouble, 1)
	case c == '\'' && l.singleQuotes:
		l.openQuote(inSingle, 1)
	case l.expansion(true):
	case c == '$' && l.param():
	default:
		l.lit(1)
	}
}

// ParamValue is what a ${...} writes of the value of its name (bashref,
// "Shell Parameter Expansion").
type ParamValue uint8

const (
	ParamValueUnset ParamValue = iota
	// ParamValueWhole: the value as it is: no operator, a subscript, or :-
	// - := = :? ? when the name is set (the words of :- - := = when it is
	// not: ValueWords).
	ParamValueWhole
	// ParamValueChanged: a value made from the value: a substring, a
	// pattern removed or replaced, the case changed, and @U @u @L @E @P
	// (Change).
	ParamValueChanged
	// ParamValueQuoted: the value quoted to be read again as input (@Q @A
	// @K @k), with no line break of the value.
	ParamValueQuoted
	// ParamValueNone: none of the value: the length (${#NAME}), the
	// attributes (@a), the names of ${!prefix*} and the keys of
	// ${!name[@]}, and :+ + (only their words: ValueWords).
	ParamValueNone
	// ParamValueIndirect: the value of the variable the value names
	// (${!NAME}).
	ParamValueIndirect
)

var paramValueNames = [...]string{"ParamValueUnset", "ParamValueWhole", "ParamValueChanged", "ParamValueQuoted", "ParamValueNone", "ParamValueIndirect"}

func (v ParamValue) String() string { return paramValueNames[v] }

// ParamChange is how a ParamValueChanged value is made from the value.
type ParamChange uint8

const (
	ParamChangeUnset ParamChange = iota
	ParamChangeSubstring
	ParamChangePrefixRemoval
	ParamChangeSuffixRemoval
	ParamChangeReplacement
	ParamChangeCaseChange
	ParamChangeOther // @E and @P
)

var paramChangeNames = [...]string{"ParamChangeUnset", "ParamChangeSubstring", "ParamChangePrefixRemoval", "ParamChangeSuffixRemoval", "ParamChangeReplacement", "ParamChangeCaseChange", "ParamChangeOther"}

func (c ParamChange) String() string { return paramChangeNames[c] }

// Value is what p writes of the value of its name.
func (p *ParamExpansion) Value() ParamValue {
	switch {
	case p.Prefix == ParamPrefixLength:
		return ParamValueNone
	case p.Prefix == ParamPrefixIndirect && p.All != ParamAllNone:
		return ParamValueNone // the names of ${!prefix*}, the keys of ${!name[@]}
	case p.Prefix == ParamPrefixIndirect:
		return ParamValueIndirect
	}
	switch p.Op {
	case ParamOpNone, ParamOpDefault, ParamOpAssign, ParamOpError:
		return ParamValueWhole
	case ParamOpAlternate:
		return ParamValueNone
	case ParamOpTransform:
		switch p.Transform {
		case ParamTransformQ, ParamTransformA, ParamTransformK, ParamTransformLowerK:
			return ParamValueQuoted
		case ParamTransformLowerA:
			return ParamValueNone
		}
	}
	return ParamValueChanged
}

// Change is how p makes its value from the value of its name, when Value
// is ParamValueChanged.
func (p *ParamExpansion) Change() ParamChange {
	if p.Value() != ParamValueChanged {
		return ParamChangeUnset
	}
	switch p.Op {
	case ParamOpSubstring:
		return ParamChangeSubstring
	case ParamOpRemovePrefix, ParamOpRemoveLongestPrefix:
		return ParamChangePrefixRemoval
	case ParamOpRemoveSuffix, ParamOpRemoveLongestSuffix:
		return ParamChangeSuffixRemoval
	case ParamOpReplace, ParamOpReplaceAll, ParamOpReplacePrefix, ParamOpReplaceSuffix:
		return ParamChangeReplacement
	case ParamOpTransform:
		if p.Transform == ParamTransformE || p.Transform == ParamTransformP {
			return ParamChangeOther
		}
	}
	return ParamChangeCaseChange
}

// ValueWords are the words of p whose expansion may become what p writes:
// the word of :- - := = :+ +, and the string of / // /# /%. The word of :?
// and ? is a message on the standard error, and patterns match the value.
func (p *ParamExpansion) ValueWords() []Word {
	switch p.Op {
	case ParamOpDefault, ParamOpAssign, ParamOpAlternate:
		return p.Words
	case ParamOpReplace, ParamOpReplaceAll, ParamOpReplacePrefix, ParamOpReplaceSuffix:
		if len(p.Words) == 2 {
			return p.Words[1:]
		}
	}
	return nil
}

// cutsLines is whether p removes from its value every line break: the
// longest end that starts at a character of a set that holds the line
// break (${T%%[[:space:]]*}, ${T%%[[:space:]_]*}, ${T%%$'\n'*}), or the
// longest start that ends at one (${T##*[[:space:]]}), so that it writes
// no line break.
func (p *ParamExpansion) cutsLines(script string) bool {
	if p.Prefix != ParamPrefixNone || len(p.Words) != 1 {
		return false
	}
	pat, ok := patternChars(script, p.Words[0])
	if !ok {
		return false
	}
	star := func(c patChar) bool { return c.c == '*' && !c.quoted }
	switch n := len(pat); {
	case p.Op == ParamOpRemoveLongestSuffix && n >= 2 && star(pat[n-1]):
		return matchesLF(pat[:n-1])
	case p.Op == ParamOpRemoveLongestPrefix && n >= 2 && star(pat[0]):
		return matchesLF(pat[1:])
	}
	return false
}

// patChar is a byte of a pattern, and whether a quote made it literal.
type patChar struct {
	c      byte
	quoted bool
}

// patternChars are the bytes of the pattern word w as bash matches them;
// false for a word that is not of literals only.
func patternChars(script string, w Word) ([]patChar, bool) {
	var out []patChar
	for _, q := range w.Parts {
		if q.Kind != PartLiteral {
			return nil, false
		}
		t := script[q.Span.Start:q.Span.End]
		switch q.Quote {
		case QuoteANSI:
			t = ansiDecode(t)
		case QuoteNone:
			for i := 0; i < len(t); i++ {
				if t[i] == '\\' && i+1 < len(t) {
					i++
					out = append(out, patChar{t[i], true})
					continue
				}
				out = append(out, patChar{t[i], false})
			}
			continue
		default:
			u, ok := unescape(t, q.Quote, false)
			if !ok {
				return nil, false
			}
			t = u
		}
		for i := 0; i < len(t); i++ {
			out = append(out, patChar{t[i], true})
		}
	}
	return out, true
}

// ansiDecode is what bash makes of the bytes inside $'...' for the escapes
// that stand for one byte (\n, \t, \r, \\, \', \", \NNN in octal); other
// escapes are kept as they are.
func ansiDecode(t string) string {
	var b strings.Builder
	for i := 0; i < len(t); i++ {
		if t[i] != '\\' || i+1 == len(t) {
			b.WriteByte(t[i])
			continue
		}
		i++
		switch d := t[i]; {
		case d == 'n':
			b.WriteByte('\n')
		case d == 't':
			b.WriteByte('\t')
		case d == 'r':
			b.WriteByte('\r')
		case d == '\\' || d == '\'' || d == '"':
			b.WriteByte(d)
		case d >= '0' && d <= '7':
			v, j := 0, i
			for ; j < len(t) && j < i+3 && t[j] >= '0' && t[j] <= '7'; j++ {
				v = v*8 + int(t[j]-'0')
			}
			b.WriteByte(byte(v))
			i = j - 1
		default:
			b.WriteByte('\\')
			b.WriteByte(d)
		}
	}
	return b.String()
}

// matchesLF is whether pat is one character, and the line break is it: a
// quoted line break, or a bracket expression that is not negated and holds
// the line break or a class of it ([:space:], [:cntrl:]).
func matchesLF(pat []patChar) bool {
	if len(pat) == 1 {
		return pat[0].c == '\n' && pat[0].quoted
	}
	n := len(pat)
	if n < 3 || pat[0].c != '[' || pat[0].quoted || pat[n-1].c != ']' || pat[n-1].quoted {
		return false
	}
	in := pat[1 : n-1]
	if in[0].c == '!' || in[0].c == '^' {
		return false
	}
	found := false
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch {
		case c.c == '[' && !c.quoted && i+1 < len(in) && in[i+1].c == ':':
			j := i + 2
			for ; j+1 < len(in) && !(in[j].c == ':' && in[j+1].c == ']'); j++ {
			}
			if j+1 >= len(in) {
				return false
			}
			var name []byte
			for _, x := range in[i+2 : j] {
				name = append(name, x.c)
			}
			if string(name) == "space" || string(name) == "cntrl" {
				found = true
			}
			i = j + 1
		case c.c == ']' && !c.quoted && i > 0:
			// a ] that ends the expression early: what follows is
			// not inside it
			return false
		case c.c == '[' && !c.quoted:
			return false // [. .] and [= =]: not read here
		case c.c == '-' && !c.quoted && i > 0 && i+1 < len(in):
			return false // a range: not read here
		case c.c == '\n':
			found = true
		}
	}
	return found
}
