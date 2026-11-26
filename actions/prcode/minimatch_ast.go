package prcode

import (
	"slices"
	"strings"
)

// mmAST is the AST of src/ast.ts of minimatch v9.0.3
// (https://github.com/isaacs/minimatch/blob/v9.0.3/src/ast.ts) for one
// part of a pattern, with no options: a part with no type, of strings and
// extglobs, or an extglob (typ one of !?+*@) whose parts are parts with no
// type, one for each alternative.
type mmAST struct {
	typ         rune
	root        *mmAST
	parent      *mmAST
	parentIndex int
	parts       []mmPart
	hasMagic    bool
	emptyExt    bool
	str         *string
	// on the root: the negative extglobs, whether the tails were appended
	// to them, and whether the part is read differently by the releases
	negs       []*mmAST
	filledNegs bool
	unknown    bool
}

// mmPart is a string or an AST.
type mmPart struct {
	s string
	a *mmAST
}

func newMMAST(typ rune, parent *mmAST) *mmAST {
	a := &mmAST{typ: typ, parent: parent}
	if typ != 0 {
		a.hasMagic = true
	}
	if parent == nil {
		a.root = a
	} else {
		a.root = parent.root
		a.parentIndex = len(parent.parts)
	}
	if typ == '!' && !a.root.filledNegs {
		a.root.negs = append(a.root.negs, a)
	}
	return a
}

func isExtglobType(c rune) bool { return strings.ContainsRune("!?+*@", c) }

func (a *mmAST) push(ps ...mmPart) {
	for _, p := range ps {
		if p.a == nil && p.s == "" {
			continue
		}
		a.parts = append(a.parts, p)
	}
}

func (a *mmAST) String() string {
	if a.str != nil {
		return *a.str
	}
	var b strings.Builder
	if a.typ != 0 {
		b.WriteRune(a.typ)
		b.WriteByte('(')
	}
	for i, p := range a.parts {
		if a.typ != 0 && i > 0 {
			b.WriteByte('|')
		}
		if p.a != nil {
			b.WriteString(p.a.String())
		} else {
			b.WriteString(p.s)
		}
	}
	if a.typ != 0 {
		b.WriteByte(')')
	}
	s := b.String()
	a.str = &s
	return s
}

func (a *mmAST) fillNegs() {
	_ = a.String() // fills the cache of every node, as fillNegs of src/ast.ts does
	a.filledNegs = true
	for len(a.negs) > 0 {
		n := a.negs[len(a.negs)-1]
		a.negs = a.negs[:len(a.negs)-1]
		p := n
		for pp := p.parent; pp != nil; p, pp = pp, pp.parent {
			for i := p.parentIndex + 1; pp.typ == 0 && i < len(pp.parts); i++ {
				for _, part := range n.parts {
					part.a.copyIn(pp.parts[i])
				}
			}
		}
	}
}

func (a *mmAST) isStart() bool {
	if a.root == a {
		return true
	}
	if !a.parent.isStart() {
		return false
	}
	if a.parentIndex == 0 {
		return true
	}
	for i := 0; i < a.parentIndex; i++ {
		if pp := a.parent.parts[i]; pp.a == nil || pp.a.typ != '!' {
			return false
		}
	}
	return true
}

func (a *mmAST) isEnd() bool {
	if a.root == a {
		return true
	}
	if a.parent.typ == '!' {
		return true
	}
	if !a.parent.isEnd() {
		return false
	}
	if a.typ == 0 {
		return a.parent.isEnd()
	}
	return a.parentIndex == len(a.parent.parts)-1
}

func (a *mmAST) copyIn(p mmPart) {
	if p.a == nil {
		a.push(p)
		return
	}
	a.push(mmPart{a: p.a.clone(a)})
}

func (a *mmAST) clone(parent *mmAST) *mmAST {
	c := newMMAST(a.typ, parent)
	for _, p := range a.parts {
		c.copyIn(p)
	}
	return c
}

// parseMMAST is AST.fromGlob. An extglob inside an extglob marks the root
// unknown.
func parseMMAST(pattern string) *mmAST {
	a := newMMAST(0, nil)
	parseMMASTAt([]rune(pattern), a, 0)
	return a
}

func parseMMASTAt(str []rune, ast *mmAST, pos int) int {
	escaping, inBrace, braceStart, braceNeg := false, false, -1, false
	if ast.typ == 0 {
		i, acc := pos, ""
		for i < len(str) {
			c := str[i]
			i++
			if escaping || c == '\\' {
				escaping = !escaping
				acc += string(c)
				continue
			}
			if inBrace {
				if i == braceStart+1 {
					if c == '^' || c == '!' {
						braceNeg = true
					}
				} else if c == ']' && !(i == braceStart+2 && braceNeg) {
					inBrace = false
				}
				acc += string(c)
				continue
			} else if c == '[' {
				inBrace, braceStart, braceNeg = true, i, false
				acc += string(c)
				continue
			}
			if isExtglobType(c) && i < len(str) && str[i] == '(' {
				ast.push(mmPart{s: acc})
				acc = ""
				ext := newMMAST(c, ast)
				i = parseMMASTAt(str, ext, i)
				ast.push(mmPart{a: ext})
				continue
			}
			acc += string(c)
		}
		ast.push(mmPart{s: acc})
		return i
	}
	i := pos + 1
	part := newMMAST(0, ast)
	var parts []mmPart
	acc := ""
	for i < len(str) {
		c := str[i]
		i++
		if escaping || c == '\\' {
			escaping = !escaping
			acc += string(c)
			continue
		}
		if inBrace {
			if i == braceStart+1 {
				if c == '^' || c == '!' {
					braceNeg = true
				}
			} else if c == ']' && !(i == braceStart+2 && braceNeg) {
				inBrace = false
			}
			acc += string(c)
			continue
		} else if c == '[' {
			inBrace, braceStart, braceNeg = true, i, false
			acc += string(c)
			continue
		}
		if isExtglobType(c) && i < len(str) && str[i] == '(' {
			ast.root.unknown = true // an extglob inside an extglob
			part.push(mmPart{s: acc})
			acc = ""
			ext := newMMAST(c, part)
			part.push(mmPart{a: ext})
			i = parseMMASTAt(str, ext, i)
			continue
		}
		if c == '|' {
			part.push(mmPart{s: acc})
			acc = ""
			parts = append(parts, mmPart{a: part})
			part = newMMAST(0, ast)
			continue
		}
		if c == ')' {
			if acc == "" && len(ast.parts) == 0 {
				ast.emptyExt = true
			}
			part.push(mmPart{s: acc})
			acc = ""
			ast.push(append(parts, mmPart{a: part})...)
			return i
		}
		acc += string(c)
	}
	// an unfinished extglob is not an extglob
	ast.typ = 0
	ast.hasMagic = false
	ast.parts = []mmPart{{s: string(str[pos-1:])}}
	return i
}

// The parts of the regular expressions that src/ast.ts builds.
const (
	startNoTraversal = `(?!(?:^|/)\.\.?(?:$|/))`
	startNoDot       = `(?!\.)`
	qmark            = `[^/]`
	star             = qmark + `*?`
	starNoEmpty      = qmark + `+?`
)

// regExpEscape is s.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&').
func regExpEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`-[]{}()*+?.,\^$|#`, r) || isJSSpace(r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isJSSpace is \s of a JavaScript regular expression.
func isJSSpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\v', '\f', '\r', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return 0x2000 <= r && r <= 0x200a
}

// toRegExpSource is AST.toRegExpSource: the source of the regular
// expression, the string to compare when there is no magic, and whether
// there is magic.
func (a *mmAST) toRegExpSource(allowDot bool) (string, string, bool) {
	if a.root == a {
		a.fillNegs()
	}
	if a.typ == 0 {
		noEmpty := a.isStart() && a.isEnd()
		if noEmpty && slices.ContainsFunc(a.parts, func(p mmPart) bool { return p.a != nil }) && slices.ContainsFunc(a.parts, func(p mmPart) bool { return p.a == nil && p.s == "*" }) {
			// 9.0.3 reads the * as one or more characters, 10.2 as any
			// (@(foo)* matches foo only in 10.2)
			a.root.unknown = true
		}
		var src strings.Builder
		for _, p := range a.parts {
			var re string
			var magic bool
			if p.a == nil {
				re, _, magic = parseMMGlob(a.root, p.s, a.hasMagic, noEmpty)
			} else {
				re, _, magic = p.a.toRegExpSource(allowDot)
			}
			a.hasMagic = a.hasMagic || magic
			src.WriteString(re)
		}
		s := src.String()
		start := ""
		if a.isStart() && len(a.parts) > 0 && a.parts[0].a == nil {
			dotTravAllowed := len(a.parts) == 1 && (a.parts[0].s == "." || a.parts[0].s == "..")
			if !dotTravAllowed {
				aps := func(i int) bool { return i < len(s) && (s[i] == '[' || s[i] == '.') }
				needNoTrav := allowDot && aps(0) ||
					strings.HasPrefix(s, `\.`) && aps(2) ||
					strings.HasPrefix(s, `\.\.`) && aps(4)
				needNoDot := !allowDot && aps(0)
				switch {
				case needNoTrav:
					start = startNoTraversal
				case needNoDot:
					start = startNoDot
				}
			}
		}
		end := ""
		if a.isEnd() && a.root.filledNegs && a.parent != nil && a.parent.typ == '!' {
			end = `(?:$|\/)`
		}
		return start + s + end, mmUnescape(s), a.hasMagic
	}
	repeated := a.typ == '*' || a.typ == '+'
	start := "(?:"
	if a.typ == '!' {
		start = "(?:(?!(?:"
	}
	body := a.partsToRegExp(allowDot)
	if a.isStart() && a.isEnd() && body == "" && a.typ != '!' {
		s := a.String()
		a.parts = []mmPart{{s: s}}
		a.typ = 0
		a.hasMagic = false
		return s, mmUnescape(a.String()), false
	}
	bodyDotAllowed := ""
	if repeated && !allowDot {
		bodyDotAllowed = a.partsToRegExp(true)
	}
	if bodyDotAllowed == body {
		bodyDotAllowed = ""
	}
	if bodyDotAllowed != "" {
		body = "(?:" + body + ")(?:" + bodyDotAllowed + ")*?"
	}
	var final string
	if a.typ == '!' && a.emptyExt {
		if a.isStart() && !allowDot {
			final = startNoDot
		}
		final += starNoEmpty
	} else {
		var closing string
		switch {
		case a.typ == '!':
			closing = "))"
			if a.isStart() && !allowDot {
				closing += startNoDot
			}
			closing += star + ")"
		case a.typ == '@':
			closing = ")"
		case a.typ == '?':
			closing = ")?"
		case a.typ == '+' && bodyDotAllowed != "":
			closing = ")"
		case a.typ == '*' && bodyDotAllowed != "":
			closing = ")?"
		default:
			closing = ")" + string(a.typ)
		}
		final = start + body + closing
	}
	a.hasMagic = true
	return final, mmUnescape(body), true
}

func (a *mmAST) partsToRegExp(dot bool) string {
	var res []string
	for _, p := range a.parts {
		re, _, _ := p.a.toRegExpSource(dot)
		if a.isStart() && a.isEnd() && re == "" {
			continue
		}
		res = append(res, re)
	}
	return strings.Join(res, "|")
}

// parseMMGlob is AST.#parseGlob of a string part.
func parseMMGlob(root *mmAST, globText string, hasMagic, noEmpty bool) (string, string, bool) {
	glob := []rune(globText)
	escaping := false
	var re strings.Builder
	for i := 0; i < len(glob); i++ {
		c := glob[i]
		if escaping {
			escaping = false
			if strings.ContainsRune(`().*{}+?[]^$\!`, c) {
				re.WriteByte('\\')
			}
			re.WriteRune(c)
			continue
		}
		if c == '\\' {
			if i == len(glob)-1 {
				re.WriteString(`\\`)
			} else {
				escaping = true
			}
			continue
		}
		if c == '[' {
			src, posix, consumed, magic := parseMMClass(glob, i)
			if posix {
				root.unknown = true
			}
			if consumed > 0 {
				re.WriteString(src)
				i += consumed - 1
				hasMagic = hasMagic || magic
				continue
			}
		}
		if c == '*' {
			if noEmpty && globText == "*" {
				re.WriteString(starNoEmpty)
			} else {
				re.WriteString(star)
			}
			hasMagic = true
			continue
		}
		if c == '?' {
			re.WriteString(qmark)
			hasMagic = true
			continue
		}
		re.WriteString(regExpEscape(string(c)))
	}
	return re.String(), mmUnescape(globText), hasMagic
}

// posixClasses are the POSIX classes of src/brace-expressions.ts.
var posixClasses = []string{"[:alnum:]", "[:alpha:]", "[:ascii:]", "[:blank:]", "[:cntrl:]", "[:digit:]", "[:graph:]", "[:lower:]", "[:print:]", "[:punct:]", "[:space:]", "[:upper:]", "[:word:]", "[:xdigit:]"}

// braceEscape is s.replace(/[[\]\\-]/g, '\\$&').
func braceEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(`[]\-`, s[i]) >= 0 {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// parseMMClass is parseClass of src/brace-expressions.ts for the [ at
// pos: the source, whether it has a POSIX class, the bytes consumed (0
// when it is not a class) and whether it is magic.
func parseMMClass(glob []rune, pos int) (string, bool, int, bool) {
	var ranges []string
	i := pos + 1
	sawStart, escaping, negate, endPos, rangeStart := false, false, false, pos, ""
	for i < len(glob) {
		c := glob[i]
		if (c == '!' || c == '^') && i == pos+1 {
			negate = true
			i++
			continue
		}
		if c == ']' && sawStart && !escaping {
			endPos = i + 1
			break
		}
		sawStart = true
		if c == '\\' && !escaping {
			escaping = true
			i++
			continue
		}
		if c == '[' && !escaping {
			for _, cls := range posixClasses {
				if strings.HasPrefix(string(glob[i:]), cls) {
					return "", true, 0, false
				}
			}
		}
		escaping = false
		if rangeStart != "" {
			if string(c) > rangeStart {
				ranges = append(ranges, braceEscape(rangeStart)+"-"+braceEscape(string(c)))
			} else if string(c) == rangeStart {
				ranges = append(ranges, braceEscape(string(c)))
			}
			rangeStart = ""
			i++
			continue
		}
		if strings.HasPrefix(string(glob[i+1:]), "-]") {
			ranges = append(ranges, braceEscape(string(c)+"-"))
			i += 2
			continue
		}
		if strings.HasPrefix(string(glob[i+1:]), "-") {
			rangeStart = string(c)
			i += 2
			continue
		}
		ranges = append(ranges, braceEscape(string(c)))
		i++
	}
	if endPos < i {
		return "", false, 0, false
	}
	if len(ranges) == 0 {
		return "$.", false, len(glob) - pos, true
	}
	if len(ranges) == 1 && !negate {
		r := ranges[0]
		if len(r) == 1 || len(r) == 2 && r[0] == '\\' {
			return regExpEscape(r[len(r)-1:]), false, endPos - pos, false
		}
	}
	neg := ""
	if negate {
		neg = "^"
	}
	return "[" + neg + strings.Join(ranges, "") + "]", false, endPos - pos, true
}

// mmUnescape is unescape of src/unescape.ts with no options:
// s.replace(/((?!\\).|^)\[([^\/\\])\]/g, '$1$2').replace(/\\([^\/])/g, '$1').
func mmUnescape(text string) string {
	s := []rune(text)
	var out []rune
	for i := 0; i < len(s); {
		// ((?!\\).|^) then [x]: at the start, or after a character that is
		// not \ (which the match takes, so a match cannot start inside the
		// [x] of the match before)
		if i == 0 && s[i] == '[' && i+2 < len(s) && s[i+2] == ']' && s[i+1] != '/' && s[i+1] != '\\' {
			out = append(out, s[i+1])
			i += 3
			continue
		}
		if s[i] != '\\' && !isLineTerminator(s[i]) && i+3 < len(s) && s[i+1] == '[' && s[i+3] == ']' && s[i+2] != '/' && s[i+2] != '\\' {
			out = append(out, s[i], s[i+2])
			i += 4
			continue
		}
		out = append(out, s[i])
		i++
	}
	s, out = out, nil
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] != '/' {
			out = append(out, s[i+1])
			i++
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}
