package prcode

// mmRegexp is a regular expression of the JavaScript syntax that
// toRegExpSource builds, anchored as minimatch anchors it (^...$), run by
// backtracking: Go's regexp has no negative lookahead, which the regular
// expressions of minimatch use for the dots and for !(...). It reads
// literals, \ escapes (each of the source is of a character that is not a
// letter or a digit, so it stands for the character), ., [...] and [^...]
// with ranges, groups (...), (?:...) and (?!...), |, the quantifiers ?, *
// and + (lazy or not: only whether a match exists is asked), ^ and $.
type mmRegexp struct {
	alts [][]reNode
}

type reKind uint8

const (
	reChar reKind = iota
	reAny
	reClass
	reStart
	reEnd
	reGroup
	reNotAhead
)

type reNode struct {
	kind     reKind
	char     rune
	negate   bool       // of reClass
	ranges   [][2]rune  // of reClass
	alts     [][]reNode // of reGroup and reNotAhead
	min, max int        // the quantifier: 1, 1 without one; max -1 for none
}

// compileMMRegexp reads src; ok is false for a source it does not read.
func compileMMRegexp(src string) (*mmRegexp, bool) {
	p := reParser{src: []rune(src)}
	alts, ok := p.alts()
	if !ok || p.i != len(p.src) {
		return nil, false
	}
	return &mmRegexp{alts: alts}, true
}

type reParser struct {
	src []rune
	i   int
}

func (p *reParser) alts() ([][]reNode, bool) {
	var alts [][]reNode
	var seq []reNode
	for p.i < len(p.src) {
		c := p.src[p.i]
		switch c {
		case '|':
			p.i++
			alts, seq = append(alts, seq), nil
			continue
		case ')':
			return append(alts, seq), true
		}
		n, ok := p.atom()
		if !ok {
			return nil, false
		}
		if n, ok = p.quantifier(n); !ok {
			return nil, false
		}
		seq = append(seq, n)
	}
	return append(alts, seq), true
}

func (p *reParser) atom() (reNode, bool) {
	c := p.src[p.i]
	p.i++
	switch c {
	case '\\':
		if p.i >= len(p.src) {
			return reNode{}, false
		}
		e := p.src[p.i]
		p.i++
		if 'a' <= e && e <= 'z' || 'A' <= e && e <= 'Z' || '0' <= e && e <= '9' {
			return reNode{}, false // a class escape such as \d or \x, which the sources do not have
		}
		return reNode{kind: reChar, char: e, min: 1, max: 1}, true
	case '.':
		return reNode{kind: reAny, min: 1, max: 1}, true
	case '^':
		return reNode{kind: reStart, min: 1, max: 1}, true
	case '$':
		return reNode{kind: reEnd, min: 1, max: 1}, true
	case '[':
		return p.class()
	case '(':
		kind := reGroup
		if p.i+1 < len(p.src) && p.src[p.i] == '?' {
			switch p.src[p.i+1] {
			case ':':
				p.i += 2
			case '!':
				kind = reNotAhead
				p.i += 2
			default:
				return reNode{}, false
			}
		}
		alts, ok := p.alts()
		if !ok || p.i >= len(p.src) || p.src[p.i] != ')' {
			return reNode{}, false
		}
		p.i++
		return reNode{kind: kind, alts: alts, min: 1, max: 1}, true
	case '*', '+', '?', ')', '{', '}', ']':
		return reNode{}, false
	}
	return reNode{kind: reChar, char: c, min: 1, max: 1}, true
}

func (p *reParser) class() (reNode, bool) {
	n := reNode{kind: reClass, min: 1, max: 1}
	if p.i < len(p.src) && p.src[p.i] == '^' {
		n.negate = true
		p.i++
	}
	char := func() (rune, bool) {
		if p.i >= len(p.src) {
			return 0, false
		}
		c := p.src[p.i]
		p.i++
		if c != '\\' {
			return c, true
		}
		if p.i >= len(p.src) {
			return 0, false
		}
		e := p.src[p.i]
		p.i++
		if 'a' <= e && e <= 'z' || 'A' <= e && e <= 'Z' || '0' <= e && e <= '9' {
			return 0, false
		}
		return e, true
	}
	for {
		if p.i >= len(p.src) {
			return reNode{}, false
		}
		if p.src[p.i] == ']' {
			p.i++
			return n, true
		}
		lo, ok := char()
		if !ok {
			return reNode{}, false
		}
		hi := lo
		if p.i+1 < len(p.src) && p.src[p.i] == '-' && p.src[p.i+1] != ']' {
			p.i++
			if hi, ok = char(); !ok {
				return reNode{}, false
			}
		}
		n.ranges = append(n.ranges, [2]rune{lo, hi})
	}
}

func (p *reParser) quantifier(n reNode) (reNode, bool) {
	if p.i >= len(p.src) {
		return n, true
	}
	switch p.src[p.i] {
	case '?':
		n.min, n.max = 0, 1
	case '*':
		n.min, n.max = 0, -1
	case '+':
		n.min, n.max = 1, -1
	default:
		return n, true
	}
	if n.kind == reStart || n.kind == reEnd || n.kind == reNotAhead {
		return reNode{}, false
	}
	p.i++
	if p.i < len(p.src) && p.src[p.i] == '?' {
		p.i++ // lazy
	}
	return n, true
}

// match is RegExp.prototype.test: whether the regular expression matches
// s at some position (minimatch builds it as ^source$, and a | at the top
// of the source binds ^ to the first alternative and $ to the last one
// only). It takes one from *budget for each step, and stops when *budget
// is below 0.
func (r *mmRegexp) match(s string, budget *int) bool {
	m := reMatcher{s: []rune(s), budget: budget}
	for start := 0; start <= len(m.s); start++ {
		if m.alts(r.alts, start, func(int) bool { return true }) {
			return true
		}
		if *budget < 0 {
			return false
		}
	}
	return false
}

type reMatcher struct {
	s      []rune
	budget *int
}

func (m *reMatcher) alts(alts [][]reNode, pos int, k func(int) bool) bool {
	for _, seq := range alts {
		if m.seq(seq, pos, k) {
			return true
		}
	}
	return false
}

func (m *reMatcher) seq(seq []reNode, pos int, k func(int) bool) bool {
	if *m.budget--; *m.budget < 0 {
		return false
	}
	if len(seq) == 0 {
		return k(pos)
	}
	n, rest := seq[0], seq[1:]
	next := func(p int) bool { return m.seq(rest, p, k) }
	if n.kind == reNotAhead {
		if m.alts(n.alts, pos, func(int) bool { return true }) {
			return false
		}
		return next(pos)
	}
	return m.repeat(n, 0, pos, next)
}

// repeat matches n count or more times from pos, then k; an iteration
// that matches nothing ends the repetition, as in JavaScript.
func (m *reMatcher) repeat(n reNode, count, pos int, k func(int) bool) bool {
	if *m.budget < 0 {
		return false
	}
	if count >= n.min && k(pos) {
		return true
	}
	if n.max >= 0 && count >= n.max {
		return false
	}
	return m.one(n, pos, func(p int) bool {
		if p == pos && count >= n.min {
			return false
		}
		return m.repeat(n, count+1, p, k)
	})
}

func (m *reMatcher) one(n reNode, pos int, k func(int) bool) bool {
	switch n.kind {
	case reChar:
		return pos < len(m.s) && m.s[pos] == n.char && k(pos+1)
	case reAny:
		return pos < len(m.s) && !isLineTerminator(m.s[pos]) && k(pos+1)
	case reClass:
		if pos >= len(m.s) {
			return false
		}
		in := false
		for _, r := range n.ranges {
			if r[0] <= m.s[pos] && m.s[pos] <= r[1] {
				in = true
				break
			}
		}
		return in != n.negate && k(pos+1)
	case reStart:
		return pos == 0 && k(pos)
	case reEnd:
		return pos == len(m.s) && k(pos)
	case reGroup:
		return m.alts(n.alts, pos, k)
	}
	return false
}

func isLineTerminator(r rune) bool {
	return r == '\n' || r == '\r' || r == 0x2028 || r == 0x2029
}
