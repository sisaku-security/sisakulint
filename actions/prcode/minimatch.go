package prcode

import (
	"strconv"
	"strings"
)

// matchArtifactName is whether minimatch, with no options, matches the
// name of an artifact (which has no /) to pattern, as
// actions/upload-artifact/merge and actions/download-artifact filter the
// artifacts of a run (new Minimatch(pattern).match(name)). It follows
// minimatch v9.0.3 and v10.2.4 (https://github.com/isaacs/minimatch):
// the comment and the negation, the brace expansion of brace-expansion
// v2.0.1, the parts between /, and the regular expression that src/ast.ts
// builds of each part, which matchRegexp runs. known is false when the
// releases read the pattern differently, or when the match takes too many
// steps: a POSIX class ([:alpha:] in [...]), which 9.0.3 turns into a
// regular expression with the u flag that other escapes break, and an
// extglob inside an extglob, which 10.2 parses only to a depth.
func matchArtifactName(pattern, name string) (match, known bool) {
	pattern, name = utf16Units(pattern), utf16Units(name)
	if strings.HasPrefix(pattern, "#") {
		return false, true // a comment matches nothing
	}
	if pattern == "" {
		return name == "", true
	}
	negate := false
	for strings.HasPrefix(pattern, "!") {
		pattern, negate = pattern[1:], !negate
	}
	var set [][]globPart
	seen := map[string]bool{}
	for _, g := range minimatchBraces(pattern) {
		if seen[g] {
			continue
		}
		seen[g] = true
		var parts []globPart
		for _, p := range levelOneOptimize(strings.FieldsFunc(g, isSlash), g) {
			gp, ok := parseGlobPart(p)
			if !ok {
				return false, false
			}
			parts = append(parts, gp)
		}
		set = append(set, parts)
	}
	budget := matchBudget
	for _, parts := range set {
		hit := matchParts([]string{name}, parts, &budget)
		if budget < 0 {
			return false, false
		}
		if hit {
			return !negate, true
		}
	}
	return negate, true
}

// matchBudget bounds the steps of matchRegexp for one name.
const matchBudget = 100000

func isSlash(r rune) bool { return r == '/' }

// utf16Units is s with each character above U+FFFF replaced by two
// characters, one for each UTF-16 code unit of it, as JavaScript reads a
// string: a ? or a [...] of minimatch takes one code unit. A code unit of
// a surrogate pair is put at U+100000 plus the unit, so that it is a
// character of a Go string; a range of a class from a code unit of a
// surrogate pair to U+E000..U+FFFF compares differently than in
// JavaScript.
func utf16Units(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if r <= 0xffff {
			b.WriteRune(r)
			continue
		}
		r -= 0x10000
		b.WriteRune(0x100000 + 0xd800 + r>>10)
		b.WriteRune(0x100000 + 0xdc00 + r&0x3ff)
	}
	return b.String()
}

// levelOneOptimize is minimatch's levelOneOptimize of the parts of g, as
// split by /+: a ** after a ** is dropped, and a .. after a part other
// than .., . and ** removes that part. A g with no parts is [""].
// strings.FieldsFunc drops the empty parts at the ends, which split(/\/+/)
// keeps, so they are put back from g.
func levelOneOptimize(fields []string, g string) []string {
	var parts []string
	if strings.HasPrefix(g, "/") {
		parts = append(parts, "")
	}
	parts = append(parts, fields...)
	if strings.HasSuffix(g, "/") {
		parts = append(parts, "")
	}
	var out []string
	for _, p := range parts {
		prev := ""
		if len(out) > 0 {
			prev = out[len(out)-1]
		}
		if p == "**" && prev == "**" && len(out) > 0 {
			continue
		}
		if p == ".." && len(out) > 0 && prev != "" && prev != ".." && prev != "." && prev != "**" {
			out = out[:len(out)-1]
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

// globPart is a part of a pattern between /: **, a string to compare, or
// a regular expression.
type globPart struct {
	globstar bool
	literal  string
	re       *mmRegexp
}

// parseGlobPart is minimatch's parse of a part; ok is false for a part
// that the releases read differently.
func parseGlobPart(p string) (globPart, bool) {
	switch p {
	case "**":
		return globPart{globstar: true}, true
	case "":
		return globPart{}, true
	}
	a := parseMMAST(p)
	if a.unknown {
		return globPart{}, false
	}
	src, body, magic := a.toRegExpSource(false)
	if a.unknown {
		return globPart{}, false
	}
	if !magic {
		return globPart{literal: body}, true
	}
	re, ok := compileMMRegexp(src)
	if !ok {
		return globPart{}, false
	}
	return globPart{re: re}, true
}

func (g globPart) matches(f string, budget *int) bool {
	if g.re != nil {
		return g.re.match(f, budget)
	}
	return f == g.literal
}

// matchParts is minimatch's matchOne (not partial, no dot) of the parts
// of a file to the parts of a pattern.
func matchParts(file []string, pattern []globPart, budget *int) bool {
	fi, pi := 0, 0
	for ; fi < len(file) && pi < len(pattern); fi, pi = fi+1, pi+1 {
		p, f := pattern[pi], file[fi]
		if p.globstar {
			if pi+1 == len(pattern) {
				for ; fi < len(file); fi++ {
					if file[fi] == "." || file[fi] == ".." || strings.HasPrefix(file[fi], ".") {
						return false
					}
				}
				return true
			}
			for fr := fi; fr < len(file); fr++ {
				if matchParts(file[fr:], pattern[pi+1:], budget) {
					return true
				}
				if strings.HasPrefix(file[fr], ".") {
					break // ** does not swallow ., .. or a name that starts with .
				}
			}
			return false
		}
		if !p.matches(f, budget) {
			return false
		}
	}
	switch {
	case fi == len(file) && pi == len(pattern):
		return true
	case fi == len(file):
		return false
	default:
		return fi == len(file)-1 && file[fi] == ""
	}
}

// minimatchBraces is minimatch's braceExpand: the pattern itself unless a
// { is followed by a } with no { or line break between them.
func minimatchBraces(p string) []string {
	has := false
	for i := 0; i < len(p) && !has; i++ {
		if p[i] != '{' {
			continue
		}
		for j := i + 1; j < len(p); j++ {
			if p[j] == '{' || p[j] == '\n' || p[j] == '\r' {
				break
			}
			if p[j] == '}' {
				has = true
				break
			}
		}
	}
	if !has {
		return []string{p}
	}
	return expandBraces(p)
}

// The placeholders of the escaped characters of brace-expansion.
const (
	escSlash  = "\x00SLASH\x00"
	escOpen   = "\x00OPEN\x00"
	escClose  = "\x00CLOSE\x00"
	escComma  = "\x00COMMA\x00"
	escPeriod = "\x00PERIOD\x00"
)

// expandBraces is expandTop of brace-expansion v2.0.1
// (https://github.com/juliangruber/brace-expansion/blob/v2.0.1/index.js).
func expandBraces(str string) []string {
	if str == "" {
		return nil
	}
	if strings.HasPrefix(str, "{}") {
		str = `\{\}` + str[2:]
	}
	u := strings.NewReplacer(escSlash, `\`, escOpen, "{", escClose, "}", escComma, ",", escPeriod, ".")
	out := braceExpand(escapeBraces(str), true)
	for i := range out {
		out[i] = u.Replace(out[i])
	}
	return out
}

// escapeBraces is escapeBraces of brace-expansion: the splits and joins
// in order, each over the whole string (a strings.Replacer replaces them
// in one pass, which differs when \\ is followed by {).
func escapeBraces(s string) string {
	for _, p := range [][2]string{{`\\`, escSlash}, {`\{`, escOpen}, {`\}`, escClose}, {`\,`, escComma}, {`\.`, escPeriod}} {
		s = strings.ReplaceAll(s, p[0], p[1])
	}
	return s
}

// balanced is balanced-match v2.0.0's range of { and } in str
// (https://github.com/juliangruber/balanced-match/blob/v2.0.0/index.js).
func balanced(str string) (pre, body, post string, ok bool) {
	ai := strings.IndexByte(str, '{')
	bi := -1
	if ai >= 0 {
		if j := strings.IndexByte(str[ai+1:], '}'); j >= 0 {
			bi = ai + 1 + j
		}
	}
	if ai < 0 || bi <= 0 {
		return "", "", "", false
	}
	index := func(c byte, from int) int {
		if from > len(str) {
			return -1
		}
		if j := strings.IndexByte(str[from:], c); j >= 0 {
			return from + j
		}
		return -1
	}
	var begs []int
	left, right := len(str), 0
	start, end, found := 0, 0, false
	i := ai
	for i >= 0 && !found {
		switch {
		case i == ai:
			begs = append(begs, i)
			ai = index('{', i+1)
		case len(begs) == 1:
			start, end, found = begs[0], bi, true
			begs = begs[:0]
		default:
			beg := begs[len(begs)-1]
			begs = begs[:len(begs)-1]
			if beg < left {
				left, right = beg, bi
			}
			bi = index('}', i+1)
		}
		if ai < bi && ai >= 0 {
			i = ai
		} else {
			i = bi
		}
	}
	if len(begs) > 0 {
		start, end, found = left, right, true
	}
	if !found {
		return "", "", "", false
	}
	return str[:start], str[start+1 : end], str[end+1:], true
}

// braceExpand is expand of brace-expansion v2.0.1.
func braceExpand(str string, isTop bool) []string {
	pre, body, post, ok := balanced(str)
	if !ok {
		return []string{str}
	}
	posts := []string{""}
	if post != "" {
		posts = braceExpand(post, false)
	}
	var out []string
	if strings.HasSuffix(pre, "$") {
		for _, p := range posts {
			out = append(out, pre+"{"+body+"}"+p)
		}
		return out
	}
	numSeq, alphaSeq := numericSequence(body), alphaSequence(body)
	seq := numSeq || alphaSeq
	if !seq && !strings.Contains(body, ",") {
		if commaThenClose(post) {
			return braceExpand(pre+"{"+body+escClose+post, false)
		}
		return []string{str}
	}
	var n []string
	if seq {
		n = strings.Split(body, "..")
	} else {
		n = parseCommaParts(body)
		if len(n) == 1 {
			var e []string
			for _, x := range braceExpand(n[0], false) {
				e = append(e, "{"+x+"}")
			}
			n = e
			if len(n) == 1 {
				for _, p := range posts {
					out = append(out, pre+n[0]+p)
				}
				return out
			}
		}
	}
	var vals []string
	if seq {
		x, y := braceNumeric(n[0]), braceNumeric(n[1])
		width := max(len(n[0]), len(n[1]))
		incr := 1
		if len(n) == 3 {
			incr = braceNumeric(n[2])
			if incr < 0 {
				incr = -incr
			}
		}
		reverse := y < x
		if reverse {
			incr = -incr
		}
		pad := false
		for _, s := range n {
			pad = pad || isPadded(s)
		}
		for i := x; reverse && i >= y || !reverse && i <= y; i += incr {
			var c string
			if alphaSeq {
				c = string(rune(i))
				if c == `\` {
					c = ""
				}
			} else {
				c = strconv.Itoa(i)
				if pad {
					if need := width - len(c); need > 0 {
						z := strings.Repeat("0", need)
						if i < 0 {
							c = "-" + z + c[1:]
						} else {
							c = z + c
						}
					}
				}
			}
			vals = append(vals, c)
			if incr == 0 {
				break // brace-expansion loops forever; a step of 0 is not a sequence anyone writes
			}
		}
	} else {
		for _, s := range n {
			vals = append(vals, braceExpand(s, false)...)
		}
	}
	for _, v := range vals {
		for _, p := range posts {
			e := pre + v + p
			if !isTop || seq || e != "" {
				out = append(out, e)
			}
		}
	}
	return out
}

// parseCommaParts is parseCommaParts of brace-expansion v2.0.1.
func parseCommaParts(str string) []string {
	if str == "" {
		return []string{""}
	}
	pre, body, post, ok := balanced(str)
	if !ok {
		return strings.Split(str, ",")
	}
	p := strings.Split(pre, ",")
	p[len(p)-1] += "{" + body + "}"
	postParts := parseCommaParts(post)
	if post != "" {
		p[len(p)-1] += postParts[0]
		p = append(p, postParts[1:]...)
	}
	return p
}

// commaThenClose is /,.*\}/.test(s): a , and a later } with no line break
// between them.
func commaThenClose(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != ',' {
			continue
		}
		for j := i + 1; j < len(s); j++ {
			if s[j] == '\n' || s[j] == '\r' {
				break
			}
			if s[j] == '}' {
				return true
			}
		}
	}
	return false
}

// numericSequence is /^-?\d+\.\.-?\d+(?:\.\.-?\d+)?$/.
func numericSequence(s string) bool {
	parts := strings.Split(s, "..")
	if len(parts) != 2 && len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if !isInteger(p) {
			return false
		}
	}
	return true
}

// alphaSequence is /^[a-zA-Z]\.\.[a-zA-Z](?:\.\.-?\d+)?$/.
func alphaSequence(s string) bool {
	parts := strings.Split(s, "..")
	if len(parts) != 2 && len(parts) != 3 {
		return false
	}
	for _, p := range parts[:2] {
		if len(p) != 1 || !('a' <= p[0] && p[0] <= 'z' || 'A' <= p[0] && p[0] <= 'Z') {
			return false
		}
	}
	return len(parts) == 2 || isInteger(parts[2])
}

func isInteger(s string) bool {
	s = strings.TrimPrefix(s, "-")
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isPadded is /^-?0\d/.
func isPadded(s string) bool {
	s = strings.TrimPrefix(s, "-")
	return len(s) >= 2 && s[0] == '0' && s[1] >= '0' && s[1] <= '9'
}

// braceNumeric is numeric of brace-expansion: the integer of s, or the
// code of its first character.
func braceNumeric(s string) int {
	if isInteger(s) {
		n, err := strconv.Atoi(s)
		if err == nil {
			return n
		}
	}
	for _, r := range s {
		return int(r)
	}
	return 0
}
