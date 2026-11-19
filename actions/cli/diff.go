package cli

import (
	"fmt"
	"slices"
	"strings"
)

// The diff of --dry-run: what --fix would write, as git diff writes it, so
// that git apply takes it.

// contextLines is how many lines around a change a hunk shows.
const contextLines = 3

// splitLines is the lines of s, each with its line break; the last has
// none when s does not end in one.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.SplitAfter(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// op is a line of an edit script: kept (' '), removed ('-') or added ('+').
type op struct {
	kind byte
	line string
}

// maxEdits is how many removed and added lines edits looks for the
// shortest script with; past it, the lines between the common start and
// end are all removed and all added, which is still a diff that applies.
const maxEdits = 1000

// edits is an edit script from a to b: the lines they start and end with
// kept, and between them the shortest script (Myers, "An O(ND) difference
// algorithm and its variations", 1986) when it has maxEdits lines or less.
func edits(a, b []string) []op {
	p := 0
	for p < len(a) && p < len(b) && a[p] == b[p] {
		p++
	}
	q := 0
	for q < len(a)-p && q < len(b)-p && a[len(a)-1-q] == b[len(b)-1-q] {
		q++
	}
	var out []op
	for _, l := range a[:p] {
		out = append(out, op{' ', l})
	}
	ma, mb := a[p:len(a)-q], b[p:len(b)-q]
	mid, ok := myers(ma, mb)
	if !ok {
		mid = nil
		for _, l := range ma {
			mid = append(mid, op{'-', l})
		}
		for _, l := range mb {
			mid = append(mid, op{'+', l})
		}
	}
	out = append(out, mid...)
	for _, l := range a[len(a)-q:] {
		out = append(out, op{' ', l})
	}
	return out
}

// myers is the shortest script from a to b, if it has maxEdits lines or
// less. It keeps, of each step d, the diagonals -d-1 to d+1 only, so what
// it holds grows with d squared, not with d times the lines.
func myers(a, b []string) ([]op, bool) {
	n, m := len(a), len(b)
	limit := min(n+m, maxEdits)
	off := limit + 1
	v := make([]int, 2*off+1) // v[off+k]: the furthest x on the diagonal k
	var trace []window
	for d := 0; d <= limit; d++ {
		trace = append(trace, window{d: d, v: slices.Clone(v[off-d-1 : off+d+2])})
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || k != d && v[off+k-1] < v[off+k+1] {
				x = v[off+k+1]
			} else {
				x = v[off+k-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x, y = x+1, y+1
			}
			v[off+k] = x
			if x >= n && y >= m {
				return backtrack(a, b, trace, d), true
			}
		}
	}
	return nil, false
}

// window is the diagonals -d-1 to d+1 of v before the step d.
type window struct {
	d int
	v []int
}

func (w window) at(k int) int { return w.v[k+w.d+1] }

func backtrack(a, b []string, trace []window, d int) []op {
	var out []op
	x, y := len(a), len(b)
	for ; d > 0; d-- {
		v := trace[d]
		k := x - y
		var pk int
		if k == -d || k != d && v.at(k-1) < v.at(k+1) {
			pk = k + 1
		} else {
			pk = k - 1
		}
		px := v.at(pk)
		py := px - pk
		for x > px && y > py {
			x, y = x-1, y-1
			out = append(out, op{' ', a[x]})
		}
		if x == px {
			y--
			out = append(out, op{'+', b[y]})
		} else {
			x--
			out = append(out, op{'-', a[x]})
		}
	}
	for x > 0 {
		x, y = x-1, y-1
		out = append(out, op{' ', a[x]})
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// unifiedDiff is the diff of the file name from a to b, or "" when they
// are the same.
func unifiedDiff(name string, a, b []byte) string {
	if string(a) == string(b) {
		return ""
	}
	ops := edits(splitLines(string(a)), splitLines(string(b)))
	var w strings.Builder
	from, to := quotePath("a/"+name), quotePath("b/"+name)
	fmt.Fprintf(&w, "diff --git %s %s\n--- %s%s\n+++ %s%s\n", from, to, from, spaced(name), to, spaced(name))
	for i := 0; i < len(ops); {
		if ops[i].kind == ' ' {
			i++
			continue
		}
		// a hunk: from context lines before the change to context lines
		// after the last change that is not more than 2*context away
		start := max(0, i-contextLines)
		end := i
		for j := i; j < len(ops); j++ {
			if ops[j].kind != ' ' {
				end = j + 1
			} else if j-end >= 2*contextLines {
				break
			}
		}
		end = min(len(ops), end+contextLines)
		writeHunk(&w, ops, start, end)
		i = end
	}
	return w.String()
}

// writeHunk writes the hunk of ops[start:end].
func writeHunk(w *strings.Builder, ops []op, start, end int) {
	s1, s2 := 1, 1 // the lines of a and of b before the hunk, plus one
	for _, o := range ops[:start] {
		if o.kind != '+' {
			s1++
		}
		if o.kind != '-' {
			s2++
		}
	}
	n1, n2 := 0, 0
	for _, o := range ops[start:end] {
		if o.kind != '+' {
			n1++
		}
		if o.kind != '-' {
			n2++
		}
	}
	// an empty side is written with the line before it (GNU diff)
	if n1 == 0 {
		s1--
	}
	if n2 == 0 {
		s2--
	}
	fmt.Fprintf(w, "@@ -%d,%d +%d,%d @@\n", s1, n1, s2, n2)
	for _, o := range ops[start:end] {
		w.WriteByte(o.kind)
		w.WriteString(o.line)
		if !strings.HasSuffix(o.line, "\n") {
			w.WriteString("\n\\ No newline at end of file\n")
		}
	}
}

// quotePath is the path p as git writes it in a diff: as it is, or, when
// it has a byte that is not printable ASCII, a double quote or a
// backslash, inside double quotes with those bytes escaped (a line break
// in a name must not start another line of the diff).
func quotePath(p string) string {
	plain := true
	for i := 0; i < len(p); i++ {
		if c := p[i]; c < 0x20 || c >= 0x7f || c == '"' || c == '\\' {
			plain = false
			break
		}
	}
	if plain {
		return p
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(p); i++ {
		switch c := p[i]; c {
		case '\a':
			b.WriteString(`\a`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\v':
			b.WriteString(`\v`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			if c < 0x20 || c >= 0x7f {
				fmt.Fprintf(&b, "\\%03o", c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// spaced is the tab git writes after a name with a space in the --- and
// +++ lines, so that the name ends where the tab is.
func spaced(name string) string {
	if strings.Contains(name, " ") && quotePath(name) == name {
		return "\t"
	}
	return ""
}
