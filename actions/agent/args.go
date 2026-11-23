package agent

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/expr"
)

// words splits s into words as shell-quote's parse does for claude_args:
// blanks part them, single and double quotes and a
// backslash keep a blank in a word, and an unquoted # begins a comment to
// the end of s, which claude-code-action drops. It expands nothing, and a
// value with a ${{ }} is not read.
func words(s string) []string {
	var out []string
	for _, w := range scan(s, nil, nil) {
		out = append(out, w.text)
	}
	return out
}

// word is a word of claude_args as shell-quote's parse makes it, and where
// its bytes come from: at[i] is the index in the value of the byte text[i].
type word struct {
	text string
	at   []int
}

// scan splits s as words does, and keeps where each byte of a word comes
// from: of[i] is the index in the value of the byte s[i] (stripCommentsAt),
// or i when of is nil. A span of opaque, in the value, is a ${{ }} that
// GitHub replaces before the action reads it: it stays in one word, as the
// blanks inside it are not the value's.
func scan(s string, of []int, opaque []expr.Span) []word {
	var out []word
	var cur word
	b := []byte{}
	in := false // a word has begun
	var quote byte
	idx := func(i int) int {
		if of == nil {
			return i
		}
		return of[i]
	}
	add := func(i int) {
		b = append(b, s[i])
		cur.at = append(cur.at, idx(i))
	}
	for i := 0; i < len(s); i++ {
		if k := slices.IndexFunc(opaque, func(e expr.Span) bool { return e.Start == idx(i) }); k >= 0 {
			for ; i < len(s) && idx(i) < opaque[k].End; i++ {
				add(i)
			}
			i--
			in = true
			continue
		}
		c := s[i]
		switch {
		case quote != 0:
			switch {
			case c == quote:
				quote = 0
			case c == '\\' && quote == '"' && i+1 < len(s):
				i++
				add(i)
			default:
				add(i)
			}
		case c == '#':
			i = len(s) // a comment: the rest is gone
		case c == '\'' || c == '"':
			quote, in = c, true
		case c == '\\' && i+1 < len(s):
			i++
			add(i)
			in = true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if in {
				cur.text = string(b)
				out = append(out, cur)
				cur, b, in = word{}, b[:0:0], false
			}
		default:
			add(i)
			in = true
		}
	}
	if in {
		cur.text = string(b)
		out = append(out, cur)
	}
	return out
}

// plainWord is s as one word whose bytes are where they are.
func plainWord(s string) word {
	w := word{text: s, at: make([]int, len(s))}
	for i := range w.at {
		w.at[i] = i
	}
	return w
}

// element is an element of a word split at commas, and its span in the
// value.
type element struct {
	text string
	span expr.Span
}

// elements are the elements of w from its byte from on, split at commas
// and trimmed, as claude-code-action splits the values of --allowedTools
// and ai-inference copilot-allow-tools;
// with blanks, at blanks outside parentheses too, as Claude Code's CLI
// reads the list the action passes it ("Comma or space-separated"), but
// inside a span of opaque, a ${{ }} of the value. The empty ones are
// dropped.
func (w word) elements(from int, blanks bool, opaque []expr.Span) []element {
	var out []element
	for i := from; i <= len(w.text); {
		j, depth := i, 0
		for ; j < len(w.text); j++ {
			c := w.text[j]
			switch {
			case c == '(':
				depth++
			case c == ')' && depth > 0:
				depth--
			}
			inExpr := slices.ContainsFunc(opaque, func(e expr.Span) bool { return e.Start <= w.at[j] && w.at[j] < e.End })
			if c == ',' || blanks && depth == 0 && !inExpr && isSpace(c) {
				break
			}
		}
		a, b := i, j
		for a < b && isSpace(w.text[a]) {
			a++
		}
		for b > a && isSpace(w.text[b-1]) {
			b--
		}
		if a < b {
			out = append(out, element{text: w.text[a:b], span: expr.Span{Start: w.at[a], End: w.at[b-1] + 1}})
		}
		i = j + 1
	}
	return out
}

// argv splits s as string-argv 0.3.2's parseArgsStringToArgv does for
// codex-args, whose expression is
// ([^\s'"]([^\s'"]*(['"])([^\3]*?)\3)+[^\s'"]*)|[^\s'"]+|(['"])([^\5]*?)\5:
// a word with quotes inside it stays as written, a word wholly in quotes
// loses them, a backslash is a letter, and a quote never closed is
// skipped.
func argv(s string) []string {
	var out []string
	plain := func(c byte) bool { return !isSpace(c) && c != '\'' && c != '"' }
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case plain(c):
			end := i + 1
			for j := end; ; {
				for j < len(s) && plain(s[j]) {
					j++
				}
				if j >= len(s) || isSpace(s[j]) {
					break
				}
				k := strings.IndexByte(s[j+1:], s[j])
				if k < 0 {
					break
				}
				j += 1 + k + 1
				end = j
			}
			for end < len(s) && plain(s[end]) {
				end++ // after the last quotes, or the word without them
			}
			out = append(out, s[i:end])
			i = end
		case c == '\'' || c == '"':
			k := strings.IndexByte(s[i+1:], c)
			if k < 0 {
				i++
				continue
			}
			out = append(out, s[i+1:i+1+k])
			i += 1 + k + 1
		default:
			i++
		}
	}
	return out
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

// stripComments drops the lines of s whose first non-blank is #, as
// claude-code-action does before it parses claude_args.
func stripComments(s string) string {
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

// stripCommentsAt is stripComments, with the index in s of each byte it
// keeps.
func stripCommentsAt(s string) (string, []int) {
	var b strings.Builder
	var of []int
	first := true
	for start := 0; start <= len(s); {
		end := strings.IndexByte(s[start:], '\n')
		if end < 0 {
			end = len(s)
		} else {
			end += start
		}
		if l := s[start:end]; !strings.HasPrefix(strings.TrimSpace(l), "#") {
			if !first {
				b.WriteByte('\n')
				of = append(of, start-1)
			}
			b.WriteString(l)
			for i := start; i < end; i++ {
				of = append(of, i)
			}
			first = false
		}
		start = end + 1
	}
	return b.String(), of
}

// flag is an entry of the record claude-code-action makes of claude_args.
type flag struct {
	key, value string
	hasValue   bool
	words      []int // the indexes of its words: the flag's, then its values'
}

// accumulating are the flags whose values claude-code-action gathers: each
// takes every word up to the next flag.
var accumulating = map[string]bool{"allowedTools": true, "allowed-tools": true, "disallowedTools": true, "disallowed-tools": true, "mcp-config": true, "add-dir": true}

// record is the record claude-code-action's parseClaudeArgsToExtraArgs
// makes of the words ws: --k takes the next word when it
// does not begin with --; a key set again keeps its first place and takes
// the later value, but an accumulating flag adds the later values to its
// own; --k=v is a key of its own. The CLI
// reads the record in its order, and a later flag wins.
func record(ws []word) []flag {
	var out []flag
	set := func(f flag) {
		for i := range out {
			if out[i].key != f.key {
				continue
			}
			if accumulating[f.key] && f.hasValue {
				out[i].words = append(out[i].words, f.words[1:]...)
				return
			}
			out[i].value, out[i].hasValue, out[i].words = f.value, f.hasValue, f.words
			return
		}
		out = append(out, f)
	}
	for i := 0; i < len(ws); i++ {
		w, ok := strings.CutPrefix(ws[i].text, "--")
		if !ok {
			continue
		}
		f := flag{key: w, words: []int{i}}
		if i+1 >= len(ws) || ws[i+1].text == "" || strings.HasPrefix(ws[i+1].text, "--") {
			set(f)
			continue
		}
		if accumulating[w] {
			for i+1 < len(ws) && !strings.HasPrefix(ws[i+1].text, "--") {
				i++
				f.words = append(f.words, i)
			}
			f.hasValue = true
			set(f)
			continue
		}
		f.value, f.hasValue = ws[i+1].text, true
		f.words = append(f.words, i+1)
		set(f)
		i++
	}
	return out
}

// lastValue is the value of the flag name the CLI takes from r: the last of
// --name v and --name=v in r's order.
func lastValue(r []flag, name string) (string, bool) {
	v, ok := "", false
	for _, f := range r {
		switch {
		case f.key == name && f.hasValue:
			v, ok = f.value, true
		case strings.HasPrefix(f.key, name+"="):
			v, ok = strings.TrimPrefix(f.key, name+"="), true
		}
	}
	return v, ok
}

// defaultMode is permissions.defaultMode of the settings s, whose keys
// are matched exactly as JSON.parse does; false when s is not a JSON
// object, which names a file then.
func defaultMode(s string) (string, bool) {
	var top map[string]json.RawMessage
	if json.Unmarshal([]byte(s), &top) != nil {
		return "", false
	}
	var perms map[string]json.RawMessage
	if json.Unmarshal(top["permissions"], &perms) != nil {
		return "", true
	}
	var mode string
	if json.Unmarshal(perms["defaultMode"], &mode) != nil {
		return "", true
	}
	return mode, true
}
