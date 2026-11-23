package edit

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/scalar"
)

// layout is where a value is written: in a flow collection or not, the
// column of the lines written (the column of a key or of a '-'), the
// width of one level of indentation, whether a sequence under a key is
// indented (key:\n  - a) or not (key:\n- a), and the line break.
type layout struct {
	flow     bool
	col      int
	unit     int
	seqUnder bool
	nl       string
}

func (l layout) pad(n int) string { return strings.Repeat(" ", n) }

// writePairs writes the entries of a mapping: in a block, whole lines at
// l.col, each ending in l.nl; in a flow collection, "a: 1, b: 2".
func writePairs(pairs Map, l layout) ([]byte, error) {
	var b strings.Builder
	for i, p := range pairs {
		if l.flow && p.Comment != "" {
			return nil, errors.New("a flow collection cannot hold comment lines")
		}
		if l.flow && i > 0 {
			b.WriteString(", ")
		}
		if !l.flow && p.Comment != "" {
			for _, line := range strings.Split(p.Comment, "\n") {
				if err := commentText(line); err != nil {
					return nil, err
				}
				b.WriteString(l.pad(l.col) + "#")
				if line != "" {
					b.WriteString(" " + line)
				}
				b.WriteString(l.nl)
			}
		}
		k, err := writeKey(p.Key, l)
		if err != nil {
			return nil, err
		}
		v, err := writeValue(p.Value, l, true)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", p.Key, err)
		}
		if !l.flow {
			b.WriteString(l.pad(l.col))
		}
		b.WriteString(k + ":" + afterIndicator(string(v)))
		if !l.flow {
			b.WriteString(l.nl)
		}
	}
	return []byte(b.String()), nil
}

// writeItem writes one sequence item: in a block, "- " and the value as
// whole lines at l.col; in a flow collection, the value alone.
func writeItem(v Value, l layout) ([]byte, error) {
	text, err := writeValue(v, l, false)
	if err != nil || l.flow {
		return text, err
	}
	return []byte(l.pad(l.col) + "-" + afterIndicator(string(text)) + l.nl), nil
}

// writeValue writes v where a value starts: after "key:" when afterKey,
// after "- " otherwise. A block collection after a key starts on the next
// line; after "- " it starts on the same line ([186], [195] compact forms). The text
// ends at the end of its last line, without the line break.
func writeValue(v Value, l layout, afterKey bool) ([]byte, error) {
	switch v := v.(type) {
	case Scalar:
		return writeScalar(v, l, afterKey)
	case Map:
		if len(v) == 0 {
			return []byte("{}"), nil
		}
		if l.flow {
			b, err := writePairs(v, l)
			return []byte("{" + string(b) + "}"), err
		}
		inner := l
		if afterKey {
			inner.col += l.unit
		} else {
			inner.col += 2 // after "- "
		}
		b, err := writePairs(v, inner)
		if err != nil {
			return nil, err
		}
		return nested(string(b), inner, afterKey || v[0].Comment != ""), nil
	case Seq:
		if len(v) == 0 {
			return []byte("[]"), nil
		}
		inner := l
		switch {
		case l.flow:
		case !afterKey:
			inner.col += 2
		case l.seqUnder:
			inner.col += l.unit
		}
		var b strings.Builder
		for i, x := range v {
			if l.flow && i > 0 {
				b.WriteString(", ")
			}
			t, err := writeItem(x, inner)
			if err != nil {
				return nil, fmt.Errorf("[%d]: %w", i, err)
			}
			b.Write(t)
		}
		if l.flow {
			return []byte("[" + b.String() + "]"), nil
		}
		return nested(b.String(), inner, afterKey), nil
	}
	return nil, errors.New("no value")
}

// nested turns lines written at inner.col into a value's text: from the
// next line, or from the first line's content on the same line.
func nested(lines string, inner layout, nextLine bool) []byte {
	lines = strings.TrimSuffix(lines, inner.nl)
	if nextLine {
		return []byte(inner.nl + lines)
	}
	return []byte(lines[inner.col:])
}

// afterIndicator is text as it follows ':' or '-': after a space, unless
// it is empty or starts on the next line.
func afterIndicator(text string) string {
	if text == "" || text[0] == '\n' || text[0] == '\r' {
		return text
	}
	return " " + text
}

func writeScalar(s Scalar, l layout, afterKey bool) ([]byte, error) {
	if s.tag != scalar.TagStr {
		if s.styled && s.style != cst.Plain {
			return nil, fmt.Errorf("%s is written plain; a quoted or block scalar is a string", s.tag)
		}
		if s.tag == scalar.TagNull && (!afterKey || l.flow) {
			return []byte("null"), nil
		}
		return []byte(s.s), nil
	}
	style := s.style
	if !s.styled {
		if plainOK(s.s, l.flow) == nil && scalar.PlainTag(s.s) == scalar.TagStr {
			return []byte(s.s), nil
		}
		style = cst.DoubleQuoted
	}
	switch style {
	case cst.Plain:
		if err := plainOK(s.s, l.flow); err != nil {
			return nil, err
		}
		if tag := scalar.PlainTag(s.s); tag != scalar.TagStr {
			return nil, fmt.Errorf("as a plain scalar, %q would be %s", s.s, tag)
		}
		return []byte(s.s), nil
	case cst.SingleQuoted, cst.DoubleQuoted:
		b, ok := scalar.Body(style, s.s, 0)
		if !ok {
			return nil, fmt.Errorf("%q cannot be written in this style", s.s)
		}
		q := "'"
		if style == cst.DoubleQuoted {
			q = `"`
		}
		return []byte(q + string(b) + q), nil
	}
	if l.flow {
		return nil, errors.New("a flow collection cannot hold a block scalar")
	}
	return blockScalar(s.s, style, l)
}

// blockScalar writes a literal or folded scalar (8.1): the header, then
// each line at one level deeper than l.col. The chomping indicator keeps
// the value's final line breaks: strip without one, clip with one, keep
// with more, or when there is nothing but line breaks. The indentation
// indicator is needed when the first line starts with a space, which
// would otherwise be taken for indentation (8.1.1.1).
func blockScalar(s string, style cst.ScalarStyle, l layout) ([]byte, error) {
	if _, ok := scalar.Body(style, s, 0); !ok {
		return nil, fmt.Errorf("%q cannot be written in this style", s)
	}
	header := "|"
	if style == cst.Folded {
		header = ">"
	}
	if strings.HasPrefix(s, " ") {
		if l.unit > 9 {
			return nil, fmt.Errorf("an indentation of %d cannot be an indicator", l.unit)
		}
		header += fmt.Sprint(l.unit)
	}
	breaks := len(s) - len(strings.TrimRight(s, "\n"))
	switch {
	case breaks == 0:
		header += "-"
	case breaks > 1 || breaks == len(s):
		header += "+"
	}
	var lines []string
	if s != "" {
		lines = strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	}
	var b strings.Builder
	b.WriteString(header)
	for _, line := range lines {
		b.WriteString(l.nl)
		if line != "" {
			b.WriteString(l.pad(l.col+l.unit) + line)
		}
	}
	return []byte(b.String()), nil
}

// writeKey writes an implicit key ([154]): one line of at most 1024
// characters, plain when a plain scalar can hold it as a string.
func writeKey(k string, l layout) (string, error) {
	if strings.ContainsAny(k, "\r\n") {
		return "", fmt.Errorf("key %q has a line break", k)
	}
	if utf8.RuneCountInString(k) > 1024 {
		return "", errors.New("a key is at most 1024 characters")
	}
	if plainOK(k, l.flow) == nil && scalar.PlainTag(k) == scalar.TagStr {
		return k, nil
	}
	b, ok := scalar.Body(cst.DoubleQuoted, k, 0)
	if !ok {
		return "", fmt.Errorf("key %q cannot be written", k)
	}
	return `"` + string(b) + `"`, nil
}

// plainOK is whether s can be a plain scalar anywhere a value or a key
// goes. A value starting with "---" or "..." could land at the start of a
// line, where it would be a document marker.
func plainOK(s string, flow bool) error {
	if s == "" {
		return errors.New("an empty plain scalar is null")
	}
	if _, ok := scalar.Body(cst.Plain, s, 0); !ok {
		return fmt.Errorf("%q cannot be a plain scalar", s)
	}
	if err := plainEdges(s, flow); err != nil {
		return err
	}
	if flow && strings.ContainsAny(s, ",[]{}") {
		return errors.New("a plain scalar in a flow collection cannot contain a flow indicator")
	}
	if strings.HasPrefix(s, "---") || strings.HasPrefix(s, "...") {
		return errors.New("a plain scalar starting with a document marker")
	}
	return nil
}

// commentText is whether line can follow '#' on a line of its own:
// printable characters ([1]) without line breaks, as a single-quoted
// scalar holds them.
func commentText(line string) error {
	if _, ok := scalar.Body(cst.SingleQuoted, line, 0); !ok {
		return fmt.Errorf("a comment cannot hold %q", line)
	}
	return nil
}
