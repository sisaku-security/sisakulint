// Package suitetest reads yaml-test-suite's data release (the data-YYYY-MM-DD
// layout described in yaml-test-suite/main/ReadMe.md). It does not depend on
// the cst package, so cst's in-package tests can import it.
package suitetest

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

type Case struct {
	ID     string // "229Q", or "2G84/00" for a sub-case
	Name   string
	In     []byte
	Events []Event
	Error  bool // the input must be rejected
}

// Event is a test.event line. String leaves out Value and Tag, so a
// comparison of String covers only the event structure.
type Event struct {
	Type     EventType
	Flow     bool // +MAP {} / +SEQ []
	Explicit bool // +DOC --- / -DOC ...
	Anchor   string
	HasTag   bool
	Tag      string // the text between < and >
	Style    Style  // =VAL
	Value    string // =VAL: the value with \\ \b \n \r \t unescaped
	Alias    string
}

// EventType is the kind of an event: the first word of its line.
type EventType uint8

const (
	EventTypeUnset EventType = iota
	EventStreamStart
	EventStreamEnd
	EventDocumentStart
	EventDocumentEnd
	EventMappingStart
	EventMappingEnd
	EventSequenceStart
	EventSequenceEnd
	EventScalar
	EventAlias
)

var eventTypeNames = [...]string{"", "+STR", "-STR", "+DOC", "-DOC", "+MAP", "-MAP", "+SEQ", "-SEQ", "=VAL", "=ALI"}

// String is t as the suite writes it.
func (t EventType) String() string { return eventTypeNames[t] }

// Style is the style of the scalar of an =VAL event.
type Style uint8

const (
	StyleUnset Style = iota
	StylePlain
	StyleSingle
	StyleDouble
	StyleLiteral
	StyleFolded
)

var styleChars = [...]byte{0, ':', '\'', '"', '|', '>'}

func (e Event) String() string {
	var b strings.Builder
	b.WriteString(e.Type.String())
	if e.Flow {
		if e.Type == EventMappingStart {
			b.WriteString(" {}")
		} else {
			b.WriteString(" []")
		}
	}
	if e.Explicit {
		if e.Type == EventDocumentStart {
			b.WriteString(" ---")
		} else {
			b.WriteString(" ...")
		}
	}
	if e.Anchor != "" {
		b.WriteString(" &" + e.Anchor)
	}
	if e.HasTag {
		b.WriteString(" <tag>")
	}
	if e.Alias != "" {
		b.WriteString(" *" + e.Alias)
	}
	if e.Style != StyleUnset {
		b.WriteString(" ")
		b.WriteByte(styleChars[e.Style])
	}
	return b.String()
}

// Load collects every directory under root that holds an in.yaml, skipping
// the name/ and tags/ indexes.
func Load(root string) ([]Case, error) {
	tops, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var cs []Case
	for _, d := range tops {
		if !d.IsDir() || d.Name() == "name" || d.Name() == "tags" {
			continue
		}
		dir := filepath.Join(root, d.Name())
		if _, err := os.Stat(filepath.Join(dir, "in.yaml")); err == nil {
			c, err := loadCase(dir, d.Name())
			if err != nil {
				return nil, err
			}
			cs = append(cs, c)
			continue
		}
		subs, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, s := range subs {
			if !s.IsDir() {
				continue
			}
			c, err := loadCase(filepath.Join(dir, s.Name()), d.Name()+"/"+s.Name())
			if err != nil {
				return nil, err
			}
			cs = append(cs, c)
		}
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].ID < cs[j].ID })
	return cs, nil
}

func loadCase(dir, id string) (Case, error) {
	c := Case{ID: id}
	var err error
	if c.In, err = os.ReadFile(filepath.Join(dir, "in.yaml")); err != nil {
		return c, err
	}
	name, err := os.ReadFile(filepath.Join(dir, "==="))
	if err != nil {
		return c, err
	}
	c.Name = strings.TrimSpace(string(name))
	ev, err := os.ReadFile(filepath.Join(dir, "test.event"))
	if err != nil {
		return c, err
	}
	if c.Events, err = ParseEvents(ev); err != nil {
		return c, fmt.Errorf("%s: %w", id, err)
	}
	_, err = os.Stat(filepath.Join(dir, "error"))
	c.Error = err == nil
	return c, nil
}

func ParseEvents(b []byte) ([]Event, error) {
	var evs []Event
	for line := range bytes.SplitSeq(b, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		e, err := parseEvent(string(line))
		if err != nil {
			return nil, err
		}
		evs = append(evs, e)
	}
	return evs, nil
}

func parseEvent(line string) (Event, error) {
	if len(line) < 4 {
		return Event{}, fmt.Errorf("short event line %q", line)
	}
	typ := slices.Index(eventTypeNames[:], line[:4])
	if typ <= 0 {
		return Event{}, fmt.Errorf("unknown event %q", line)
	}
	e := Event{Type: EventType(typ)}
	rest := strings.TrimPrefix(line[4:], " ")
	for rest != "" {
		if st := bytes.IndexByte(styleChars[1:], rest[0]); e.Type == EventScalar && st >= 0 {
			e.Style = Style(st + 1)
			v, err := unescape(rest[1:])
			if err != nil {
				return Event{}, fmt.Errorf("%w in %q", err, line)
			}
			e.Value = v
			return e, nil
		}
		var field string
		if rest[0] == '<' {
			end := strings.IndexByte(rest, '>')
			if end < 0 {
				return Event{}, fmt.Errorf("unterminated tag in %q", line)
			}
			field, rest = rest[:end+1], strings.TrimPrefix(rest[end+1:], " ")
		} else {
			field, rest, _ = strings.Cut(rest, " ")
		}
		switch {
		case field == "{}" || field == "[]":
			e.Flow = true
		case field == "---" || field == "...":
			e.Explicit = true
		case field[0] == '&':
			e.Anchor = field[1:]
		case field[0] == '<':
			e.HasTag = true
			e.Tag = field[1 : len(field)-1]
		case field[0] == '*':
			e.Alias = field[1:]
		default:
			return Event{}, fmt.Errorf("unknown field %q in %q", field, line)
		}
	}
	if e.Type == EventScalar {
		return Event{}, errors.New("=VAL without a style: " + line)
	}
	return e, nil
}

// unescape reverses the escaping of test.event values. The suite does not
// document it; these five are the escapes data-2022-01-17 contains, and any
// other one is an error so that a new data release cannot pass silently.
func unescape(s string) (string, error) {
	if strings.IndexByte(s, '\\') < 0 {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		i++
		if i == len(s) {
			return "", errors.New("trailing backslash")
		}
		switch s[i] {
		case '\\':
			b.WriteByte('\\')
		case 'b':
			b.WriteByte('\b')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		default:
			return "", fmt.Errorf("unknown escape \\%c", s[i])
		}
	}
	return b.String(), nil
}
