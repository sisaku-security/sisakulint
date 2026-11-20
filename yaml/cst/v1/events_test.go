package cst

import (
	"strings"

	"github.com/sisaku-security/sisakulint/yaml/cst/v1/internal/suitetest"
)

// events renders the tree as yaml-test-suite events without scalar values,
// using only the typed read API.
func events(tr *Tree) []suitetest.Event {
	evs := []suitetest.Event{{Type: suitetest.EventStreamStart}}
	for e := range tr.Root().Children() {
		doc, ok := e.Node()
		if !ok || doc.Kind() != NodeDocument {
			continue
		}
		start, end := false, false
		for de := range doc.Children() {
			if k, ok := de.Token(); ok {
				start = start || k.Kind() == TokDocStart
				end = end || k.Kind() == TokDocEnd
			}
		}
		evs = append(evs, suitetest.Event{Type: suitetest.EventDocumentStart, Explicit: start})
		for de := range doc.Children() {
			if c, ok := de.Node(); ok && c.Kind() != NodeDirective && c.Kind() != NodeError {
				evs = nodeEvents(evs, c)
			}
		}
		evs = append(evs, suitetest.Event{Type: suitetest.EventDocumentEnd, Explicit: end})
	}
	return append(evs, suitetest.Event{Type: suitetest.EventStreamEnd})
}

func nodeEvents(evs []suitetest.Event, n Node) []suitetest.Event {
	props := func(e suitetest.Event) suitetest.Event {
		if a, ok := n.Anchor(); ok {
			e.Anchor = strings.TrimPrefix(string(a.Bytes()), "&")
		}
		_, e.HasTag = n.Tag()
		return e
	}
	if m, ok := n.Mapping(); ok {
		evs = append(evs, props(suitetest.Event{Type: suitetest.EventMappingStart, Flow: n.IsFlow()}))
		for e := range m.Entries() {
			evs = nodeEvents(evs, e.Key)
			evs = nodeEvents(evs, e.Value)
		}
		return append(evs, suitetest.Event{Type: suitetest.EventMappingEnd})
	}
	if s, ok := n.Sequence(); ok {
		evs = append(evs, props(suitetest.Event{Type: suitetest.EventSequenceStart, Flow: n.IsFlow()}))
		for it := range s.Items() {
			evs = nodeEvents(evs, it)
		}
		return append(evs, suitetest.Event{Type: suitetest.EventSequenceEnd})
	}
	if n.Kind() == NodeAlias {
		return append(evs, suitetest.Event{Type: suitetest.EventAlias, Alias: strings.TrimPrefix(string(n.Bytes()), "*")})
	}
	return append(evs, props(suitetest.Event{Type: suitetest.EventScalar, Style: styleChar[n.Style()]}))
}

var styleChar = map[ScalarStyle]suitetest.Style{Plain: suitetest.StylePlain, SingleQuoted: suitetest.StyleSingle, DoubleQuoted: suitetest.StyleDouble, Literal: suitetest.StyleLiteral, Folded: suitetest.StyleFolded}

// skeleton is Parse followed by events, one event per line.
func skeleton(src string) string {
	var lines []string
	for _, e := range events(Parse([]byte(src))) {
		lines = append(lines, e.String())
	}
	return strings.Join(lines, "\n")
}
