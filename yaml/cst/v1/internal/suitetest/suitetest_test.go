package suitetest

import "testing"

const root = "../../../../yaml-test-suite/data-2022-01-17"

func TestLoadCounts(t *testing.T) {
	cs, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	nerr := 0
	seen := map[string]bool{}
	for _, c := range cs {
		if seen[c.ID] {
			t.Errorf("duplicate ID %s", c.ID)
		}
		seen[c.ID] = true
		if c.Error {
			nerr++
		}
	}
	if len(cs) != 402 || nerr != 94 {
		t.Errorf("cases %d (error %d), want 402 (94)", len(cs), nerr)
	}
	if !seen["2G84/00"] {
		t.Error("sub-case 2G84/00 missing")
	}
	for _, c := range cs {
		if c.ID == "229Q" {
			if len(c.Events) != 22 || c.Events[0].Type != EventStreamStart || c.Name == "" || len(c.In) == 0 {
				t.Errorf("229Q: %d events, first %v, name %q", len(c.Events), c.Events[0], c.Name)
			}
		}
	}
}

func TestParseEvents(t *testing.T) {
	cases := []struct {
		line string
		want Event
	}{
		{"+MAP {} &a <tag:yaml.org,2002:map>", Event{Type: EventMappingStart, Flow: true, Anchor: "a", HasTag: true, Tag: "tag:yaml.org,2002:map"}},
		{"=VAL &x <!foo> 'text with spaces", Event{Type: EventScalar, Anchor: "x", HasTag: true, Tag: "!foo", Style: StyleSingle, Value: "text with spaces"}},
		{"=VAL <!> 'a\\tb\\\\c\\bd\\re", Event{Type: EventScalar, HasTag: true, Tag: "!", Style: StyleSingle, Value: "a\tb\\c\bd\re"}},
		{"=VAL :", Event{Type: EventScalar, Style: StylePlain}},
		{"=VAL |a\\nb", Event{Type: EventScalar, Style: StyleLiteral, Value: "a\nb"}},
		{"=ALI *anc", Event{Type: EventAlias, Alias: "anc"}},
		{"+DOC ---", Event{Type: EventDocumentStart, Explicit: true}},
		{"-DOC ...", Event{Type: EventDocumentEnd, Explicit: true}},
		{"-DOC", Event{Type: EventDocumentEnd}},
		{"+SEQ []", Event{Type: EventSequenceStart, Flow: true}},
		{"+STR", Event{Type: EventStreamStart}},
	}
	for _, c := range cases {
		evs, err := ParseEvents([]byte(c.line + "\n"))
		if err != nil {
			t.Errorf("%q: %v", c.line, err)
			continue
		}
		if len(evs) != 1 || evs[0] != c.want {
			t.Errorf("%q = %+v, want %+v", c.line, evs, c.want)
		}
	}
	if _, err := ParseEvents([]byte("=VAL\n")); err == nil {
		t.Error("=VAL without a style was accepted")
	}
}

func TestEventString(t *testing.T) {
	e := Event{Type: EventScalar, Anchor: "x", HasTag: true, Tag: "!foo", Style: StyleDouble, Value: "v"}
	if got := e.String(); got != `=VAL &x <tag> "` {
		t.Errorf("String = %q", got)
	}
}

func TestTally(t *testing.T) {
	var tl Tally
	if tl.String() != "" {
		t.Errorf("empty tally = %q", tl.String())
	}
	tl.Count("b", t)
	tl.Count("a", t)
	tl.Count("a", t)
	if got := tl.String(); got != "a 2/2, b 1/1" {
		t.Errorf("tally = %q", got)
	}
}

func TestCorpusFiles(t *testing.T) {
	files, err := CorpusFiles(CorpusRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 7259 {
		t.Errorf("%d corpus files, want 7259", len(files))
	}
}

func TestRun(t *testing.T) {
	cs := []Case{{ID: "a"}, {ID: "b", Error: true}, {ID: "c"}}
	var tl Tally
	var ran []string
	Run(t, cs, "check", map[string]string{"c": "why"}, &tl, func(t *testing.T, c Case) { ran = append(ran, c.ID) })
	if len(ran) != 1 || ran[0] != "a" || tl.String() != "check 1/1" {
		t.Errorf("ran %v, tally %q", ran, tl.String())
	}
	a, err1 := LoadCached(root)
	b, err2 := LoadCached(root)
	if err1 != nil || err2 != nil || len(a) != 402 || &a[0] != &b[0] {
		t.Errorf("LoadCached: %v %v, %d cases", err1, err2, len(a))
	}
}
