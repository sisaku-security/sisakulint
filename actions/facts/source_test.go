package facts

import (
	"context"
	"strings"
	"testing"
)

// Each answer says where it comes from: a file of facts, the assumptions,
// or (in actions/facts/github) the API; Checked, First and a Recorder keep
// it, a report writes it, and a file of facts does not.
func TestSource(t *testing.T) {
	ctx := context.Background()
	q := TestFlag{Name: "a"}
	s, err := LoadStore([]byte(`{"schema": "sisakulint/facts/v0", "facts": [{"query": {"kind": "test.flag", "name": "a"}, "state": "found", "value": true}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if r := s.Resolve(ctx, q); r.Source != SourceFile {
		t.Errorf("the file: %+v", r)
	}
	if r := Assume(resolverFunc(func(context.Context, Query) RawAnswer { return RawAnswer{State: StateUnknown, Reason: "offline"} })).Resolve(ctx, RepoWikiOpen{}); r.Source != SourceAssumption || !r.Assumed() {
		t.Errorf("the assumption: %+v", r)
	}
	rec := NewRecorder(First(s))
	if r := rec.Resolve(ctx, q); r.Source != SourceFile {
		t.Errorf("First and the Recorder: %+v", r)
	}
	b, err := Entry{q, rec.Resolve(ctx, q)}.MarshalJSON()
	if err != nil || !strings.Contains(string(b), `"source":"file"`) {
		t.Errorf("the entry: %s %v", b, err)
	}
	f, err := EncodeFile(rec.Entries())
	if err != nil || strings.Contains(string(f), "source") {
		t.Errorf("the file of facts: %s %v", f, err)
	}
	// a report's entries, with their sources, read as a file of facts
	if _, err := LoadStore([]byte(`{"schema": "sisakulint/facts/v0", "facts": [` + string(b) + `]}`)); err != nil {
		t.Errorf("a file with a source: %v", err)
	}
}
