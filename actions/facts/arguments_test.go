package facts

import (
	"context"
	"strings"
	"testing"
)

func TestArguments(t *testing.T) {
	ctx := context.Background()
	flag := func(name, v string) Entry {
		return Entry{TestFlag{Name: name}, RawAnswer{State: StateFound, Value: []byte(v)}}
	}
	r, err := Arguments([]Entry{flag("a", "true"), flag("b", "false")})
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Resolve(ctx, TestFlag{Name: "a"}); got.State != StateFound || string(got.Value) != "true" || got.Source != SourceArgument {
		t.Errorf("a = %+v", got)
	}
	if got := r.Resolve(ctx, TestFlag{Name: "c"}); got.State != StateUnknown || got.Reason == "" || got.Source != SourceUnset {
		t.Errorf("c = %+v", got)
	}
	// kept through a Recorder, and written to a file of facts
	rec := NewRecorder(r)
	rec.Resolve(ctx, TestFlag{Name: "a"})
	f, err := rec.WriteFile()
	if err != nil || !strings.Contains(string(f), `"name":"a"`) {
		t.Errorf("the file of facts: %s %v", f, err)
	}
	for _, c := range []struct {
		name    string
		entries []Entry
	}{
		{"twice", []Entry{flag("a", "true"), flag("a", "false")}},
		{"not a boolean", []Entry{flag("a", `"yes"`)}},
		{"absent", []Entry{{TestFlag{Name: "a"}, RawAnswer{State: StateAbsent}}}},
	} {
		if _, err := Arguments(c.entries); err == nil {
			t.Errorf("%s: no error", c.name)
		}
	}
}
