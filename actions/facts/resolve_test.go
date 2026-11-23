package facts

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/internal/jsonschema"
)

func TestFirst(t *testing.T) {
	ctx := context.Background()
	q := TestFlag{Name: "a"}
	unknown := answerWith(RawAnswer{State: StateUnknown, Reason: "one"})
	unknown2 := answerWith(RawAnswer{State: StateUnknown, Reason: "two"})
	yes := answerWith(RawAnswer{State: StateFound, Value: json.RawMessage(`true`)})
	if r := First(unknown, yes, unknown2).Resolve(ctx, q); r.State != StateFound {
		t.Errorf("First(unknown, yes) = %+v", r)
	}
	if r := First(unknown, unknown2).Resolve(ctx, q); r.State != StateUnknown || r.Reason != "two" {
		t.Errorf("First(unknown, unknown) = %+v, want the last unknown", r)
	}
	if r := First().Resolve(ctx, q); r.State != StateUnknown || r.Reason == "" {
		t.Errorf("First() = %+v", r)
	}
	bad := answerWith(RawAnswer{State: StateFound, Value: json.RawMessage(`"x"`)})
	if r := First(bad, yes).Resolve(ctx, q); r.State != StateFound || string(r.Value) != "true" {
		t.Errorf("a value off x-value must not stop First: %+v", r)
	}
}

func TestRecorder(t *testing.T) {
	ctx := context.Background()
	calls := 0
	rec := NewRecorder(resolverFunc(func(_ context.Context, q Query) RawAnswer {
		calls++
		if q.Kind() == KindTestList {
			return RawAnswer{State: StateFound, Value: json.RawMessage(` [ "b" ] `)}
		}
		return RawAnswer{State: StateAbsent}
	}))
	a := mustRepo(t, "Org/App")
	for _, q := range []Query{TestList{Name: "z"}, TestFlag{Name: "a"}, TestRepoFlag{Repo: a}, TestRepoFlag{Repo: mustRepo(t, "org/app")}, TestFlag{Name: "a"}} {
		rec.Resolve(ctx, q)
	}
	if calls != 3 {
		t.Errorf("the resolver below was called %d times, want 3", calls)
	}
	var got []string
	for _, e := range rec.Entries() {
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, string(b))
	}
	want := []string{
		`{"query":{"kind":"test.flag","name":"a"},"state":"absent"}`,
		`{"query":{"kind":"test.list","name":"z"},"state":"found","value":["b"]}`,
		`{"query":{"kind":"test.repo-flag","repo":"org/app"},"state":"absent"}`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("Entries =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestRecorderRefusesWhatCannotBeWritten(t *testing.T) {
	calls := 0
	rec := NewRecorder(resolverFunc(func(context.Context, Query) RawAnswer { calls++; return RawAnswer{State: StateAbsent} }))
	r := rec.Resolve(context.Background(), TestRepoFlag{})
	if r.State != StateUnknown || r.Reason == "" || calls != 0 || len(rec.Entries()) != 0 {
		t.Errorf("a zero Repo: %+v, calls %d, entries %d", r, calls, len(rec.Entries()))
	}
}

func TestRecorderFileReplays(t *testing.T) {
	ctx := context.Background()
	online := resolverFunc(func(_ context.Context, q Query) RawAnswer {
		switch q.(type) {
		case TestFlag:
			return RawAnswer{State: StateFound, Value: json.RawMessage(`true`)}
		case TestText:
			return RawAnswer{State: StateUnknown, Reason: "rate limit"}
		}
		return RawAnswer{State: StateAbsent}
	})
	qs := []Query{TestFlag{Name: "a"}, TestText{Name: "t"}, TestRepoFlag{Repo: mustRepo(t, "o/r")}}
	rec := NewRecorder(online)
	for _, q := range qs {
		rec.Resolve(ctx, q)
	}
	b, err := rec.WriteFile()
	if err != nil {
		t.Fatal(err)
	}
	set, err := jsonschema.Load(map[string][]byte{SchemaName: schemaJSON}, jsonschema.Options{SchemaAnnotations: []string{"x-value"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := set.Validate(SchemaName, "#/$defs/file", b); err != nil {
		t.Errorf("WriteFile does not fit $defs/file: %v\n%s", err, b)
	}
	store, err := LoadStore(b)
	if err != nil {
		t.Fatalf("LoadStore(WriteFile): %v\n%s", err, b)
	}
	for _, q := range qs {
		if got, want := store.Resolve(ctx, q), rec.Resolve(ctx, q); got.State != want.State || string(got.Value) != string(want.Value) || got.Reason != want.Reason {
			t.Errorf("%#v: replayed %+v, recorded %+v", q, got, want)
		}
	}
	again := NewRecorder(store)
	for _, q := range qs {
		again.Resolve(ctx, q)
	}
	b2, _ := again.WriteFile()
	if string(b2) != string(b) {
		t.Errorf("the replay writes another file:\n%s\n%s", b, b2)
	}
}
