package facts

import (
	"context"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/internal/enumtest"
)

// TestEnums: every type of enum_gen.go, by enumtest.Check.
func TestEnums(t *testing.T) {
	in := func(def string) func([]byte) error {
		return func(b []byte) error { return schema().Validate(SchemaName, "#/$defs/"+def, b) }
	}
	// x-go-zero: unknown is the zero State, and a value
	t.Run("state", func(t *testing.T) { enumtest.Check(t, len(stateNames), true, ParseState, in("state")) })
	t.Run("provider", func(t *testing.T) { enumtest.Check(t, len(providerNames), false, ParseProvider, in("provider")) })
	if StateUnknown != 0 || StateUnknown.String() != "unknown" {
		t.Errorf("the zero State is %v", State(0))
	}
}

// TestFileOfEveryState: a file of facts with an entry of
// each state is read, and written again the same.
func TestFileOfEveryState(t *testing.T) {
	src := "{\"schema\":\"sisakulint/facts/v0\",\"facts\":[\n" +
		`{"query":{"kind":"test.flag","name":"a"},"state":"unknown","reason":"rate limit"},` + "\n" +
		`{"query":{"kind":"test.flag","name":"b"},"state":"found","value":true},` + "\n" +
		`{"query":{"kind":"test.flag","name":"c"},"state":"absent"}` + "\n]}\n"
	s, err := LoadStore([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	rec := NewRecorder(s)
	for _, n := range []string{"a", "b", "c"} {
		rec.Resolve(context.Background(), TestFlag{Name: n})
	}
	b, err := EncodeFile(rec.Entries())
	if err != nil || string(b) != src {
		t.Errorf("EncodeFile = %s, %v; want\n%s", b, err, src)
	}
}
