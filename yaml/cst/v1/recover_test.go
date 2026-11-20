package cst

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// entryKeys lists the keys of the first block mapping.
func entryKeys(tr *Tree) []string {
	m, _ := firstNode(tr.Root(), NodeBlockMapping).Mapping()
	var ks []string
	for e := range m.Entries() {
		ks = append(ks, string(e.Key.Bytes()))
	}
	return ks
}

func TestRecovery(t *testing.T) {
	cases := []struct {
		src   string
		code  ErrorCode
		keys  []string // keys of the first block mapping after recovery; nil: not checked
		error string   // bytes of the first Error node; "" : none expected
	}{
		{"a: [b, c\nd: e\n", ErrUnclosedFlow, []string{"a", "d"}, ""},
		{"a: b\n c: d\ne: f\n", ErrUnexpected, []string{"a", "e"}, ": d"}, // the plain value is "b c"
		{"a: b\nc\nd: e\n", ErrUnexpected, []string{"a", "d"}, "c\n"},
		{"a:\n  b: c\n  d\n  e: f\ng: h\n", ErrUnexpected, []string{"a", "g"}, "  d\n"},
		{"key:\n- a\n- b\nother: x\n", 0, []string{"key", "other"}, ""},
		{"a: [b, c: d: e, f]\n", ErrUnexpected, []string{"a"}, ": e"},
		{"a: {b: c, d\ng: h\n", ErrUnclosedFlow, []string{"a", "g"}, ""},
		{"[a, b", ErrUnclosedFlow, nil, ""},
		{"]]]", ErrUnexpected, nil, "]]]"},
		{"- a\n- b\n  c: d\n- e\n", ErrUnexpected, nil, ": d"},
	}
	for _, c := range cases {
		tr := Parse([]byte(c.src))
		if err := validate(tr); err != nil {
			t.Errorf("%q: %v", c.src, err)
			continue
		}
		got := codes(tr)
		if c.code == 0 && len(got) > 0 || c.code != 0 && !slices.Contains(got, c.code) {
			t.Errorf("%q: errors %v, want code %d", c.src, tr.Errors(), c.code)
		}
		if c.keys != nil {
			if ks := entryKeys(tr); !slices.Equal(ks, c.keys) {
				t.Errorf("%q: keys %q, want %q", c.src, ks, c.keys)
			}
		}
		e := firstNode(tr.Root(), NodeError)
		if c.error != "" && (e.t == nil || string(e.Bytes()) != c.error) {
			var b []byte
			if e.t != nil {
				b = e.Bytes()
			}
			t.Errorf("%q: Error node %q, want %q", c.src, b, c.error)
		}
	}
}

// The time is compared with ACTIONS_SCALE=1 only, as it depends on the
// machine.
func TestDepthLimit(t *testing.T) {
	for _, src := range []string{
		strings.Repeat("[", 100000),
		strings.Repeat("- ", 5000) + "a\n",
		strings.Repeat("{a: ", 3000) + "b" + strings.Repeat("}", 3000),
	} {
		start := time.Now()
		tr := Parse([]byte(src))
		if d := time.Since(start); os.Getenv("ACTIONS_SCALE") == "1" && d > 5*time.Second {
			t.Errorf("%.20q…: took %v", src, d)
		}
		if err := validate(tr); err != nil {
			t.Errorf("%.20q…: %v", src, err)
		}
		if !slices.Contains(codes(tr), ErrDepth) {
			t.Errorf("%.20q…: errors %v, want ErrDepth", src, codes(tr))
		}
	}
}

// The time is compared with ACTIONS_SCALE=1 only, as it depends on the
// machine.
func TestNestedFlowIsFast(t *testing.T) {
	for _, src := range []string{
		strings.Repeat("[", 200) + "a" + strings.Repeat("]", 200),
		strings.Repeat("[a: ", 200) + "b" + strings.Repeat("]", 200),
		"k: " + strings.Repeat("{", 200) + "a" + strings.Repeat("}", 200),
	} {
		start := time.Now()
		tr := Parse([]byte(src))
		if d := time.Since(start); os.Getenv("ACTIONS_SCALE") == "1" && d > time.Second {
			t.Errorf("%.20q…: took %v", src, d)
		}
		if len(tr.Errors()) > 0 {
			t.Errorf("%.20q…: errors %v", src, tr.Errors())
		}
	}
}

// Implicit keys longer than 1024 characters are invalid; nesting them must
// still fail fast rather than retry every level. The time is compared with
// ACTIONS_SCALE=1 only, as it depends on the machine.
func TestLongNestedKeysFailFast(t *testing.T) {
	for _, d := range []int{500, 1000, 5000} {
		src := strings.Repeat("[", d) + "a" + strings.Repeat("]: x", d)
		start := time.Now()
		tr := Parse([]byte(src))
		if el := time.Since(start); os.Getenv("ACTIONS_SCALE") == "1" && el > time.Second {
			t.Errorf("depth %d: took %v", d, el)
		}
		if err := validate(tr); err != nil {
			t.Errorf("depth %d: %v", d, err)
		}
		if len(tr.Errors()) == 0 {
			t.Errorf("depth %d: no error", d)
		}
	}
}

// Nested flow collections that fail inside an implicit key must not retry
// every level. The time is compared with ACTIONS_SCALE=1
// only, as it depends on the machine.
func TestFailingNestedKeysAreFast(t *testing.T) {
	for _, src := range []string{
		strings.Repeat("[", 22) + "a,," + strings.Repeat("]: x", 22) + ": y\n",
		"k: " + strings.Repeat("[", 22) + "a,," + strings.Repeat("]: x", 22) + "\n",
		strings.Repeat("[{", 100) + "a,," + strings.Repeat("}]", 100) + "\n",
		strings.Repeat("[{", 100) + "a" + strings.Repeat("}]: x", 100) + "\n",
	} {
		start := time.Now()
		tr := Parse([]byte(src))
		if d := time.Since(start); os.Getenv("ACTIONS_SCALE") == "1" && d > time.Second {
			t.Errorf("%.30q…: took %v", src, d)
		}
		if err := validate(tr); err != nil {
			t.Errorf("%.30q…: %v", src, err)
		}
	}
}
