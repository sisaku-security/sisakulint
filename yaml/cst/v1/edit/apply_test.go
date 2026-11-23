package edit

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

func at(src, sub string) cst.Span {
	i := strings.Index(src, sub)
	if i < 0 {
		panic(sub + " not in " + src)
	}
	return cst.Span{Start: i, End: i + len(sub)}
}

func mustApply(t *testing.T, tr *cst.Tree, edits ...Edit) Result {
	t.Helper()
	res, err := Apply(tr, edits)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	back, err := Apply(res.Tree, res.Inverse)
	if err != nil {
		t.Fatalf("Apply of the inverse: %v", err)
	}
	if !bytes.Equal(back.Tree.Bytes(), tr.Bytes()) {
		t.Fatalf("the inverse gives %q, want %q", back.Tree.Bytes(), tr.Bytes())
	}
	return res
}

func TestApply(t *testing.T) {
	src := "a: b\nc: d\n"
	tr := cst.Parse([]byte(src))
	res := mustApply(t, tr,
		Edit{Span: at(src, "d"), Old: []byte("d"), New: []byte("dd")},
		Edit{Span: at(src, "b"), New: []byte("")},
		Edit{Span: cst.Span{Start: 0, End: 0}, New: []byte("# x\n")},
	)
	if got := string(res.Tree.Bytes()); got != "# x\na: \nc: dd\n" {
		t.Errorf("result %q", got)
	}
	if string(tr.Bytes()) != src {
		t.Errorf("the original bytes changed to %q", tr.Bytes())
	}
}

func TestApplyOrder(t *testing.T) {
	src := "a: b\n"
	tr := cst.Parse([]byte(src))
	b := at(src, "b")
	// insertions just before and after a replacement are allowed
	res := mustApply(t, tr,
		Edit{Span: cst.Span{Start: b.End, End: b.End}, New: []byte("3")},
		Edit{Span: b, New: []byte("2")},
		Edit{Span: cst.Span{Start: b.Start, End: b.Start}, New: []byte("1")},
	)
	if got := string(res.Tree.Bytes()); got != "a: 123\n" {
		t.Errorf("result %q", got)
	}
}

func TestApplyRejects(t *testing.T) {
	src := "a: bcd\n"
	tr := cst.Parse([]byte(src))
	cases := map[string][]Edit{
		"out of range":   {{Span: cst.Span{Start: 3, End: 99}}},
		"negative":       {{Span: cst.Span{Start: -1, End: 1}}},
		"start > end":    {{Span: cst.Span{Start: 4, End: 3}}},
		"old differs":    {{Span: at(src, "b"), Old: []byte("x"), New: []byte("y")}},
		"overlap":        {{Span: at(src, "bc"), New: []byte("x")}, {Span: at(src, "cd"), New: []byte("y")}},
		"inside":         {{Span: at(src, "bcd"), New: []byte("x")}, {Span: cst.Span{Start: 4, End: 4}, New: []byte("y")}},
		"same insertion": {{Span: cst.Span{Start: 3, End: 3}, New: []byte("x")}, {Span: cst.Span{Start: 3, End: 3}, New: []byte("y")}},
		"new error":      {{Span: at(src, "bcd"), New: []byte(`"unclosed`)}},
	}
	for name, edits := range cases {
		res, err := Apply(tr, edits)
		var e *Error
		if err == nil || !errors.As(err, &e) || res.Tree != nil {
			t.Errorf("%s: Apply = %v, %v", name, res.Tree, err)
		}
	}
	if string(tr.Bytes()) != src {
		t.Errorf("the original bytes changed to %q", tr.Bytes())
	}
}

// An edit made from a tree is refused on the tree that an earlier Apply
// returned, where its range means something else.
func TestApplyStaleEdit(t *testing.T) {
	src := "a: b\nc: d\n"
	tr := cst.Parse([]byte(src))
	e1 := Edit{Span: at(src, "b"), Old: []byte("b"), New: []byte("bbb")}
	e2 := Edit{Span: at(src, "d"), Old: []byte("d"), New: []byte("x")}
	res := mustApply(t, tr, e1)
	if _, err := Apply(res.Tree, []Edit{e2}); err == nil {
		t.Error("a stale edit was applied")
	}
}

func TestApplyKeepsOldErrors(t *testing.T) {
	src := "a: \"\\q\"\nb: c\n" // ErrInvalidEscape at \q
	tr := cst.Parse([]byte(src))
	if len(tr.Errors()) != 1 {
		t.Fatalf("setup: %v", tr.Errors())
	}
	res := mustApply(t, tr, Edit{Span: at(src, "c"), New: []byte("ccc")})
	if len(res.Tree.Errors()) != 1 {
		t.Errorf("errors %v", res.Tree.Errors())
	}
	// an edit on the error's range cannot keep it: the error is new
	if _, err := Apply(tr, []Edit{{Span: at(src, `\q`), New: []byte(`\z`)}}); err == nil {
		t.Error("an edit over an error was accepted")
	}
}

// TestApplyManyEdits: many edits in one Apply. The time is compared with
// ACTIONS_SCALE=1 only, as it depends on the machine.
func TestApplyManyEdits(t *testing.T) {
	var b strings.Builder
	for i := range 1000 {
		b.WriteString("k")
		b.WriteString(strings.Repeat("x", i%7))
		b.WriteString(": v\n")
	}
	src := b.String()
	tr := cst.Parse([]byte(src))
	var edits []Edit
	for i := 0; i+1 < len(src); i++ {
		if src[i] == 'v' {
			edits = append(edits, Edit{Span: cst.Span{Start: i, End: i + 1}, Old: []byte("v"), New: []byte("ww")})
		}
	}
	start := time.Now()
	res := mustApply(t, tr, edits...)
	if d := time.Since(start); os.Getenv("ACTIONS_SCALE") == "1" && d > time.Second {
		t.Errorf("%d edits took %v", len(edits), d)
	}
	if strings.Count(string(res.Tree.Bytes()), "ww") != 1000 {
		t.Error("not every edit was applied")
	}
}

// An edit that writes the bytes it replaces does nothing, so it neither
// overlaps nor takes a place from another edit.
func TestApplyNoop(t *testing.T) {
	src := "a: bcd\n"
	tr := cst.Parse([]byte(src))
	res := mustApply(t, tr,
		Edit{Span: cst.Span{Start: 3, End: 3}, New: []byte{}},
		Edit{Span: cst.Span{Start: 3, End: 3}, New: nil},
		Edit{Span: at(src, "bcd"), New: []byte("bcd")},
		Edit{Span: at(src, "c"), New: []byte("x")},
	)
	if got := string(res.Tree.Bytes()); got != "a: bxd\n" {
		t.Errorf("got %q", got)
	}
}

// An edit may remove an error the input had. Undoing it brings the error
// back, which the syntax check would refuse; the inverse is not checked,
// since it restores bytes that were read before.
func TestApplyUndoBringsErrorsBack(t *testing.T) {
	src := "- item1\n- item2\ninvalid\n"
	tr := cst.Parse([]byte(src))
	if len(tr.Errors()) == 0 {
		t.Fatal("setup: no error")
	}
	res := mustApply(t, tr, Edit{Span: cst.Span{Start: 0, End: 0}, New: []byte("x")})
	if len(res.Tree.Errors()) != 0 {
		t.Fatalf("setup: the edit keeps errors %v", res.Tree.Errors())
	}
}

// The inverse skips the syntax check only when it restores the bytes it
// was made from: a stale inverse, a changed copy and part of an inverse
// are checked.
func TestApplyUndoIsChecked(t *testing.T) {
	src := "a: 1\nb: 2\n"
	tr := cst.Parse([]byte(src))
	r1 := mustApply(t, tr, Edit{Span: cst.Span{Start: 3, End: 4}, New: []byte("|")})
	r2 := mustApply(t, r1.Tree, Edit{Span: cst.Span{Start: 5, End: 9}, New: []byte("  x: y")})
	if len(r2.Tree.Errors()) != 0 {
		t.Fatalf("setup: %q has errors", r2.Tree.Bytes())
	}
	if res, err := Apply(r2.Tree, r1.Inverse); err == nil {
		t.Errorf("a stale inverse gave %q", res.Tree.Bytes())
	}
	inv := r1.Inverse[0]
	inv.New = []byte("\"unclosed")
	if res, err := Apply(r1.Tree, []Edit{inv}); err == nil {
		t.Errorf("a changed inverse gave %q", res.Tree.Bytes())
	}
	inv.Span, inv.Old = cst.Span{Start: 0, End: 0}, nil
	other := cst.Parse([]byte("[a: 1]\n"))
	if res, err := Apply(other, []Edit{inv}); err == nil {
		t.Errorf("an inverse on another tree gave %q", res.Tree.Bytes())
	}
}
