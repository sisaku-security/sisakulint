package shell

import (
	"reflect"
	"testing"
)

// FuzzReadAtTree: the tree of a script tokenized with the places of its
// expressions is the tree of Parse, so that one tokenizing serves the
// tree and the places.
func FuzzReadAtTree(f *testing.F) {
	for _, s := range []string{
		"echo aaaaaaaaaaaa",
		"echo \"aaaaaaaaaaaa\" > $GITHUB_ENV",
		"x=aaaaaaaaaaaa; cat <<EOF\naaaaaaaaaaaa\nEOF\n",
		"if [ aaaaaaaaaaaa ]; then echo $(aaaaaaaaaaaa); fi",
		"aaaaaaaaaaaa'b'\"c\"",
	} {
		f.Add(s, 5)
	}
	f.Fuzz(func(t *testing.T, script string, at int) {
		var ats []int
		if at >= 0 && at < len(script) {
			ats = []int{at}
		}
		if got, want := ReadAt(script, ats).Script, Parse(script); !reflect.DeepEqual(got, want) {
			t.Errorf("the tree with at %v differs from Parse of %q", ats, script)
		}
	})
}

// TestReadAtPlaces: the places are those of Places.
func TestReadAtPlaces(t *testing.T) {
	s := "echo aaaa \"bbbb\" 'cccc'"
	at := []int{5, 11, 18}
	if got, want := ReadAt(s, at).Places, Places(s, at); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestMemoReadsOnce: a Memo reads a script and places once.
func TestMemoReadsOnce(t *testing.T) {
	m := NewMemo()
	a := m.Read("echo aaaa", []int{5})
	b := m.Read("echo aaaa", []int{5})
	if a.Script != b.Script || m.n != 1 {
		t.Errorf("read %d times", m.n)
	}
	if c := m.Read("echo aaaa", nil); c.Script == a.Script || m.n != 2 {
		t.Errorf("another at is another read")
	}
}

// TestMemoVisibilityOnce: a Memo reads the NameVisibility of a tree once;
// a nil Memo reads it each time.
func TestMemoVisibilityOnce(t *testing.T) {
	src := "x=1; echo $x"
	m := NewMemo()
	sc := m.Read(src, nil).Script
	if a, b := m.Visibility(src, sc), m.Visibility(src, sc); a != b {
		t.Errorf("read twice")
	}
	var nilMemo *Memo
	if a, b := nilMemo.Visibility(src, sc), nilMemo.Visibility(src, sc); a == b || a == nil {
		t.Errorf("a nil Memo kept a reading")
	}
}
