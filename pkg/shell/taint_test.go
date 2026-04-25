package shell

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// parseScript はテスト用のヘルパ。Bash として parse して *syntax.File を返す。
func parseScript(t *testing.T, src string) *syntax.File {
	t.Helper()
	p := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	file, err := p.Parse(strings.NewReader(src), "")
	if err != nil {
		t.Fatalf("parse failed: %v\nscript:\n%s", err, src)
	}
	return file
}

func TestWalkAssignments(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		script        string
		expected      []AssignmentInfo // Offset は無視（後続テストで検証）
		expectNilVal  []bool           // true の位置は Value が nil であることを期待する
	}{
		{
			name:   "simple_assignment",
			script: `X=hello`,
			expected: []AssignmentInfo{
				{Name: "X", Keyword: AssignNone},
			},
		},
		{
			name:   "two_assignments_one_line",
			script: `X=1; Y=2`,
			expected: []AssignmentInfo{
				{Name: "X", Keyword: AssignNone},
				{Name: "Y", Keyword: AssignNone},
			},
		},
		{
			name:   "export_keyword",
			script: `export X=value`,
			expected: []AssignmentInfo{
				{Name: "X", Keyword: AssignExport},
			},
		},
		{
			name:   "local_keyword",
			script: `local X=value`,
			expected: []AssignmentInfo{
				{Name: "X", Keyword: AssignLocal},
			},
		},
		{
			name:   "readonly_keyword",
			script: `readonly X=value`,
			expected: []AssignmentInfo{
				{Name: "X", Keyword: AssignReadonly},
			},
		},
		{
			name:   "local_no_value",
			script: `local X`,
			expected: []AssignmentInfo{
				{Name: "X", Value: nil, Keyword: AssignLocal},
			},
			expectNilVal: []bool{true},
		},
		{
			name:   "comment_line_excluded",
			script: "# X=hello\nY=world",
			expected: []AssignmentInfo{
				{Name: "Y", Keyword: AssignNone},
			},
		},
		{
			name:   "heredoc_body_excluded",
			script: "cat <<EOF\nX=fake\nEOF\nY=real",
			expected: []AssignmentInfo{
				{Name: "Y", Keyword: AssignNone},
			},
		},
		{
			name:     "no_assignments",
			script:   `echo hello`,
			expected: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			file := parseScript(t, tc.script)
			got := WalkAssignments(file)
			if len(got) != len(tc.expected) {
				t.Fatalf("len mismatch: got %d, want %d (got=%+v)", len(got), len(tc.expected), got)
			}
			for i, want := range tc.expected {
				if got[i].Name != want.Name {
					t.Errorf("[%d] Name: got %q, want %q", i, got[i].Name, want.Name)
				}
				if got[i].Keyword != want.Keyword {
					t.Errorf("[%d] Keyword: got %v, want %v", i, got[i].Keyword, want.Keyword)
				}
				// expectNilVal が指定されている場合のみ Value の nil を確認する。
				// 指定がない場合は「値あり」を暗黙的に期待する（非 nil）。
				if i < len(tc.expectNilVal) {
					wantNil := tc.expectNilVal[i]
					gotNil := got[i].Value == nil
					if gotNil != wantNil {
						t.Errorf("[%d] Value nil mismatch: got nil=%v, want nil=%v",
							i, gotNil, wantNil)
					}
				}
			}
		})
	}
}

func TestWordReferencesEntry(t *testing.T) {
	t.Parallel()

	tainted := map[string]Entry{
		"X": {Sources: []string{"secrets.X"}, Offset: -1},
		"Y": {Sources: []string{"secrets.Y"}, Offset: -1},
	}

	cases := []struct {
		name      string
		script    string
		wantName  string
		wantFound bool
	}{
		{"plain_param", `Z=$X`, "X", true},
		{"braced_param", `Z=${X}`, "X", true},
		{"quoted_param", `Z="$X"`, "X", true},
		{"quoted_braced", `Z="${X}"`, "X", true},
		{"not_referenced", `Z=literal`, "", false},
		{"first_match_X", `Z="prefix$X-suffix$Y"`, "X", true},
		{"first_match_Y", `Z="$Y$X"`, "Y", true},
		{"untracked_var", `Z="$UNTRACKED"`, "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			file := parseScript(t, tc.script)
			assigns := WalkAssignments(file)
			if len(assigns) != 1 || assigns[0].Value == nil {
				t.Fatalf("unexpected assigns: %+v", assigns)
			}
			gotName, gotFound := WordReferencesEntry(assigns[0].Value, tainted)
			if gotName != tc.wantName || gotFound != tc.wantFound {
				t.Errorf("got (%q, %v), want (%q, %v)", gotName, gotFound, tc.wantName, tc.wantFound)
			}
		})
	}
}

func TestPropagateTaint(t *testing.T) {
	t.Parallel()

	envEntry := func(src string) Entry {
		return Entry{Sources: []string{src}, Offset: -1}
	}

	cases := []struct {
		name        string
		script      string
		initial     map[string]Entry
		wantNames   []string
		wantSources map[string][]string
	}{
		{
			name:      "empty_initial",
			script:    `Y=$X`,
			initial:   map[string]Entry{},
			wantNames: []string{},
		},
		{
			name:      "direct_propagation",
			script:    `Y=$X`,
			initial:   map[string]Entry{"X": envEntry("secrets.X")},
			wantNames: []string{"X", "Y"},
			wantSources: map[string][]string{
				"Y": {"shellvar:X"},
			},
		},
		{
			name:      "concatenation_multiple_sources",
			script:    `Z="$A$B"`,
			initial:   map[string]Entry{"A": envEntry("secrets.A"), "B": envEntry("secrets.B")},
			wantNames: []string{"A", "B", "Z"},
		},
		{
			name:      "no_propagation_if_not_referenced",
			script:    `Z=literal`,
			initial:   map[string]Entry{"X": envEntry("secrets.X")},
			wantNames: []string{"X"},
		},
		{
			name:      "comment_line_not_propagated",
			script:    "# Y=$X\nZ=$X",
			initial:   map[string]Entry{"X": envEntry("secrets.X")},
			wantNames: []string{"X", "Z"},
		},
		{
			name:      "heredoc_body_not_propagated",
			script:    "cat <<EOF\nY=$X\nEOF\nZ=$X",
			initial:   map[string]Entry{"X": envEntry("secrets.X")},
			wantNames: []string{"X", "Z"},
		},
		{
			name:      "one_liner_two_assigns",
			script:    `A=$X; B=$X`,
			initial:   map[string]Entry{"X": envEntry("secrets.X")},
			wantNames: []string{"X", "A", "B"},
		},
		{
			name:      "subshell_flat_namespace",
			script:    `(Y=$X)`,
			initial:   map[string]Entry{"X": envEntry("secrets.X")},
			wantNames: []string{"X", "Y"},
		},
		{
			name:   "first_taint_preserved_on_reassign",
			script: "Y=$X\nY=$Z\n",
			initial: map[string]Entry{
				"X": envEntry("secrets.X"),
				"Z": envEntry("secrets.Z"),
			},
			wantNames: []string{"X", "Z", "Y"},
			wantSources: map[string][]string{
				"Y": {"shellvar:X"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			file := parseScript(t, tc.script)
			got := PropagateTaint(file, tc.initial)

			for _, name := range tc.wantNames {
				if _, ok := got[name]; !ok {
					t.Errorf("expected tainted var %q not found in result; got=%+v", name, got)
				}
			}

			for name, wantSrcs := range tc.wantSources {
				gotSrcs := got[name].Sources
				if len(gotSrcs) != len(wantSrcs) {
					t.Errorf("var %q sources len: got %d, want %d (got=%v, want=%v)",
						name, len(gotSrcs), len(wantSrcs), gotSrcs, wantSrcs)
					continue
				}
				for i := range wantSrcs {
					if gotSrcs[i] != wantSrcs[i] {
						t.Errorf("var %q sources[%d]: got %q, want %q",
							name, i, gotSrcs[i], wantSrcs[i])
					}
				}
			}
		})
	}
}

func TestPropagateTaint_OrderAware(t *testing.T) {
	t.Parallel()

	script := `Y=$X`
	initial := map[string]Entry{"X": {Sources: []string{"secrets.X"}, Offset: -1}}
	file := parseScript(t, script)
	got := PropagateTaint(file, initial)

	if got["X"].Offset != -1 {
		t.Errorf("X should keep Offset=-1, got %d", got["X"].Offset)
	}
	if got["Y"].Offset < 0 {
		t.Errorf("Y should have positive Offset (script body), got %d", got["Y"].Offset)
	}
}

func TestPropagateTaint_ReturnsNewMap(t *testing.T) {
	t.Parallel()

	initial := map[string]Entry{"X": {Sources: []string{"secrets.X"}, Offset: -1}}
	file := parseScript(t, `Y=$X`)
	PropagateTaint(file, initial)
	if _, hasY := initial["Y"]; hasY {
		t.Errorf("PropagateTaint must not mutate initial; got %+v", initial)
	}
}
