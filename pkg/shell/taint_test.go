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
		tc := tc
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
