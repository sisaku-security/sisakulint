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
		name         string
		script       string
		expected     []AssignmentInfo // Offset は無視（後続テストで検証）
		expectNilVal []bool           // true の位置は Value が nil であることを期待する
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
			// Locks in current behavior: WordReferencesEntry returns the
			// FIRST tainted name in the RHS, so Z.Sources only carries the
			// shellvar marker for A. If/when PropagateTaint is enhanced to
			// merge all referenced sources, update this expectation.
			name:      "concatenation_multiple_sources",
			script:    `Z="$A$B"`,
			initial:   map[string]Entry{"A": envEntry("secrets.A"), "B": envEntry("secrets.B")},
			wantNames: []string{"A", "B", "Z"},
			wantSources: map[string][]string{
				"Z": {"shellvar:A"},
			},
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
			// Subshell `( Y=$X )` 内の代入は親に漏れない (Task 2 で scope 隔離)。
			// Y は subshell frame ローカルに留まるため Final には現れない。
			// より詳細な scope 検証は TestPropagateTaint_Scoped を参照。
			name:      "subshell_isolation",
			script:    `(Y=$X)`,
			initial:   map[string]Entry{"X": envEntry("secrets.X")},
			wantNames: []string{"X"},
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
			got := PropagateTaint(file, tc.initial).Final

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
	got := PropagateTaint(file, initial).Final

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

func TestWalkRedirectWrites(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		script    string
		target    string
		wantCount int
		wantNames []string
		wantHd    []bool
	}{
		{
			name:      "echo_to_output",
			script:    `echo "name=value" >> $GITHUB_OUTPUT`,
			target:    "GITHUB_OUTPUT",
			wantCount: 1,
			wantNames: []string{"name"},
			wantHd:    []bool{false},
		},
		{
			name:      "echo_quoted_target",
			script:    `echo "name=value" >> "$GITHUB_OUTPUT"`,
			target:    "GITHUB_OUTPUT",
			wantCount: 1,
			wantNames: []string{"name"},
			wantHd:    []bool{false},
		},
		{
			name:      "echo_braced_target",
			script:    `echo "name=value" >> "${GITHUB_OUTPUT}"`,
			target:    "GITHUB_OUTPUT",
			wantCount: 1,
			wantNames: []string{"name"},
			wantHd:    []bool{false},
		},
		{
			name:      "echo_single_redirect",
			script:    `echo "name=value" > $GITHUB_OUTPUT`,
			target:    "GITHUB_OUTPUT",
			wantCount: 1,
			wantNames: []string{"name"},
		},
		{
			name:      "different_target",
			script:    `echo "name=value" >> $GITHUB_ENV`,
			target:    "GITHUB_OUTPUT",
			wantCount: 0,
		},
		{
			name:      "no_redirect",
			script:    `echo "name=value"`,
			target:    "GITHUB_OUTPUT",
			wantCount: 0,
		},
		{
			name:      "target_with_prefix",
			script:    `echo "name=value" >> "$BASE/$GITHUB_OUTPUT"`,
			target:    "GITHUB_OUTPUT",
			wantCount: 0,
		},
		{
			name: "heredoc_to_output",
			script: `cat <<EOF >> $GITHUB_OUTPUT
key1=value1
key2=value2
EOF`,
			target:    "GITHUB_OUTPUT",
			wantCount: 2,
			wantNames: []string{"key1", "key2"},
			wantHd:    []bool{true, true},
		},
		{
			name:      "heredoc_strip_tabs",
			script:    "cat <<-EOF >> $GITHUB_OUTPUT\n\tk=v\n\tEOF",
			target:    "GITHUB_OUTPUT",
			wantCount: 1,
			wantNames: []string{"k"},
			wantHd:    []bool{true},
		},
		{
			name:      "github_env_target",
			script:    `echo "FOO=bar" >> $GITHUB_ENV`,
			target:    "GITHUB_ENV",
			wantCount: 1,
			wantNames: []string{"FOO"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			file := parseScript(t, tc.script)
			got := WalkRedirectWrites(file, tc.target)
			if len(got) != tc.wantCount {
				t.Fatalf("count: got %d, want %d (got=%+v)", len(got), tc.wantCount, got)
			}
			for i := range tc.wantNames {
				if got[i].Name != tc.wantNames[i] {
					t.Errorf("[%d] Name: got %q, want %q", i, got[i].Name, tc.wantNames[i])
				}
				if i < len(tc.wantHd) && got[i].IsHeredoc != tc.wantHd[i] {
					t.Errorf("[%d] IsHeredoc: got %v, want %v", i, got[i].IsHeredoc, tc.wantHd[i])
				}
			}
		})
	}
}

func TestEntryFirst(t *testing.T) {
	t.Parallel()
	if got := (Entry{}).First(); got != "" {
		t.Errorf("empty Sources: got %q, want \"\"", got)
	}
	if got := (Entry{Sources: []string{"a", "b"}}).First(); got != "a" {
		t.Errorf("got %q, want \"a\"", got)
	}
}

func TestKeywordFor(t *testing.T) {
	t.Parallel()
	cases := map[string]AssignKeyword{
		"export":   AssignExport,
		"local":    AssignLocal,
		"readonly": AssignReadonly,
		"declare":  AssignDeclare,
		"typeset":  AssignDeclare,
		"unknown":  AssignNone,
	}
	for variant, want := range cases {
		if got := keywordFor(variant); got != want {
			t.Errorf("keywordFor(%q): got %v, want %v", variant, got, want)
		}
	}
}

func TestIsValidShellName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		want bool
	}{
		{"", false},
		{"X", true},
		{"_X", true},
		{"X1", true},
		{"1X", false},
		{"X-Y", false},
		{"X.Y", false},
	}
	for _, tc := range cases {
		if got := isValidShellName(tc.name); got != tc.want {
			t.Errorf("isValidShellName(%q): got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFirstNameEqualsArg_Variants(t *testing.T) {
	t.Parallel()
	// option args are skipped; NAME=fmt with %... pulls value from the next arg.
	cases := []struct {
		name     string
		script   string
		wantName string
		wantOK   bool
	}{
		{"option_skipped", `echo -n FOO=bar`, "FOO", true},
		{"printf_format_uses_next_arg", `printf "KEY=%s\n" "val"`, "KEY", true},
		{"single_dash_kept", `echo - FOO=bar`, "FOO", true},
		{"no_eq", `echo plain`, "", false},
		{"invalid_name", `echo 1bad=val`, "", false},
		// `%` inside an echo arg must NOT trigger the printf next-arg branch;
		// `PERCENT=50%` is a single NAME=value pair where the value happens to
		// contain `%`. Regression for the echo-misclassified-as-printf bug.
		{"echo_value_contains_percent", `echo "PERCENT=50%"`, "PERCENT", true},
		{"echo_with_extra_arg_percent", `echo "PERCENT=50%" extra`, "PERCENT", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			file := parseScript(t, tc.script)
			var call *syntax.CallExpr
			syntax.Walk(file, func(n syntax.Node) bool {
				if c, ok := n.(*syntax.CallExpr); ok && call == nil {
					call = c
					return false
				}
				return true
			})
			gotName, _, _, gotOK := firstNameEqualsArg(call)
			if gotName != tc.wantName || gotOK != tc.wantOK {
				t.Errorf("got (%q, %v), want (%q, %v)", gotName, gotOK, tc.wantName, tc.wantOK)
			}
		})
	}
	if _, _, _, ok := firstNameEqualsArg(nil); ok {
		t.Error("nil call should return false")
	}
}

func TestWalkRedirectWrites_PrintfFormat(t *testing.T) {
	t.Parallel()
	// printf 'name=%s\n' "$VAR" >> $GITHUB_OUTPUT — name comes from format arg,
	// value Word comes from the second arg ($VAR).
	file := parseScript(t, `printf 'head_ref_branch=%s\n' "$HEAD_REF" >> "$GITHUB_OUTPUT"`)
	got := WalkRedirectWrites(file, "GITHUB_OUTPUT")
	if len(got) != 1 {
		t.Fatalf("got %d, want 1: %+v", len(got), got)
	}
	if got[0].Name != "head_ref_branch" {
		t.Errorf("Name: got %q, want head_ref_branch", got[0].Name)
	}
	tainted := map[string]Entry{"HEAD_REF": {Sources: []string{"github.head_ref"}, Offset: -1}}
	name, ok := WordReferencesEntry(got[0].ValueWord, tainted)
	if !ok || name != "HEAD_REF" {
		t.Errorf("ValueWord should reference HEAD_REF; got name=%q ok=%v", name, ok)
	}
}

func TestWordLitPrefix_Mixed(t *testing.T) {
	t.Parallel()
	// Mix Lit + SglQuoted + DblQuoted, then a ParamExp which truncates.
	file := parseScript(t, `echo abc'def'"ghi"$X`)
	call := file.Stmts[0].Cmd.(*syntax.CallExpr)
	got := wordLitPrefix(call.Args[1])
	if got != "abcdefghi" {
		t.Errorf("got %q, want %q", got, "abcdefghi")
	}
	if got := wordLitPrefix(nil); got != "" {
		t.Errorf("nil word: got %q", got)
	}
}

func TestRedirTargetMatches_Edge(t *testing.T) {
	t.Parallel()
	// Multiple parts (compound) → false
	file := parseScript(t, `echo x >> "$BASE/$GITHUB_OUTPUT"`)
	stmt := file.Stmts[0]
	w := stmt.Redirs[0].Word
	if redirTargetMatches(w, "GITHUB_OUTPUT") {
		t.Error("compound target should not match")
	}
	// Lit-only target (no expansion) should not match
	file = parseScript(t, `echo x >> /tmp/out`)
	w = file.Stmts[0].Redirs[0].Word
	if redirTargetMatches(w, "GITHUB_OUTPUT") {
		t.Error("literal path should not match")
	}
	// nil/empty
	if redirTargetMatches(nil, "X") {
		t.Error("nil word should not match")
	}
	if redirTargetMatches(&syntax.Word{}, "X") {
		t.Error("empty parts should not match")
	}
}

func TestPropagateTaint_NilFile(t *testing.T) {
	t.Parallel()
	initial := map[string]Entry{"X": {Sources: []string{"s"}, Offset: -1}}
	got := PropagateTaint(nil, initial).Final
	if _, ok := got["X"]; !ok {
		t.Error("initial entry must be preserved with nil file")
	}
}

func TestWalkAssignments_NilFile(t *testing.T) {
	t.Parallel()
	if got := WalkAssignments(nil); got != nil {
		t.Errorf("nil file should return nil, got %+v", got)
	}
}

func TestWalkRedirectWrites_NilFile(t *testing.T) {
	t.Parallel()
	if got := WalkRedirectWrites(nil, "X"); got != nil {
		t.Errorf("nil file should return nil, got %+v", got)
	}
}

func TestExtractHeredocAssignments_NilAndEdge(t *testing.T) {
	t.Parallel()
	if got := extractHeredocAssignments(nil); got != nil {
		t.Errorf("nil hdoc should return nil, got %+v", got)
	}
	// Heredoc with comment-only / empty / no-eq lines should be filtered.
	file := parseScript(t, "cat <<EOF >> $GITHUB_OUTPUT\n# comment\n\nplain\n=novar\nFOO=bar\nEOF")
	stmt := file.Stmts[0]
	var hdoc *syntax.Word
	for _, r := range stmt.Redirs {
		if r.Hdoc != nil {
			hdoc = r.Hdoc
			break
		}
	}
	got := extractHeredocAssignments(hdoc)
	if len(got) != 1 || got[0].name != "FOO" {
		t.Errorf("got %+v, want one FOO entry", got)
	}
}

func TestDblQuotedTargetMatches_NonParam(t *testing.T) {
	t.Parallel()
	// "$(echo X)" — DblQuoted contains CmdSubst, not ParamExp → false
	file := parseScript(t, `echo x >> "$(echo Y)"`)
	w := file.Stmts[0].Redirs[0].Word
	if redirTargetMatches(w, "GITHUB_OUTPUT") {
		t.Error("DblQuoted with CmdSubst should not match")
	}
}

// TestDblQuotedTargetMatches_Compound は内側 Parts が複合の場合
// （`"$GITHUB_OUTPUT/$X"` のように target ParamExp が先頭にあっても）
// false が返ることを assert する。`len(dq.Parts) != 1` ガードを
// 取り除く mutation を kill するため、先頭が target ParamExp である
// compound を必ず含める。
func TestDblQuotedTargetMatches_Compound(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		script string
	}{
		{
			name: "param_lit_param",
			// DblQuoted Parts = [ParamExp(GITHUB_OUTPUT), Lit(/), ParamExp(X)]
			script: `echo x >> "$GITHUB_OUTPUT/$X"`,
		},
		{
			name: "param_then_lit_suffix",
			// DblQuoted Parts = [ParamExp(GITHUB_OUTPUT), Lit(suffix)]
			script: `echo x >> "${GITHUB_OUTPUT}suffix"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			file := parseScript(t, tc.script)
			w := file.Stmts[0].Redirs[0].Word
			if len(w.Parts) != 1 {
				t.Fatalf("expected single-part outer Word, got %d parts", len(w.Parts))
			}
			dq, ok := w.Parts[0].(*syntax.DblQuoted)
			if !ok {
				t.Fatalf("expected DblQuoted, got %T", w.Parts[0])
			}
			if len(dq.Parts) <= 1 {
				t.Fatalf("setup error: DblQuoted should be compound (>=2 parts), got %d", len(dq.Parts))
			}
			if dblQuotedTargetMatches(dq, "GITHUB_OUTPUT") {
				t.Errorf("compound DblQuoted (parts=%d) must not match target", len(dq.Parts))
			}
		})
	}
}

// TestExtractHeredocAssignments_CommentLine は heredoc 本文の
// `# K=V` 形式コメント行を assignment として誤抽出しないことを assert する。
// 既存 NilAndEdge テストは `# comment`（=を含まない）形式のため、
// `#` ガードを取り除いても通ってしまい mutation が survive する。
func TestExtractHeredocAssignments_CommentLine(t *testing.T) {
	t.Parallel()
	src := "cat <<EOF >> $GITHUB_OUTPUT\n# K=ignored\n  # leading_ws=ignored\nNAME=value\nEOF"
	file := parseScript(t, src)
	stmt := file.Stmts[0]
	var hdoc *syntax.Word
	for _, r := range stmt.Redirs {
		if r.Hdoc != nil {
			hdoc = r.Hdoc
			break
		}
	}
	if hdoc == nil {
		t.Fatal("heredoc body not found")
	}
	got := extractHeredocAssignments(hdoc)
	if len(got) != 1 {
		t.Fatalf("expected 1 entry (NAME=value only), got %d: %+v", len(got), got)
	}
	if got[0].name != "NAME" || got[0].value != "value" {
		t.Errorf("got %+v, want {name:NAME, value:value}", got[0])
	}
}

func TestDedupAppend(t *testing.T) {
	t.Parallel()
	got := dedupAppend([]string{"a"}, "b", "a", "c", "b")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("len: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] got %q, want %q", i, got[i], want[i])
		}
	}
}

// TestPropagateTaint_Scoped は scope-aware な PropagateTaint の挙動を検証する。
func TestPropagateTaint_Scoped(t *testing.T) {
	t.Parallel()

	type want struct {
		// finalHas は Final に含まれるべき変数名 → Sources の最初の値
		finalHas map[string]string
		// finalAbsent は Final に含まれてはいけない変数名
		finalAbsent []string
	}

	cases := []struct {
		name    string
		script  string
		initial map[string]Entry
		want    want
	}{
		{
			name:    "subshell_isolation_fp_suppressed",
			script:  `X="$T"; ( X="safe"; cmd "$X" )`,
			initial: map[string]Entry{"T": {Sources: []string{"github.event.issue.body"}, Offset: -1}},
			want: want{
				// 親 X は T 経由で tainted (subshell 内の X="safe" は親に漏れない)
				finalHas: map[string]string{
					"T": "github.event.issue.body",
					"X": "shellvar:T",
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			file := parseScript(t, tc.script)
			result := PropagateTaint(file, tc.initial)
			for name, wantOrigin := range tc.want.finalHas {
				entry, ok := result.Final[name]
				if !ok {
					t.Errorf("Final[%q] missing; want origin %q", name, wantOrigin)
					continue
				}
				if entry.First() != wantOrigin {
					t.Errorf("Final[%q].First() = %q; want %q", name, entry.First(), wantOrigin)
				}
			}
			for _, name := range tc.want.finalAbsent {
				if _, ok := result.Final[name]; ok {
					t.Errorf("Final[%q] should be absent", name)
				}
			}
		})
	}
}
