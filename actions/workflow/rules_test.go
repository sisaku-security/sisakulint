package workflow

import (
	"strings"
	"testing"
)

// What the reader of GitHub checks beyond the schema, from the expected
// results of languageservices' reader tests (the copy in testdata/languageservices).
func TestReaderRules(t *testing.T) {
	long := strings.Repeat("x", 21000)
	for _, tt := range []struct {
		name, src string
		want      []Code
	}{
		// YamlObjectReader.AllowLiteral: an explicit tag.
		{"bool", "    timeout-minutes: !!bool test\n", []Code{InvalidValue}},
		{"int", "    timeout-minutes: !!int test\n", []Code{InvalidValue}},
		{"float", "    timeout-minutes: !!float test\n", []Code{InvalidValue}},
		{"int ok", "    timeout-minutes: !!int 5\n", nil},
		{"quoted int", "    timeout-minutes: !!int \"300\"\n", []Code{InvalidValue}},
		{"str", "    name: !!str 5\n", nil},
		{"timestamp", "    name: !!timestamp 2001-12-14\n", []Code{InvalidValue}},
		// TemplateReader.ParseScalar: text and ${{ }} become one format()
		// expression, which has the length limit of every expression.
		{"format length", "    steps:\n      - run: " + long + " ${{ github.sha }}\n", []Code{ExprSyntax}},
		{"format short", "    steps:\n      - run: x ${{ github.sha }}\n", nil},
	} {
		src := "on: push\njobs:\n  a:\n    runs-on: x\n" + tt.src
		_, diags, _ := parse(t, src)
		wantCodes(t, tt.name, diags, tt.want...)
	}
}

// Job ids (reader tests errors-job-id-format, errors-job-id-leading-underscores).
func TestJobIDFormat(t *testing.T) {
	for _, tt := range []struct {
		id string
		ok bool
	}{
		{"build", true},
		{"_build-2", true},
		{"my.job", false},
		{"2build", false},
		{"__", false},
		{"__x", false},
		{strings.Repeat("a", 99), true},
		{strings.Repeat("a", 100), false},
		// a key YAML reads as a number is not judged: GitHub writes it as
		// a string its own way, and took .inf
		{".inf", true},
	} {
		src := "on: push\njobs:\n  " + tt.id + ":\n    runs-on: x\n"
		_, diags, _ := parse(t, src)
		if tt.ok {
			wantCodes(t, tt.id, diags)
		} else {
			wantCodes(t, tt.id, diags, InvalidValue)
		}
	}
}
