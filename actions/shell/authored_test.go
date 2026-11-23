package shell

import (
	"slices"
	"testing"
)

// authored are the names of the workflow commands src writes to its log
// with the name in its text, and the text of each name's span.
func authored(src string) []string {
	ws := Writes(src, Parse(src), WriteOptions{Log: true, Target: func(Word) bool { return false }, Holes: holes(src)})
	var out []string
	names := []string{"set-output", "save-state", "set-env", "add-path"}
	for _, c := range AuthoredCommands(src, ws, names) {
		out = append(out, names[c.Name]+" "+src[c.Span.Start:c.Span.End])
	}
	return out
}

// TestAuthoredCommands: :: after the
// white space at the head of a line, ##[ anywhere in a line, the name in
// any case, and nothing that does not reach the log.
func TestAuthoredCommands(t *testing.T) {
	for _, c := range []struct {
		src  string
		want []string
	}{
		{`echo "::set-output name=a::b"`, []string{"set-output set-output"}},
		{`echo "  ::save-state name=a::b"`, []string{"save-state save-state"}},
		{`echo "::SET-OUTPUT name=a::b"`, []string{"set-output SET-OUTPUT"}},
		{`echo "x ##[set-env name=A;]b"`, []string{"set-env set-env"}},
		{`echo "##[add-path]/p"`, []string{"add-path add-path"}},
		{`echo "::add-path::/p"`, []string{"add-path add-path"}},
		// the text printf makes is not the format's bytes: the span is the format
		{`printf '::set-output name=%s::%s\n' a b`, []string{`set-output '::set-output name=%s::%s\n'`}},
		{"cat <<EOF\nfirst\n::set-output name=a::b\nEOF", []string{"set-output set-output"}},
		{`echo "::set-output name=a::$V"`, []string{"set-output set-output"}},
		{`echo "::set-output name=a::xxx"`, []string{"set-output set-output"}},
		{"echo \"::set-env name=A::b\" >&2", []string{"set-env set-env"}},
		{"echo \"::set-output name=v::1\"\necho \"::add-path::/opt/bin\"\n", []string{"set-output set-output", "add-path add-path"}},
		// not to the log, or not a command the runner reads there
		{`echo "::set-output name=a::b" > out.txt`, nil},
		{`x=$(echo "::set-output name=a::b")`, nil},
		{`# ::set-output name=a::b`, nil},
		{`echo "x ::set-output name=a::b"`, nil},
		{`echo "::$C name=a::b"`, nil},
		{`echo "::warning::x"`, nil},
		{`echo "::set-outputs name=a::b"`, nil},
		{`echo "::xxx name=a::b"`, nil},
	} {
		if got := authored(c.src); !slices.Equal(got, c.want) {
			t.Errorf("%q: %q, want %q", c.src, got, c.want)
		}
	}
}
