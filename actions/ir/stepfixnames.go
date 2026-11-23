package ir

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/expr"
)

// identifier is a name the shell may read as a variable: those of a script
// are taken, so that a new variable does not shadow one.
var identifier = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// envVarName is a name for the variable of the context path: its last
// two names, in capitals (github.event.issue.title is ISSUE_TITLE).
func envVarName(path []expr.PathElem) string {
	var names []string
	for _, e := range path {
		if e.Name != "" {
			names = append(names, e.Name)
		}
	}
	if len(names) > 0 && expr.EqualName(names[0], "github") {
		names = names[1:]
	}
	if len(names) > 1 && expr.EqualName(names[0], "event") {
		names = names[1:]
	}
	if len(names) > 2 {
		names = names[len(names)-2:]
	}
	var b strings.Builder
	for i, n := range names {
		if i > 0 {
			b.WriteByte('_')
		}
		for _, r := range n {
			switch {
			case r >= 'a' && r <= 'z':
				b.WriteRune(r - 'a' + 'A')
			case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
				b.WriteRune(r)
			default:
				b.WriteByte('_')
			}
		}
	}
	name := b.String()
	if name == "" || name[0] >= '0' && name[0] <= '9' {
		name = "VALUE_" + name
	}
	return name
}

// freeName is name, or name with a number after it, that no env of the
// step sees and no other variable of the fix has; it takes it.
func freeName(name string, taken map[string]bool) string {
	n := name
	for i := 2; taken[expr.FoldName(n)]; i++ {
		n = fmt.Sprintf("%s_%d", name, i)
	}
	taken[expr.FoldName(n)] = true
	return n
}
