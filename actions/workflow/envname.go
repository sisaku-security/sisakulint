package workflow

import "strings"

// EnvName is the name of an environment variable, as an env of a workflow
// sets it: not empty, without = or a NUL byte, which no environment holds
// in a name.
type EnvName struct{ s string }

func (n EnvName) String() string { return n.s }

// EnvNameOf is s as the name of an environment variable.
func EnvNameOf(s string) (EnvName, bool) {
	if s == "" || strings.ContainsAny(s, "=\x00") {
		return EnvName{}, false
	}
	return EnvName{s}, true
}
