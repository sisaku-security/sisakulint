package lint

import (
	"fmt"

	"github.com/gh-intel/sisakulint/actions/internal/ident"
)

// KindArgumentName is the name of an argument of a kind of finding: a key
// of the args of a finding in the JSON, in snake_case; where the text of
// what the kind detects names the argument, the text writes it as {name}.
type KindArgumentName struct{ s string }

// ParseKindArgumentName reads the name of an argument.
func ParseKindArgumentName(s string) (KindArgumentName, error) {
	if !ident.IsSnake(s) {
		return KindArgumentName{}, fmt.Errorf("the name %q of an argument is not snake_case", s)
	}
	return KindArgumentName{s}, nil
}

// MustKindArgumentName is ParseKindArgumentName for a name known to be one.
func MustKindArgumentName(s string) KindArgumentName { return must(ParseKindArgumentName(s)) }

func (n KindArgumentName) String() string { return n.s }

// MarshalText is the name, as an example catalog writes it.
func (n KindArgumentName) MarshalText() ([]byte, error) { return []byte(n.s), nil }

// KindArgument is an argument a kind of finding declares: its name, what it
// holds, and whether the text of what the kind detects names it.
type KindArgument struct {
	Name       KindArgumentName
	Text       string
	InDetected bool
}
