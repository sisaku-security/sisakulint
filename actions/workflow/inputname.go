package workflow

// InputName is the name of an input of an action or of a called workflow,
// as a with gives it: not empty.
type InputName struct{ s string }

func (n InputName) String() string { return n.s }

// InputNameOf is s as the name of an input.
func InputNameOf(s string) (InputName, bool) {
	if s == "" {
		return InputName{}, false
	}
	return InputName{s}, true
}
