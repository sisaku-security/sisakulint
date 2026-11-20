package workflow

import (
	"errors"
	"fmt"
	"strings"
)

// RunnerLabelName is the name of a label a runner has, as runs-on writes
// it. It is made by ParseRunnerLabelName only: a runner cannot have an empty
// label, or one with white space around it (GitHub refuses it, or drops the
// white space). Labels compare in any case: Equal, not ==, says whether
// they are the same label.
type RunnerLabelName struct{ name string }

// ParseRunnerLabelName is the label s.
func ParseRunnerLabelName(s string) (RunnerLabelName, error) {
	switch {
	case s == "":
		return RunnerLabelName{}, errors.New("a runner label is empty")
	case strings.TrimSpace(s) != s:
		return RunnerLabelName{}, fmt.Errorf("the runner label %q has white space around it", s)
	}
	return RunnerLabelName{s}, nil
}

// String is the label as written.
func (n RunnerLabelName) String() string { return n.name }

// Equal is whether n and o are the same label, in any case.
func (n RunnerLabelName) Equal(o RunnerLabelName) bool { return strings.EqualFold(n.name, o.name) }

// SelfHostedLabel is the label a self-hosted runner has unless it is made
// without the default labels.
var SelfHostedLabel = mustRunnerLabelName("self-hosted")

func mustRunnerLabelName(s string) RunnerLabelName {
	n, err := ParseRunnerLabelName(s)
	if err != nil {
		panic(err)
	}
	return n
}
