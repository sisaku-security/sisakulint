package core

import (
	"bytes"
	"strings"
	"testing"
)

func TestCommandHelpDescribesIgnorePatternAsRuleName(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := &Command{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
	}

	if got := cmd.Main([]string{"sisakulint", "-help"}); got != ExitStatusSuccessNoProblem {
		t.Fatalf("Main(-help) exit code = %d, want %d", got, ExitStatusSuccessNoProblem)
	}
	if !strings.Contains(stderr.String(), "Regular expression matching rule names you want to ignore.") {
		t.Fatalf("-ignore help text = %q, want it to describe rule-name matching", stderr.String())
	}
}
