package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// runner runs a command in dir (the current directory when empty) and
// gives its standard output.
type runner interface {
	run(dir, name string, args ...string) (string, error)
}

type execRunner struct{}

func (execRunner) run(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(errOut.String()))
	}
	return out.String(), nil
}
