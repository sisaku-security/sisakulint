package labeler

import (
	"github.com/gh-intel/sisakulint/actions/attacker"
	"io/fs"

	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/facts"
)

// Table are the steps of the workflows of a repository that run
// actions/labeler on the pull request of an attacker with a token other
// than the GITHUB_TOKEN.
type Table struct {
	steps []Step
}

// Read is the table of the workflows of files, the whole repository of
// root; a configuration under a path excluded is not read. A nil root (the
// inputs are not the whole repository) has no steps.
func Read(files []calls.File, root fs.FS, excluded func(facts.InputPath) bool) *Table {
	return ReadIn(attacker.Outsider, files, root, excluded)
}

// ReadIn is Read, with the ifs read in the attacker run table at.
func ReadIn(at attacker.Table, files []calls.File, root fs.FS, excluded func(facts.InputPath) bool) *Table {
	t := &Table{}
	if root == nil {
		return t
	}
	for _, f := range files {
		for _, s := range stepsOf(at, f.Name, f.Workflow, root, excluded) {
			s.Tree = f.Tree
			t.steps = append(t.steps, s)
		}
	}
	return t
}

// Steps are the steps of t, in the order of the files and of the steps.
// One step of actions/labeler may give two Steps: one that surely runs,
// and one that may not run (MayNotRun), whose labels are more.
func (t *Table) Steps() []Step {
	if t == nil {
		return nil
	}
	return t.steps
}
