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

// The labels a self-hosted runner has for its operating system unless it is
// made without the default labels ("linux, windows, or macOS: Applied
// depending on operating system",
// https://github.com/github/docs/blob/df6faa250dc425fa137d270c967e6a74f12103a7/content/actions/how-tos/manage-runners/self-hosted-runners/use-in-a-workflow.md).
var (
	LinuxLabel   = mustRunnerLabelName("linux")
	WindowsLabel = mustRunnerLabelName("windows")
	MacOSLabel   = mustRunnerLabelName("macOS")
)

// HostedRunnerLabelsSource is the table of GitHub-hosted runners that
// HostedWindowsLabels, and the labels of the Linux and macOS runners that
// other packages hold, are from. A label the table no longer has, such as
// macos-14 (retired, github/docs commit 2eefcb3a), is not read as a
// GitHub-hosted label.
const HostedRunnerLabelsSource = "https://raw.githubusercontent.com/github/docs/2eefcb3a7f7cfafb15d77da07c691324f6696e69/data/reusables/actions/supported-github-runners.md"

// HostedWindowsLabels are the labels of the GitHub-hosted Windows runners
// of HostedRunnerLabelsSource. A self-hosted runner may have a custom label
// of the same name, or any custom label that begins with windows-.
var HostedWindowsLabels = []RunnerLabelName{
	mustRunnerLabelName("windows-latest"), mustRunnerLabelName("windows-2025"), mustRunnerLabelName("windows-2025-vs2026"),
	mustRunnerLabelName("windows-2022"), mustRunnerLabelName("windows-11-arm"), mustRunnerLabelName("windows-11-vs2026-arm"),
}

func mustRunnerLabelName(s string) RunnerLabelName {
	n, err := ParseRunnerLabelName(s)
	if err != nil {
		panic(err)
	}
	return n
}
