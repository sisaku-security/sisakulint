package job

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// hostedLabelsSource is the table of GitHub-hosted runners the labels are
// from. Their Linux and macOS virtual machines run with passwordless sudo
// (content/actions/reference/runners/github-hosted-runners.md of commit
// ae648a1d328cb15fb173e80984aac748cf4b5af2). A label the table no longer
// has, such as macos-14 (retired, github/docs commit 2eefcb3a), is not read
// as a GitHub-hosted label.
const hostedLabelsSource = "https://raw.githubusercontent.com/github/docs/2eefcb3a7f7cfafb15d77da07c691324f6696e69/data/reusables/actions/supported-github-runners.md"

// hostedSudoLabels are the labels of the GitHub-hosted Linux and macOS
// runners of hostedLabelsSource. ubuntu-slim is not among them: its runner
// is a container run in unprivileged mode, not a virtual machine
// (github-hosted-runners.md, "ubuntu-slim runners execute Actions
// workflows in Ubuntu Linux, inside a container rather than a full VM
// instance").
var hostedSudoLabels = mustLabels(
	"ubuntu-latest", "ubuntu-24.04", "ubuntu-22.04", "ubuntu-26.04",
	"ubuntu-24.04-arm", "ubuntu-22.04-arm", "ubuntu-26.04-arm",
	"macos-15-intel", "macos-26-intel", "macos-latest", "macos-15", "macos-26", "xcode-27",
)

// hostedLabels are the labels of every GitHub-hosted runner of
// hostedLabelsSource: hostedSudoLabels and the Windows ones.
var hostedLabels = append(slices.Clone(hostedSudoLabels), mustLabels(
	"windows-latest", "windows-2025", "windows-2025-vs2026", "windows-2022", "windows-11-arm", "windows-11-vs2026-arm",
)...)

func mustLabels(names ...string) []workflow.RunnerLabelName {
	out := make([]workflow.RunnerLabelName, len(names))
	for i, n := range names {
		l, err := workflow.ParseRunnerLabelName(n)
		if err != nil {
			panic(err)
		}
		out[i] = l
	}
	return out
}

// HostedSudo is whether the steps of j run on a GitHub-hosted Linux or
// macOS runner, whose user has passwordless sudo: every label of its
// runs-on, as written or as the matrix gives it, is one of theirs, and no
// group picks the runner (a group's runners are larger or self-hosted
// ones). A ${{ }} the matrix does not give, any other label, and a job
// with a container, whose steps run in the container, are not decided:
// false.
func HostedSudo(j workflow.Job) bool {
	if j.RunsOnForm == workflow.RunsOnFormMapping || j.Container.Status != workflow.Absent {
		return false
	}
	labels, inconclusive := runnerLabelsOf(nil, j)
	if len(labels) == 0 || len(inconclusive) > 0 {
		return false
	}
	for _, l := range labels {
		if !slices.ContainsFunc(hostedSudoLabels, l.Label.Equal) {
			return false
		}
	}
	return true
}

// Hosted is who runs the machine the steps of j run on, by its runs-on:
// self-hosted when a label, as written or as the matrix gives it, is the
// one every self-hosted runner has; GitHub when every label is one of
// GitHub's hosted runners (a new virtual machine for each job) and no group
// picks the runner; else not known (a group, another label, or a ${{ }}
// the matrix does not give).
func Hosted(j workflow.Job) analysis.RunnerHosting {
	labels, inconclusive := runnerLabelsOf(nil, j)
	for _, l := range labels {
		if l.HasSelfHostedLabel {
			return analysis.RunnerHostingSelfHosted
		}
	}
	if j.RunsOnForm == workflow.RunsOnFormMapping || len(labels) == 0 || len(inconclusive) > 0 {
		return analysis.RunnerHostingUnknown
	}
	for _, l := range labels {
		if !slices.ContainsFunc(hostedLabels, l.Label.Equal) {
			return analysis.RunnerHostingUnknown
		}
	}
	return analysis.RunnerHostingGitHub
}

// ServiceNames are the names of the services of j, in the order written:
// its steps reach a service by its name.
func ServiceNames(j workflow.Job) []string {
	if j.Services.Status != workflow.Present {
		return nil
	}
	var out []string
	for _, e := range j.Services.Value.Entries {
		out = append(out, e.Key.AsString())
	}
	return out
}

// RunnerLabelTexts are the labels of the runs-on of j, as written or as the
// matrix gives them.
func RunnerLabelTexts(j workflow.Job) []string {
	labels, _ := runnerLabelsOf(nil, j)
	var out []string
	for _, l := range labels {
		out = append(out, l.Label.String())
	}
	return out
}
