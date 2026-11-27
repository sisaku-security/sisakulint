package job

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// TestForkPullRequestOnly: a job runs only for a pull request from a fork
// when its if is false for a pull request from a branch of the repository,
// on pull_request alone.
func TestForkPullRequestOnly(t *testing.T) {
	for _, c := range []struct {
		on, cond string
		want     bool
	}{
		{"pull_request", "github.event.pull_request.head.repo.fork", true},
		{"pull_request", "github.event.pull_request.head.repo.fork == true", true},
		{"pull_request", "github.event.pull_request.head.repo.full_name != github.repository", true},
		{"pull_request", "", false},
		{"pull_request", "github.event.pull_request.head.repo.fork || github.event.pull_request.head.repo.full_name == github.repository", false},
		{"pull_request", "!github.event.pull_request.head.repo.fork", false},
		{"[pull_request, push]", "github.event.pull_request.head.repo.fork", false},
		{"[pull_request, push]", "github.event_name == 'pull_request' && github.event.pull_request.head.repo.fork", true},
		{"pull_request_target", "github.event.pull_request.head.repo.fork", false},
		{"pull_request_review", "github.event.pull_request.head.repo.fork", false},
	} {
		src := "on: " + c.on + "\njobs:\n  a:\n"
		if c.cond != "" {
			src += "    if: " + c.cond + "\n"
		}
		src += "    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
		w, _ := workflow.Parse(cst.Parse([]byte(src)))
		j := w.Jobs.Value.Entries[0].Value.Value
		if got := ForkPullRequestOnly(w, &j); got != c.want {
			t.Errorf("on %s, if %q: %v, want %v", c.on, c.cond, got, c.want)
		}
	}
}
