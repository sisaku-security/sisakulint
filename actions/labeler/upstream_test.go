package labeler

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/releasetable"
)

// TestUpstreamTables: each release of actions/labeler published after the
// table was taken is in it (ACTIONS_UPSTREAM=1).
func TestUpstreamTables(t *testing.T) {
	repo, err := facts.ParseRepo("actions/labeler")
	if err != nil {
		t.Fatal(err)
	}
	releasetable.CheckTable(t, repo, releasesOn, func(s facts.SHA) bool {
		_, ok := ReleaseOf(s.String())
		return ok
	})
}
