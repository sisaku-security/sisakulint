package prcode

import (
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/releasetable"
)

func inAny(sets ...map[string]bool) func(facts.SHA) bool {
	return func(s facts.SHA) bool {
		for _, set := range sets {
			if set[s.String()] {
				return true
			}
		}
		return false
	}
}

// TestUpstreamTables: each release published after the tables were taken
// is in them (ACTIONS_UPSTREAM=1).
func TestUpstreamTables(t *testing.T) {
	t.Run("checkout", func(t *testing.T) {
		releasetable.CheckTable(t, mustRepo("actions/checkout"), releaseCommitsOn,
			func(s facts.SHA) bool { return slices.Contains(releaseCommits, s.String()) })
	})
	t.Run("download-artifact", func(t *testing.T) {
		releasetable.CheckTable(t, mustRepo("actions/download-artifact"), downloadTablesOn,
			inAny(downloadBefore4, downloadZipSlip, downloadFixedOn))
	})
	t.Run("dawidd6", func(t *testing.T) {
		releasetable.CheckTable(t, mustRepo("dawidd6/action-download-artifact"), downloadTablesOn,
			inAny(dawidd6Forks, dawidd6NoForksOn, dawidd6NoAllowForks))
	})
}
