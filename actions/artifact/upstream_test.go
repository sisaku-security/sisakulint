package artifact

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/releasetable"
)

// TestUpstreamTables: each release published after the tables were taken
// is in them (ACTIONS_UPSTREAM=1).
func TestUpstreamTables(t *testing.T) {
	in := func(sets ...map[string]bool) func(facts.SHA) bool {
		return func(s facts.SHA) bool {
			for _, set := range sets {
				if set[s.String()] {
					return true
				}
			}
			return false
		}
	}
	t.Run("checkout", func(t *testing.T) {
		releasetable.CheckTable(t, mustRepo("actions/checkout"), tablesOn, in(checkoutLeaves, checkoutKeeps))
	})
	t.Run("upload-artifact", func(t *testing.T) {
		releasetable.CheckTable(t, mustRepo("actions/upload-artifact"), tablesOn, in(uploadTakes, uploadNever, uploadInput))
	})
}
