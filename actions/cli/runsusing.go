package cli

import (
	"errors"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// readRunsUsing is the runs.using of the metadata of an action, as the
// runner reads it (without case): what --online answers action.runs-using
// with. Another error of the metadata (no main) is not asked about: the
// action declares the runtime all the same. A YAML that is not read, and a
// runs.using the runner does not accept, are errors.
func readRunsUsing(definition []byte) (facts.RunsUsing, error) {
	m, diags := workflow.ParseActionMetadata(cst.ParseMode(definition, cst.ModeGitHub))
	for _, d := range diags {
		if d.Code == workflow.Syntax {
			return facts.RunsUsingUnset, errors.New("the metadata is not YAML that GitHub reads")
		}
	}
	if m == nil || m.Runs.Status != workflow.Present || m.Runs.Value.Using.Status != workflow.Present {
		return facts.RunsUsingUnset, errors.New("the metadata has no runs.using")
	}
	return facts.ParseRunsUsing(strings.ToLower(m.Runs.Value.Using.Value.AsString()))
}
