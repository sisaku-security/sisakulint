package rules

import (
	"github.com/gh-intel/sisakulint/actions/internal/attackrun"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// AttackMarkers are the rules whose examples' attack values are run
// (actions/internal/attackrun), each with where its harm shows: the
// rules whose attacker puts a string into a shell.
var AttackMarkers = map[lint.RuleID]attackrun.Marker{
	CodeInjectionID:    attackrun.MarkerStdout,
	EnvvarInjectionID:  attackrun.MarkerEnv,
	OutputClobberingID: attackrun.MarkerOutput,
	EnvpathInjectionID: attackrun.MarkerPath,
}
