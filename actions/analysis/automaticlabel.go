package analysis

import "errors"

// AutomaticLabel is what lets a run that a label approves start for an
// attacker: a workflow of the repository that runs actions/labeler on the
// pull request of the attacker with a token other than the GITHUB_TOKEN,
// whose label lets the run in. A run has a set of them: Free alone, or the
// ones that leave it undecided.
type AutomaticLabel uint8

const (
	AutomaticLabelFree       AutomaticLabel = iota // the attacker gets the label with any files of their choice
	AutomaticLabelPaths                            // only when every file the pull request changes matches globs
	AutomaticLabelBaseBranch                       // only on a base branch whose name matches, which the repository may not have
	AutomaticLabelLabelSet                         // the if asks for another label that the same run may or may not have
	AutomaticLabelUnknown                          // the release, the configuration, the pull request or the token is not known
)

var automaticLabelNames = [...]string{"free", "paths", "base-branch", "label-set", "unknown"}

func (a AutomaticLabel) String() string { return automaticLabelNames[a] }

// LabelName is the name of a label of an issue or a pull request, as the
// configuration of actions/labeler writes it.
type LabelName struct{ s string }

// NewLabelName is the label named s; GitHub has no label without a name.
func NewLabelName(s string) (LabelName, error) {
	if s == "" {
		return LabelName{}, errors.New("a label has a name")
	}
	return LabelName{s}, nil
}

func (n LabelName) String() string { return n.s }
