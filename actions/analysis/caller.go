package analysis

// CallerCoverage is how much of the callers of a called workflow or a
// composite action the inputs of a run have: whether its callers there
// decide its events and its inputs.
type CallerCoverage uint8

const (
	CallerCoverageNone    CallerCoverage = iota // no caller among the inputs: read in the worst case
	CallerCoveragePartial                       // some callers, but the inputs are not the whole repository, or one is not resolved
	CallerCoverageAll                           // the whole repository, every caller resolved: they decide it
)

var callerCoverageNames = [...]string{"CallerCoverageNone", "CallerCoveragePartial", "CallerCoverageAll"}

func (c CallerCoverage) String() string { return callerCoverageNames[c] }
