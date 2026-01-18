package core

// OutputClobberingMedium is a type alias for backward compatibility with existing tests
// The actual implementation is in OutputClobberingRule
type OutputClobberingMedium = OutputClobberingRule

// OutputClobberingMediumRule creates a rule for detecting output clobbering in normal workflow contexts
// Normal contexts include: pull_request, push, schedule, workflow_dispatch
// These triggers have limited permissions, making output clobbering medium severity
func OutputClobberingMediumRule() *OutputClobberingRule {
	return newOutputClobberingRule("medium", false)
}
