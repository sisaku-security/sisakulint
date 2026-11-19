package workflow

import "slices"

// EventName is the name of an event that triggers a workflow: one of the
// constants of the runner's on-string, compared exactly. Its
// values are made by internal/schemagen (schema_gen.go).
type EventName uint8

// ActivityType is an activity type of an event: a value of on.<event>.types
// and the action of its payload, compared exactly. Its
// values are made by internal/schemagen (schema_gen.go).
type ActivityType uint8

// EventNames are every EventName, in the order of the constants.
func EventNames() []EventName { return eventNameValues() }

// ActivityTypesOf are the activity types of e, by name: those of the
// workflow schema and of GitHub's webhooks of e; none for an event without
// activity types. A run without types runs on any of them.
func ActivityTypesOf(e EventName) []ActivityType { return slices.Clone(activityTypesOf[e]) }
