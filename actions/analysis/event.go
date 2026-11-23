package analysis

import (
	"errors"
	"fmt"
	"slices"

	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// EventActivity is an event that triggers a run, with one of its activity
// types (ActivityTypeUnset for an event without activity types). It is made
// by NewEventActivity only.
type EventActivity struct {
	name         workflow.EventName
	activityType workflow.ActivityType
}

// NewEventActivity is the pair of e, an event, and t: t is one of e's
// activity types (workflow.ActivityTypesOf), or e has none and t is
// ActivityTypeUnset.
func NewEventActivity(e workflow.EventName, t workflow.ActivityType) (EventActivity, error) {
	if e == workflow.EventNameUnset {
		return EventActivity{}, errors.New("no event")
	}
	all := workflow.ActivityTypesOf(e)
	if len(all) == 0 && t != workflow.ActivityTypeUnset || len(all) > 0 && !slices.Contains(all, t) {
		name := "none"
		if t != workflow.ActivityTypeUnset {
			name = t.String()
		}
		return EventActivity{}, fmt.Errorf("%s has no activity type %s", e, name)
	}
	return EventActivity{e, t}, nil
}

// MustEventActivity is NewEventActivity for a pair of the tables: it
// panics when the pair is none.
func MustEventActivity(e workflow.EventName, t workflow.ActivityType) EventActivity {
	x, err := NewEventActivity(e, t)
	if err != nil {
		panic(err)
	}
	return x
}

// Name is the event.
func (e EventActivity) Name() workflow.EventName { return e.name }

// ActivityType is the activity type, ActivityTypeUnset for an event without
// activity types.
func (e EventActivity) ActivityType() workflow.ActivityType { return e.activityType }
