package analysis

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/workflow"
)

// TestNewEventActivity: a pair is made only of an event and one of its
// activity types, or of an event without them and none.
func TestNewEventActivity(t *testing.T) {
	ok := []struct {
		e workflow.EventName
		a workflow.ActivityType
	}{
		{workflow.EventNameIssues, workflow.ActivityTypeOpened},
		{workflow.EventNameDiscussion, workflow.ActivityTypeClosed},
		{workflow.EventNamePush, workflow.ActivityTypeUnset},
	}
	for _, c := range ok {
		e, err := NewEventActivity(c.e, c.a)
		if err != nil || e.Name() != c.e || e.ActivityType() != c.a {
			t.Errorf("%s/%s: %+v %v", c.e, c.a, e, err)
		}
	}
	bad := []struct {
		e workflow.EventName
		a workflow.ActivityType
	}{
		{workflow.EventNameIssues, workflow.ActivityTypeSynchronize},
		{workflow.EventNameIssues, workflow.ActivityTypeUnset},
		{workflow.EventNamePush, workflow.ActivityTypeOpened},
		{workflow.EventNameUnset, workflow.ActivityTypeUnset},
	}
	for _, c := range bad {
		if _, err := NewEventActivity(c.e, c.a); err == nil {
			t.Errorf("%s/%s is a pair", c.e, c.a)
		}
	}
}

// TestNewEventActivityError: the error names the activity type, or none.
func TestNewEventActivityError(t *testing.T) {
	_, err := NewEventActivity(workflow.EventNameIssues, workflow.ActivityTypeUnset)
	if err == nil || err.Error() != "issues has no activity type none" {
		t.Error(err)
	}
}
