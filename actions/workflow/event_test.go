package workflow

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/internal/enumtest"
)

func TestParseEventName(t *testing.T) {
	for _, s := range []string{"push", "pull_request_target", "issue_comment", "workflow_call", "workflow_dispatch", "schedule", "repository_dispatch", "pull_request_comment"} {
		n, err := ParseEventName(s)
		if err != nil || n.String() != s {
			t.Errorf("ParseEventName(%q) = %v, %v", s, n, err)
		}
	}
	// the runner checks event names exactly
	for _, s := range []string{"", "Push", "pull-request", "nope", " push"} {
		if n, err := ParseEventName(s); err == nil {
			t.Errorf("ParseEventName(%q) = %v, want an error", s, n)
		}
	}
}

// onStrings are the constants of on-string, the names GitHub takes.
func onStrings() []string {
	var out []string
	for _, d := range schemaDefs[dOnString].oneOf {
		if c := schemaDefs[d].constant; c != "" {
			out = append(out, c)
		}
	}
	return out
}

// TestEventNames: EventName has a constant for each name of on-string, and
// no other.
func TestEventNames(t *testing.T) {
	names := onStrings()
	enumtest.Check(t, len(eventNameNames), false, ParseEventName, func(b []byte) error {
		var s string
		if err := json.Unmarshal(b, &s); err != nil || !slices.Contains(names, s) {
			return fmt.Errorf("%s is not a name of on-string", b)
		}
		return nil
	})
	if len(eventNameNames)-1 != len(names) {
		t.Errorf("%d constants, %d names of on-string", len(eventNameNames)-1, len(names))
	}
	if EventNamePullRequestTarget.String() != "pull_request_target" || EventNameWorkflowCall.String() != "workflow_call" {
		t.Errorf("the constants are %v, %v", EventNamePullRequestTarget, EventNameWorkflowCall)
	}
}

// TestActivityTypesOf: an event's activity types are those of the workflow
// schema and of the webhook.
func TestActivityTypesOf(t *testing.T) {
	for _, c := range []struct {
		e   EventName
		has []ActivityType
	}{
		{EventNameDiscussion, []ActivityType{ActivityTypeClosed, ActivityTypeReopened, ActivityTypeCreated}},
		{EventNameIssues, []ActivityType{ActivityTypeFieldAdded, ActivityTypeFieldRemoved, ActivityTypeOpened}},
		{EventNamePullRequestTarget, []ActivityType{ActivityTypeStacked, ActivityTypeOpened, ActivityTypeSynchronize}},
		{EventNameMergeGroup, []ActivityType{ActivityTypeChecksRequested, ActivityTypeDestroyed}},
	} {
		got := ActivityTypesOf(c.e)
		for _, a := range c.has {
			if !slices.Contains(got, a) {
				t.Errorf("%s: %v lacks %s", c.e, got, a)
			}
		}
		if !slices.IsSortedFunc(got, func(a, b ActivityType) int { return strings.Compare(a.String(), b.String()) }) {
			t.Errorf("%s: %v is not sorted", c.e, got)
		}
	}
	if got := ActivityTypesOf(EventNamePush); got != nil {
		t.Errorf("push: %v", got)
	}
	got := ActivityTypesOf(EventNameIssues)
	got[0] = ActivityTypeUnset
	if ActivityTypesOf(EventNameIssues)[0] == ActivityTypeUnset {
		t.Error("ActivityTypesOf shares its table")
	}
}

// TestParseActivityType: case counts.
func TestParseActivityType(t *testing.T) {
	if a, err := ParseActivityType("opened"); err != nil || a != ActivityTypeOpened {
		t.Error(a, err)
	}
	for _, s := range []string{"Opened", "opend", "foo", ""} {
		if _, err := ParseActivityType(s); err == nil {
			t.Errorf("%q is an activity type", s)
		}
	}
}
