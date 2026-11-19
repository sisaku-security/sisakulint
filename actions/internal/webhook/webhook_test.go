package webhook

import (
	"slices"
	"testing"
)

func spec(t *testing.T) Spec {
	t.Helper()
	src, err := Read("../../taint/schema/api.github.com.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	s, err := Parse(src)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestActions: the actions of an event's webhooks.
func TestActions(t *testing.T) {
	s := spec(t)
	for _, c := range []struct {
		event  string
		has    []string
		hasNot []string
	}{
		{"discussion", []string{"closed", "reopened", "created"}, nil},
		// v12.2.0 has field_added, stacked, pinned and unpinned
		{"issues", []string{"opened", "labeled", "field_added", "field_removed"}, []string{""}},
		{"pull_request_target", []string{"opened", "synchronize", "stacked"}, nil},
		{"issue_comment", []string{"created", "pinned", "unpinned"}, nil},
		{"merge_group", []string{"checks_requested", "destroyed"}, nil},
	} {
		got := s.Actions(c.event)
		if !slices.IsSorted(got) {
			t.Errorf("%s: %v is not sorted", c.event, got)
		}
		for _, a := range c.has {
			if !slices.Contains(got, a) {
				t.Errorf("%s: %v lacks %q", c.event, got, a)
			}
		}
		for _, a := range c.hasNot {
			if slices.Contains(got, a) {
				t.Errorf("%s: %v has %q", c.event, got, a)
			}
		}
	}
	if got := s.Actions("push"); got != nil {
		t.Errorf("push has actions %v", got)
	}
	if got := s.Actions("no_such_event"); got != nil {
		t.Errorf("no_such_event: %v", got)
	}
}

func TestSubcategory(t *testing.T) {
	if Subcategory("pull_request_target") != "pull_request" || Subcategory("issues") != "issues" {
		t.Error(Subcategory("pull_request_target"), Subcategory("issues"))
	}
}
