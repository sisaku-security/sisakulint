package workflow

import "testing"

// TestInputNameOf: a name is not empty, and keeps the case of the with.
func TestInputNameOf(t *testing.T) {
	if n, ok := InputNameOf("Prompt"); !ok || n.String() != "Prompt" {
		t.Errorf("Prompt: %v %v", n, ok)
	}
	if _, ok := InputNameOf(""); ok {
		t.Error("the empty name is a name")
	}
}
