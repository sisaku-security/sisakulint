package calls

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
)

func TestNodeEquality(t *testing.T) {
	p := facts.MustCleanInputPath(".github/workflows/ci.yml")
	if InputNode(p) != InputNode(p) {
		t.Error("two nodes of one input differ")
	}
	a, b := RemoteNode(&RemoteCalled{order: 1}), RemoteNode(&RemoteCalled{order: 1})
	if a == b {
		t.Error("the nodes of two remote called workflows are the same")
	}
	if n, ok := InputNode(p).Input(); !ok || n != p {
		t.Errorf("Input() = %v, %v", n, ok)
	}
	if _, ok := InputNode(p).Remote(); ok {
		t.Error("an input node is a remote called workflow")
	}
	if _, ok := a.Input(); ok {
		t.Error("a remote node is an input")
	}
	if _, ok := a.Remote(); !ok {
		t.Error("a remote node is not a remote called workflow")
	}
	if !(Node{}).IsZero() || InputNode(p).IsZero() || a.IsZero() {
		t.Error("IsZero")
	}
	if CompareNodes(InputNode(p), a) >= 0 || CompareNodes(a, InputNode(p)) <= 0 {
		t.Error("an input is not ordered before a remote called workflow")
	}
}
