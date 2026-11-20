package suitewalk

import (
	"testing"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

func TestNodes(t *testing.T) {
	tr := cst.Parse([]byte("a: [b, *c]\n--- d\n"))
	var got []string
	var docs []int
	for doc, n := range Nodes(tr) {
		got = append(got, n.Kind().String()+" "+string(n.Bytes()))
		docs = append(docs, doc)
	}
	want := []string{"BlockMapping a: [b, *c]\n", "Scalar a", "FlowSequence [b, *c]", "Scalar b", "Alias *c", "Scalar d"}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("node %d = %q, want %q", i, got[i], want[i])
		}
	}
	if docs[4] != 0 || docs[5] != 1 {
		t.Errorf("documents %v", docs)
	}
}
