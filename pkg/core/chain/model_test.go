// pkg/core/chain/model_test.go
package chain

import "testing"

func TestNodeKindString(t *testing.T) {
	cases := map[NodeKind]string{
		NodeTrigger:    "trigger",
		NodePermission: "permission",
		NodeSource:     "source",
		NodeAction:     "action",
		NodeSink:       "sink",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("NodeKind(%d).String() = %q, want %q", k, got, want)
		}
	}
}

func TestSinkKindString(t *testing.T) {
	cases := map[SinkKind]string{
		SinkLog: "log", SinkNetwork: "network", SinkArtifact: "artifact",
		SinkExpr: "expr", SinkBoundary: "boundary",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("SinkKind(%d).String() = %q, want %q", k, got, want)
		}
	}
}
