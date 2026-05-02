package core

import "testing"

func TestSinkTypeString(t *testing.T) {
	cases := map[SinkType]string{
		SinkRun:          "run",
		SinkGitHubScript: "github-script",
		SinkEnv:          "env",
		SinkType(99):     "unknown",
	}
	for st, want := range cases {
		if got := st.String(); got != want {
			t.Errorf("SinkType(%d).String() = %q, want %q", st, got, want)
		}
	}
}
