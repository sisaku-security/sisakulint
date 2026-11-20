package rules

import "testing"

func TestMissingTimeoutMinutes(t *testing.T) {
	got := qualityKinds(t, MissingTimeoutMinutesID, `on: push
jobs:
  a:
    runs-on: x
    steps: [{run: a}]
  b:
    runs-on: x
    timeout-minutes: ${{ fromJSON(vars.T) }}
    steps: [{run: a}]
  c:
    uses: ./.github/workflows/c.yml
`)
	if len(got) != 1 || got[0] != "missing-timeout-minutes.job: the job a has no timeout-minutes" {
		t.Errorf("%v", got)
	}
}
