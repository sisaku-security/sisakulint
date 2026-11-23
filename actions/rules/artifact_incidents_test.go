package rules

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// TestArtifactIncidents holds the workflows of the projects the ArtiPACKED
// report names, each cut to the checkout, the upload and the steps around them,
// before the commit that fixed them. Their uploads were of releases before
// v4.4.0, which took hidden files; here @v4 was v4.3.x then, so it is
// pinned to v4.3.1 (5d5d22a31266ced268874388b861e4b58bb5c2f3). The report
// does not say which workflow it used; the fixing commits are the ones
// found in the history of .github/workflows. The other
// named projects had no such upload in the history searched.
func TestArtifactIncidents(t *testing.T) {
	const up431 = "actions/upload-artifact@5d5d22a31266ced268874388b861e4b58bb5c2f3 # v4.3.1"
	for _, c := range []struct {
		name, src, kind string // kind "" for none
	}{
		// quay/clair 6f3b13479a40b3285fbb2cfd633fc8815db98a1e .github/workflows/tests.yml:73-74,83,106,123-127,
		// removed by 23a8c33d7f062a61d5fe96b1821dd7bcea80c24c ("cicd: don't upload workspace on failure",
		// 2024-03-25). The upload is the job's last step; the post steps (actions/cache saves the cache after
		// it) leave the time, and the report created a branch of clair with a token taken from an artifact.
		// The report's screen recording shows "Nightly CI" (seen by the user, 2026-09-30):
		// .github/workflows/nightly-ci.yml:4-7,46,51 of the same commit calls tests.yml on schedule, with no
		// permissions written, on three platforms under QEMU.
		{"quay/clair", "on:\n  workflow_call:\n    inputs:\n      package_expr: {required: true, type: string}\njobs:\n  tests:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Checkout\n        uses: actions/checkout@v4\n      - uses: actions/setup-go@v5\n      - name: Cache go artifacts\n        uses: actions/cache@v4\n        with: {path: ~/go/pkg/mod, key: k}\n      - name: Tests\n        run: go test -tags integration ${{ inputs.package_expr }}\n      - uses: " + up431 + "\n        if: failure()\n        with:\n          name: workspace-${{matrix.go}}\n          path: ${{ github.workspace }}\n", "artipacked.github-token"},
		// the same with a step after the upload
		{"quay/clair, a step after", "on: push\njobs:\n  tests:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: " + up431 + "\n        if: failure()\n        with:\n          path: ${{ github.workspace }}\n      - run: echo after\n", "artipacked.github-token"},
		// Azure/draft f7c086e41e681e5e6ff133593f4bfb2c4097a1b2 .github/workflows/integration-linux.yml:341,347-350,411-417,
		// changed by 0108a192d29f7db88291efc96c9cf9a26c376936 ("Add exclusion for .git in artifact upload",
		// 2024-07-26). The checkout of another repository into ./langtest leaves the job's GITHUB_TOKEN in
		// langtest/.git/config; the upload was v3, whose artifact is there only after the run: the limit
		// before-v4.
		{"Azure/draft", "on: push\njobs:\n  gomodule-manifests-create:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v3\n      - uses: actions/checkout@v3\n        with:\n          repository: gambtho/go_echo\n          path: ./langtest\n      - uses: actions/upload-artifact@v3\n        with:\n          name: gomodule-manifests-create\n          path: ./langtest\n      - name: Fail if any error\n        run: exit 6\n", ""},
		// the same with v4.3.1
		{"Azure/draft, v4.3.1", "on: push\njobs:\n  gomodule-manifests-create:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v3\n        with:\n          repository: gambtho/go_echo\n          path: ./langtest\n      - uses: " + up431 + "\n        with:\n          path: ./langtest\n      - run: exit 6\n", "artipacked.github-token"},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{Artipacked, SecretsInArtifacts}, wfFile(c.src), artifactFacts{})
		switch {
		case c.kind == "" && len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0:
			t.Errorf("%s: %+v", c.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
		case c.kind != "" && (len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID().String() != c.kind):
			t.Errorf("%s: %+v; want one %s", c.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), c.kind)
		}
	}
}
