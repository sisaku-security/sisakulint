package prcode

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
)

// oneDownload is the one download of a job on on, with jobExtra, whose
// first step is uses with with, followed by after.
func oneDownload(t *testing.T, on, jobExtra, uses, with, after string) DownloadSite {
	t.Helper()
	src := "on: " + on + "\njobs:\n  a:\n    runs-on: ubuntu-latest\n" + jobExtra + "    steps:\n      - uses: " + uses + "\n"
	if with != "" {
		src += "        with: " + with + "\n"
	}
	src += after
	sites := AnalyzeDownloads(mustWorkflow(t, src), nil, nil)
	if len(sites) != 1 {
		t.Fatalf("%q: %d sites", src, len(sites))
	}
	return sites[0]
}

const runOn = "{workflow_run: {workflows: [ci], types: [completed]}}"

func runRefTexts(rs []PRRunRef) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Input.String()+" "+r.Text)
	}
	return out
}

// TestDownloadRefs: the forms of a download that point to a run of the
// attacker, row by row.
func TestDownloadRefs(t *testing.T) {
	const da, dw = "actions/download-artifact@v4", "dawidd6/action-download-artifact@v6"
	const runID, tok = "run-id: '${{ github.event.workflow_run.id }}'", "github-token: '${{ github.token }}'"
	for _, c := range []struct {
		name, on, uses, with string
		refs                 []string
		inconclusive         int
		events               []string
	}{
		{"run id with a token", runOn, da, "{" + runID + ", " + tok + "}", []string{"run-id github.event.workflow_run.id"}, 0, []string{"workflow_run/completed"}},
		{"spacing and case", runOn, da, "{run-id: '${{github.event.workflow_run.ID}}', " + tok + "}", []string{"run-id github.event.workflow_run.ID"}, 0, []string{"workflow_run/completed"}},
		{"no token: the current run", runOn, da, "{" + runID + "}", nil, 0, nil},
		{"empty token", runOn, da, "{" + runID + ", github-token: ''}", nil, 0, nil},
		{"no with", runOn, da, "", nil, 0, nil},
		{"github.run_id", runOn, da, "{run-id: '${{ github.run_id }}', " + tok + "}", nil, 0, nil},
		{"a number", runOn, da, "{run-id: '123', " + tok + "}", nil, 0, nil},
		{"a step's output", runOn, da, "{run-id: '${{ steps.find.outputs.id }}', " + tok + "}", nil, 1, nil},
		{"a token of a step", runOn, da, "{" + runID + ", github-token: '${{ steps.t.outputs.token }}'}", nil, 1, nil},
		{"another repository", runOn, da, "{" + runID + ", " + tok + ", repository: '${{ github.event.workflow_run.head_repository.full_name }}'}", nil, 1, nil},
		{"github.repository", runOn, da, "{" + runID + ", " + tok + ", repository: '${{ github.repository }}'}", []string{"run-id github.event.workflow_run.id"}, 0, []string{"workflow_run/completed"}},
		{"with a ${{ }}", runOn, da, "'${{ fromJSON(inputs.w) }}'", nil, 1, nil},
		{"v3", runOn, "actions/download-artifact@v3", "{" + runID + ", " + tok + "}", nil, 0, nil},
		{"v3-node20", runOn, "actions/download-artifact@v3-node20", "{" + runID + ", " + tok + "}", nil, 0, nil},
		{"a v3 commit", runOn, "actions/download-artifact@9bc31d5ccc31df68ecc42ccf4149144866c47d8a", "{" + runID + ", " + tok + "}", nil, 0, nil},
		{"a branch", runOn, "actions/download-artifact@main", "{" + runID + ", " + tok + "}", []string{"run-id github.event.workflow_run.id"}, 0, []string{"workflow_run/completed"}},
		{"run id on pull_request_target", "pull_request_target", da, "{" + runID + ", " + tok + "}", nil, 0, nil},
		// on workflow_run alone, run_id github.event.workflow_run.id is never
		// empty: no search
		{"dawidd6 run_id", runOn, dw, "{run_id: '${{ github.event.workflow_run.id }}'}", []string{"run_id github.event.workflow_run.id"}, 0, []string{"workflow_run/completed"}},
		{"dawidd6 repo of the fork", "pull_request_target", dw, "{repo: '${{ github.event.pull_request.head.repo.full_name }}'}", []string{"repo github.event.pull_request.head.repo.full_name"}, 0, []string{"pull_request_target/opened", "pull_request_target/reopened", "pull_request_target/synchronize"}},
		{"dawidd6 allow_forks", runOn, dw, "{workflow: ci.yml, allow_forks: true}", []string{"allow_forks true"}, 0, []string{"workflow_run/completed"}},
		// as observed on 2026-11-06: with allow_forks false, a search takes
		// the run of a review of a pull request from a fork, whose head
		// repository is the base
		{"dawidd6 v6 searches the runs of reviews", runOn, dw, "{workflow: ci.yml}", []string{"uses dawidd6/action-download-artifact@v6"}, 0, []string{"workflow_run/completed"}},
		{"dawidd6 v20 on push", "push", "dawidd6/action-download-artifact@v20", "{name: out}", []string{"uses dawidd6/action-download-artifact@v20"}, 0, []string{"push/"}},
		{"dawidd6 v6, allow_forks false", "push", dw, "{allow_forks: false}", []string{"uses dawidd6/action-download-artifact@v6"}, 0, []string{"push/"}},
		{"dawidd6 a commit of v4 on", "push", "dawidd6/action-download-artifact@854e2de9396304899dbe03bf9995fd73533190d1", "", []string{"uses dawidd6/action-download-artifact@854e2de9396304899dbe03bf9995fd73533190d1"}, 0, []string{"push/"}},
		{"dawidd6 v3 searches forks", runOn, "dawidd6/action-download-artifact@v3", "{workflow: '${{ github.event.workflow_run.workflow_id }}'}", []string{"uses dawidd6/action-download-artifact@v3"}, 0, []string{"workflow_run/completed"}},
		{"dawidd6 v3 with no with", runOn, "dawidd6/action-download-artifact@v3", "", []string{"uses dawidd6/action-download-artifact@v3"}, 0, []string{"workflow_run/completed"}},
		{"dawidd6 v3, allow_forks false", runOn, "dawidd6/action-download-artifact@v3", "{allow_forks: false}", []string{"uses dawidd6/action-download-artifact@v3"}, 0, []string{"workflow_run/completed"}},
		// a workflow on workflow_call: the caller gives the input on its
		// events, so no search
		{"dawidd6 run_id of an input of a called workflow", "{workflow_call: {inputs: {run: {type: string}}}}", dw, "{run_id: '${{ inputs.run }}'}", nil, 1, nil},
		// its own push gives no input: the release searches on push
		{"dawidd6 run_id of an input, push and workflow_call", "{push: {}, workflow_call: {inputs: {run: {type: string}}}}", dw, "{run_id: '${{ inputs.run }}'}", []string{"uses dawidd6/action-download-artifact@v6"}, 1, []string{"push/"}},
		{"dawidd6 allow_forks by a ${{ }}", runOn, dw, "{allow_forks: '${{ inputs.f }}'}", []string{"uses dawidd6/action-download-artifact@v6"}, 0, []string{"workflow_run/completed"}},
		// a search that takes forks' runs holds on any event
		{"dawidd6 v3 on push", "push", "dawidd6/action-download-artifact@v3", "", []string{"uses dawidd6/action-download-artifact@v3"}, 0, []string{"push/"}},
		{"dawidd6 allow_forks on workflow_dispatch", "workflow_dispatch", dw, "{workflow: build.yml, allow_forks: true}", []string{"allow_forks true"}, 0, []string{"workflow_dispatch/"}},
		{"dawidd6 repo of the fork on push: no value", "push", dw, "{repo: '${{ github.event.pull_request.head.repo.full_name }}'}", nil, 0, nil},
	} {
		s := oneDownload(t, c.on, "", c.uses, c.with, "      - run: echo\n")
		if got := runRefTexts(s.PRRunRefs); !slices.Equal(got, c.refs) || len(s.InconclusiveValues) != c.inconclusive && !(c.inconclusive == 1 && s.Dynamic) {
			t.Errorf("%s: refs %q inconclusive %d dynamic %v; want %q %d", c.name, got, len(s.InconclusiveValues), s.Dynamic, c.refs, c.inconclusive)
		}
		if got := eventNames(s.PRCodeOn); len(c.refs) > 0 && !slices.Equal(got, c.events) {
			t.Errorf("%s: events %q, want %q", c.name, got, c.events)
		}
	}
}

// TestDownloadDestination: where a download puts the files.
func TestDownloadDestination(t *testing.T) {
	const with = "{run-id: '${{ github.event.workflow_run.id }}', github-token: '${{ github.token }}', path: %s}"
	for _, c := range []struct {
		name, uses, path string
		want             analysis.DownloadDestination
		root             Placement
		missing          int
	}{
		{"none", "actions/download-artifact@v4", "", analysis.DownloadDestinationWorkspace, ws("."), 0},
		{"relative", "actions/download-artifact@v4", "dist", analysis.DownloadDestinationWorkspace, ws("dist"), 0},
		{"dot slash", "actions/download-artifact@v4", "./dist/", analysis.DownloadDestinationWorkspace, ws("dist"), 0},
		{"github.workspace", "actions/download-artifact@v4", "'${{ github.workspace }}/out'", analysis.DownloadDestinationWorkspace, ws("out"), 0},
		{"literal RUNNER_TEMP", "actions/download-artifact@v4", "'$RUNNER_TEMP/artifacts'", analysis.DownloadDestinationWorkspace, ws("$RUNNER_TEMP/artifacts"), 0},
		{"runner.temp", "actions/download-artifact@v4", "'${{ runner.temp }}/artifacts'", analysis.DownloadDestinationRunnerTemp, rt("artifacts"), 0},
		{"runner.temp alone", "actions/download-artifact@v4", "'${{ runner.temp }}'", analysis.DownloadDestinationRunnerTemp, rt(""), 0},
		{"runner.temp compact", "actions/download-artifact@v4", "'${{runner.temp}}/a'", analysis.DownloadDestinationRunnerTemp, rt("a"), 0},
		{"runner.temp upper", "actions/download-artifact@v4", "'${{ RUNNER.TEMP }}/a'", analysis.DownloadDestinationRunnerTemp, rt("a"), 0},
		{"runner.temp leaves", "actions/download-artifact@v4", "'${{ runner.temp }}/../x'", analysis.DownloadDestinationInconclusive, workspacePlacement(anyDir()), 0},
		{"runner.temp glued", "actions/download-artifact@v4", "'${{ runner.temp }}x'", analysis.DownloadDestinationInconclusive, workspacePlacement(anyDir()), 0},
		{"runner.temperature", "actions/download-artifact@v4", "'${{ runner.temperature }}/x'", analysis.DownloadDestinationInconclusive, workspacePlacement(anyDir()), 0},
		{"env.RUNNER_TEMP", "actions/download-artifact@v4", "'${{ env.RUNNER_TEMP }}/x'", analysis.DownloadDestinationInconclusive, workspacePlacement(anyDir()), 0},
		{"/tmp", "actions/download-artifact@v4", "/tmp/x", analysis.DownloadDestinationInconclusive, workspacePlacement(anyDir()), 0},
		{"home", "actions/download-artifact@v4", "'~/x'", analysis.DownloadDestinationInconclusive, workspacePlacement(anyDir()), 0},
		{"windows", "actions/download-artifact@v4", "'C:\\x'", analysis.DownloadDestinationInconclusive, workspacePlacement(anyDir()), 0},
		{"leaves", "actions/download-artifact@v4", "../x", analysis.DownloadDestinationInconclusive, workspacePlacement(anyDir()), 0},
		{"zip-slip release", "actions/download-artifact@v4.1.2", "'${{ runner.temp }}/a'", analysis.DownloadDestinationWorkspace, ws("."), 0},
		{"fixed release", "actions/download-artifact@v4.1.3", "'${{ runner.temp }}/a'", analysis.DownloadDestinationRunnerTemp, rt("a"), 0},
		{"zip-slip commit", "actions/download-artifact@eaceaf801fd36c7dee90939fad912460b18a1ffe", "'${{ runner.temp }}/a'", analysis.DownloadDestinationWorkspace, ws("."), 0},
		{"commit not in the tables", "actions/download-artifact@0123456789abcdef0123456789abcdef01234567", "'${{ runner.temp }}/a'", analysis.DownloadDestinationWorkspace, ws("."), 1},
	} {
		w := "{run-id: '${{ github.event.workflow_run.id }}', github-token: '${{ github.token }}'}"
		if c.path != "" {
			w = fmt.Sprintf(with, c.path)
		}
		s := oneDownload(t, runOn, "", c.uses, w, "      - run: echo\n")
		if s.Destination != c.want || s.DestinationRoot != c.root || len(s.MissingCommits) != c.missing {
			t.Errorf("%s: %v %v %d; want %v %v %d", c.name, s.Destination, s.DestinationRoot, len(s.MissingCommits), c.want, c.root, c.missing)
		}
	}
}

// TestDownloadActionsRead: the actions scope of the token of a download.
func TestDownloadActionsRead(t *testing.T) {
	for _, c := range []struct {
		name, jobExtra, token string
		want                  analysis.ActionsRead
	}{
		{"github.token, unwritten", "", "${{ github.token }}", analysis.ActionsReadUnwritten},
		{"GITHUB_TOKEN, actions read", "    permissions: {actions: read}\n", "${{ secrets.GITHUB_TOKEN }}", analysis.ActionsReadYes},
		{"github.token, contents only", "    permissions: {contents: read}\n", "${{ github.token }}", analysis.ActionsReadNo},
		{"a PAT", "    permissions: {contents: read}\n", "${{ secrets.PAT }}", analysis.ActionsReadNotNeeded},
	} {
		s := oneDownload(t, runOn, c.jobExtra, "actions/download-artifact@v4", "{run-id: '${{ github.event.workflow_run.id }}', github-token: '"+c.token+"'}", "")
		if s.ActionsRead != c.want {
			t.Errorf("%s: %v, want %v", c.name, s.ActionsRead, c.want)
		}
	}
	// dawidd6's github_token is github.token when not written
	s := oneDownload(t, runOn, "    permissions: {contents: read}\n", "dawidd6/action-download-artifact@v6", "{run_id: '${{ github.event.workflow_run.id }}'}", "")
	if s.ActionsRead != analysis.ActionsReadNo {
		t.Errorf("dawidd6 default token: %v", s.ActionsRead)
	}
}

// TestDownloadEvidenceAndApproval: the steps after it, as codeRuns reads
// them from the destination's root, and the approval of the job.
func TestDownloadEvidenceAndApproval(t *testing.T) {
	s := oneDownload(t, runOn, "    environment: prod\n", "actions/download-artifact@v4",
		"{run-id: '${{ github.event.workflow_run.id }}', github-token: '${{ github.token }}'}", "      - run: npm ci\n")
	if len(s.CodeRunSteps) != 1 || s.CodeRunSteps[0].Text != "npm ci" || s.Approval != analysis.ApprovalEnvironment || s.Environment.String() != "prod" {
		t.Errorf("%+v", s)
	}
	// GHSL-2024-125: chmod, then the script of the artifact
	s = oneDownload(t, runOn, "", "dawidd6/action-download-artifact@v3",
		"{workflow: '${{ github.event.workflow_run.workflow_id }}', workflow_conclusion: success, name: documentation, path: documentation-temp}",
		"      - run: |\n          chmod 755 ./documentation-temp/docs/sync-web-site.sh\n          ./documentation-temp/docs/sync-web-site.sh main ../../\n")
	if len(s.CodeRunSteps) != 1 || s.CodeRunSteps[0].Text != "./documentation-temp/docs/sync-web-site.sh main ../../" {
		t.Errorf("GHSL-2024-125: %+v", s.CodeRunSteps)
	}
}

// TestDownloadAction: a composite action.yml's download runs on every
// privileged event, and its token is taken as reading.
func TestDownloadAction(t *testing.T) {
	a := mustAction(t, "runs:\n  using: composite\n  steps:\n    - uses: actions/download-artifact@v4\n      with:\n        run-id: ${{ github.event.workflow_run.id }}\n        github-token: ${{ github.token }}\n    - run: make\n      shell: bash\n")
	sites := AnalyzeDownloads(nil, a, nil)
	if len(sites) != 1 || len(sites[0].PRRunRefs) != 1 || sites[0].ActionsRead != analysis.ActionsReadYes || len(sites[0].CodeRunSteps) != 1 {
		t.Errorf("%+v", sites)
	}
}

func TestDownloadTables(t *testing.T) {
	if !downloadFixedOn[downloadFixed] || !dawidd6NoForksOn[dawidd6NoForks] {
		t.Error("a fix's commit is not in its table")
	}
	for c := range downloadBefore4 {
		if downloadZipSlip[c] || downloadFixedOn[c] {
			t.Errorf("%s is in two tables", c)
		}
	}
	for c := range downloadZipSlip {
		if downloadFixedOn[c] {
			t.Errorf("%s is in two tables", c)
		}
	}
	for c := range dawidd6Forks {
		if dawidd6NoForksOn[c] {
			t.Errorf("%s is in two tables", c)
		}
	}
	if len(dawidd6Forks) != 50 || len(dawidd6NoForksOn) != 25 {
		t.Errorf("dawidd6: %d, %d", len(dawidd6Forks), len(dawidd6NoForksOn))
	}
}

// TestDownloadSearchesAndTokens: searches whose allow_forks or run id is
// not plain, releases before allow_forks, tokens and destinations that a
// ${{ }} decides, and the zip-slip of a release.
func TestDownloadSearchesAndTokens(t *testing.T) {
	const tok = "github-token: '${{ github.token }}'"
	for _, c := range []struct {
		name, on, jobExtra, uses, with string
		refs                           []string
		inconclusive                   int
		events                         []string
	}{
		// a search whose allow_forks is not known holds on any event
		{"allow_forks by a ${{ }} on push", "push", "", "dawidd6/action-download-artifact@v6", "{allow_forks: '${{ inputs.f }}'}", []string{"uses dawidd6/action-download-artifact@v6"}, 0, []string{"push/"}},
		// run_id may be empty on another event, and v3 then searches forks
		{"run_id on push too, v3", "[push, workflow_run]", "", "dawidd6/action-download-artifact@v3", "{run_id: '${{ github.event.workflow_run.id }}'}", []string{"run_id github.event.workflow_run.id", "uses dawidd6/action-download-artifact@v3"}, 0, []string{"push/", "workflow_run/completed", "workflow_run/in_progress", "workflow_run/requested"}},
		{"run_id empty, v3", "push", "", "dawidd6/action-download-artifact@v3", "{run_id: ''}", []string{"uses dawidd6/action-download-artifact@v3"}, 0, []string{"push/"}},
		{"run_id a number, v3", "push", "", "dawidd6/action-download-artifact@v3", "{run_id: '123'}", nil, 0, nil},
		// a run_id that the one who starts the run chooses: no search, as its
		// value is not empty; one that an env or a step makes may be empty
		{"run_id of a client_payload, v6", "repository_dispatch", "", "dawidd6/action-download-artifact@v6", "{run_id: '${{ github.event.client_payload.run }}'}", nil, 1, nil},
		{"run_id of an input, v6", "workflow_dispatch", "", "dawidd6/action-download-artifact@v6", "{run_id: '${{ inputs.run }}'}", nil, 0, nil},
		{"run_id of an env, v6", "push", "", "dawidd6/action-download-artifact@v6", "{run_id: '${{ env.RUN }}'}", []string{"uses dawidd6/action-download-artifact@v6"}, 1, []string{"push/"}},
		// on the events whose payload lacks the value, the release searches
		{"run_id of a client_payload on push too, v3", "[push, repository_dispatch]", "", "dawidd6/action-download-artifact@v3", "{run_id: '${{ github.event.client_payload.run_id }}'}", []string{"uses dawidd6/action-download-artifact@v3"}, 1, []string{"push/"}},
		{"run_id of an input on push too, v3", "[push, workflow_dispatch]", "", "dawidd6/action-download-artifact@v3", "{run_id: '${{ inputs.run }}'}", []string{"uses dawidd6/action-download-artifact@v3"}, 0, []string{"push/"}},
		{"run_id of github.event.inputs on schedule too, v6", "[schedule, workflow_dispatch]", "", "dawidd6/action-download-artifact@v6", "{run_id: '${{ github.event.inputs.run }}'}", []string{"uses dawidd6/action-download-artifact@v6"}, 0, []string{"schedule/"}},
		{"run_id of the payload or an input, v6", "[push, workflow_run]", "", "dawidd6/action-download-artifact@v6", "{run_id: '${{ github.event.workflow_run.id || inputs.x }}'}", []string{"run_id github.event.workflow_run.id", "uses dawidd6/action-download-artifact@v6"}, 0, []string{"push/", "workflow_run/completed", "workflow_run/in_progress", "workflow_run/requested"}},
		{"run_id with text written out, v6", "push", "", "dawidd6/action-download-artifact@v6", "{run_id: '1${{ env.N }}'}", nil, 1, nil},
		{"run_id of the payload on push too, v6", "[push, workflow_run]", "", "dawidd6/action-download-artifact@v6", "{run_id: '${{ github.event.workflow_run.id }}'}", []string{"run_id github.event.workflow_run.id", "uses dawidd6/action-download-artifact@v6"}, 0, []string{"push/", "workflow_run/completed", "workflow_run/in_progress", "workflow_run/requested"}},
		// before v2.28.0 there is no allow_forks: forks are searched
		{"allow_forks false before v2.28.0", "push", "", "dawidd6/action-download-artifact@v2.27.0", "{allow_forks: false}", []string{"uses dawidd6/action-download-artifact@v2.27.0"}, 0, []string{"push/"}},
		{"allow_forks false at v2.28.0", "push", "", "dawidd6/action-download-artifact@v2.28.0", "{allow_forks: false}", []string{"uses dawidd6/action-download-artifact@v2.28.0"}, 0, []string{"push/"}},
		// one value once
		{"repo by an input", "push", "", "dawidd6/action-download-artifact@v6", "{repo: '${{ inputs.r }}'}", nil, 1, []string{"push/"}},
		// no run-id is the current run, whatever the token
		{"token by an input, no run-id", runOn, "", "actions/download-artifact@v4", "{github-token: '${{ inputs.t }}'}", nil, 0, nil},
	} {
		s := oneDownload(t, c.on, c.jobExtra, c.uses, c.with, "      - run: echo\n")
		if got := runRefTexts(s.PRRunRefs); !slices.Equal(got, c.refs) || len(s.InconclusiveValues) != c.inconclusive {
			t.Errorf("%s: refs %q inconclusive %d; want %q %d", c.name, got, len(s.InconclusiveValues), c.refs, c.inconclusive)
		}
		if got := eventNames(s.PRCodeOn); (len(c.refs) > 0 || c.inconclusive > 0) && !slices.Equal(got, c.events) {
			t.Errorf("%s: events %q, want %q", c.name, got, c.events)
		}
	}
	// the token's scope is read before the repository
	s := oneDownload(t, runOn, "    permissions: {contents: read}\n", "actions/download-artifact@v4", "{run-id: '${{ github.event.workflow_run.id }}', "+tok+", repository: '${{ inputs.r }}'}", "")
	if s.ActionsRead != analysis.ActionsReadNo {
		t.Errorf("the token's scope: %v", s.ActionsRead)
	}
	// a with of a whole ${{ }} has no known destination
	s = oneDownload(t, runOn, "", "actions/download-artifact@v4", "'${{ fromJSON(inputs.w) }}'", "")
	if s.Destination != analysis.DownloadDestinationInconclusive {
		t.Errorf("a destination a ${{ }} decides: %v", s.Destination)
	}
	// a release with the zip-slip writes anywhere from a subdirectory too
	s = oneDownload(t, runOn, "", "actions/download-artifact@v4.1.2", "{run-id: '${{ github.event.workflow_run.id }}', "+tok+", path: dist}", "      - run: npm ci\n")
	if s.DestinationRoot != ws(".") || len(s.CodeRunSteps) != 1 {
		t.Errorf("the zip-slip of a release: %v %d", s.DestinationRoot, len(s.CodeRunSteps))
	}
}

// sameRunWorkflow is a workflow on pull_request_target whose job build
// checks out the pull request's head and uploads, and whose job deploy
// downloads; the parts vary by case.
func sameRunWorkflow(on, buildIf, buildSteps, deployNeeds, download string) string {
	return "on: " + on + "\njobs:\n" +
		"  build:\n    runs-on: ubuntu-latest\n" + buildIf + "    steps:\n" + buildSteps +
		"  test:\n    runs-on: ubuntu-latest\n    needs: build\n    steps:\n      - run: echo ok\n" +
		"  deploy:\n    runs-on: ubuntu-latest\n" + deployNeeds + "    permissions:\n      contents: write\n    steps:\n" + download +
		"      - run: ./run.sh\n"
}

const (
	srCheckout = "      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
	srUpload   = "      - uses: actions/upload-artifact@v4\n        with:\n          name: out\n          path: out\n"
	srDownload = "      - uses: actions/download-artifact@v4\n        with:\n          name: out\n"
	srNeeds    = "    needs: build\n"
	// srCheckoutPR checks out the pull request's head into the directory pr
	srCheckoutPR = "      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          path: pr\n"
)

// srUploadPath is an upload of the artifact out with the path p.
func srUploadPath(p string) string {
	return "      - uses: actions/upload-artifact@v4\n        with:\n          name: out\n          path: '" + p + "'\n"
}

func TestSameRunUploads(t *testing.T) {
	cases := []struct {
		name, on, buildIf, buildSteps, deployNeeds, download string
		want                                                 []string
		wantOn                                               []string
	}{
		{"needs", "pull_request_target", "", srCheckout + srUpload, srNeeds, srDownload, []string{"jobs.build"}, []string{"pull_request_target"}},
		{"v3", "pull_request_target", "", srCheckout + srUpload, srNeeds, strings.Replace(srDownload, "@v4", "@v3", 1), []string{"jobs.build"}, []string{"pull_request_target"}},
		{"transitive", "pull_request_target", "", srCheckout + srUpload, "    needs: test\n", srDownload, []string{"jobs.build"}, []string{"pull_request_target"}},
		{"no needs", "pull_request_target", "", srCheckout + srUpload, "", srDownload, nil, nil},
		{"upload before checkout", "pull_request_target", "", srUpload + srCheckout, srNeeds, srDownload, nil, nil},
		{"name differs", "pull_request_target", "", srCheckout + srUpload, srNeeds, strings.Replace(srDownload, "name: out", "name: other", 1), nil, nil},
		{"no name", "pull_request_target", "", srCheckout + srUpload, srNeeds, "      - uses: actions/download-artifact@v4\n", []string{"jobs.build"}, []string{"pull_request_target"}},
		{"pattern", "pull_request_target", "", srCheckout + srUpload, srNeeds, "      - uses: actions/download-artifact@v4\n        with:\n          pattern: o*\n", []string{"jobs.build"}, []string{"pull_request_target"}},
		{"base checkout", "pull_request_target", "", "      - uses: actions/checkout@v4\n" + srUpload, srNeeds, srDownload, nil, nil},
		{"run-id other run", "\n  workflow_run:\n    workflows: [ci]\n    types: [completed]", "", srCheckout + srUpload, srNeeds,
			"      - uses: actions/download-artifact@v4\n        with:\n          name: out\n          run-id: ${{ github.event.workflow_run.id }}\n          github-token: ${{ github.token }}\n", nil, nil},
		{"push only", "push", "", srCheckout + srUpload, srNeeds, srDownload, nil, nil},
		{"guarded major tag", "pull_request_target", "", strings.Replace(srCheckout, "@v4.2.2", "@v4", 1) + srUpload, srNeeds, srDownload, nil, nil},
		{"guard SHA", "pull_request_target", "", strings.Replace(srCheckout, "@v4.2.2", "@0123456789abcdef0123456789abcdef01234567", 1) + srUpload, srNeeds, srDownload, []string{"jobs.build"}, []string{"pull_request_target"}},
		{"upload if push only", "[push, pull_request_target]", "", srCheckout + "      - if: github.event_name == 'push'\n        uses: actions/upload-artifact@v4\n        with:\n          name: out\n          path: out\n", srNeeds, srDownload, nil, nil},
		{"needs case", "pull_request_target", "", srCheckout + srUpload, "    needs: Build\n", srDownload, []string{"jobs.build"}, []string{"pull_request_target"}},
		{"v3 upload v4 download", "pull_request_target", "", srCheckout + strings.Replace(srUpload, "@v4", "@v3", 1), srNeeds, srDownload, nil, nil},
		{"run-id written no token", "pull_request_target", "", srCheckout + srUpload, srNeeds, "      - uses: actions/download-artifact@v4\n        with:\n          name: out\n          run-id: '123'\n", []string{"jobs.build"}, []string{"pull_request_target"}},
		{"pattern braces", "pull_request_target", "", srCheckout + srUpload, srNeeds, "      - uses: actions/download-artifact@v4\n        with:\n          pattern: '{out,x}'\n", []string{"jobs.build"}, []string{"pull_request_target"}},
		{"unrelated upload", "pull_request_target", "", srCheckoutPR + "      - run: echo ${{ github.event.pull_request.number }} > number.txt\n" + srUploadPath("number.txt"), srNeeds, srDownload, nil, nil},
		{"upload covers checkout", "pull_request_target", "", srCheckoutPR + srUploadPath("pr/dist"), srNeeds, srDownload, []string{"jobs.build"}, []string{"pull_request_target"}},
		{"upload of the workspace", "pull_request_target", "", srCheckoutPR + srUploadPath("."), srNeeds, srDownload, []string{"jobs.build"}, []string{"pull_request_target"}},
		{"code runs", "pull_request_target", "", srCheckoutPR + "      - run: ./pr/build.sh\n" + srUploadPath("number.txt"), srNeeds, srDownload, []string{"jobs.build"}, []string{"pull_request_target"}},
		{"upload path expression", "pull_request_target", "", srCheckoutPR + srUploadPath("${{ inputs.dir }}"), srNeeds, srDownload, []string{"jobs.build"}, []string{"pull_request_target"}},
		{"label approval", "\n  pull_request_target:\n    types: [labeled]", "    if: github.event.label.name == 'safe to test'\n", srCheckout + srUpload, srNeeds, srDownload, []string{"jobs.build"}, []string{"pull_request_target"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := mustWorkflow(t, sameRunWorkflow(tc.on, tc.buildIf, tc.buildSteps, tc.deployNeeds, tc.download))
			var site *DownloadSite
			for _, s := range AnalyzeDownloads(w, nil, nil) {
				if strings.Contains(s.Path.String(), "deploy") {
					site = &s
				}
			}
			if site == nil {
				t.Fatal("no download site in deploy")
			}
			var got []string
			for _, u := range site.SameRunUploads {
				got = append(got, u.Text)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("SameRunUploads = %q, want %q", got, tc.want)
			}
			var on []string
			for _, e := range site.PRCodeOn {
				if n := e.Name().String(); !slices.Contains(on, n) {
					on = append(on, n)
				}
			}
			if tc.want != nil && !slices.Equal(on, tc.wantOn) {
				t.Errorf("PRCodeOn = %q, want %q", on, tc.wantOn)
			}
			if guardSHA := tc.name == "guard SHA"; len(site.SameRunUploads) > 0 && guardSHA != (len(site.SameRunUploads[0].Unless) > 0) {
				t.Errorf("Unless = %v", site.SameRunUploads[0].Unless)
			}
		})
	}
}
