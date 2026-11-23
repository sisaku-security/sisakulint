package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/ident"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// limitFacts answers git.ref-commit with a commit, so that commit-sha's
// findings are whole, and git.commit-ref absent: no branch or tag has the
// commit, which impostor-commit reports. For the rules of checkouts it
// answers the worst case: the tree runs, no environment approves, no pinned
// commit has the guard. For the rules of artifacts, the default token
// writes. For the rules of jobs, the repository is public. For
// known-vulnerable-actions, the advisories and the tags its examples ask
// (knownVulnerableFacts), and of other packages and commits none.
type limitFacts struct{}

func (limitFacts) Resolve(ctx context.Context, q facts.Query) facts.RawAnswer {
	if a, ok := knownVulnerableAnswer(ctx, q); ok {
		return a
	}
	switch q := q.(type) {
	case facts.GitCommitRef:
		return facts.RawAnswer{State: facts.StateAbsent}
	case facts.CheckoutExecuted:
		return facts.RawAnswer{State: facts.StateFound, Value: []byte("true")}
	case facts.RepoEnvironmentProtected, facts.GitCommitContains:
		return facts.RawAnswer{State: facts.StateFound, Value: []byte("false")}
	case facts.RepoDefaultTokenWrite, facts.RepoPublic:
		return facts.RawAnswer{State: facts.StateFound, Value: []byte("true")}
	case facts.RepoArchived:
		// actions/create-release is archived
		return facts.RawAnswer{State: facts.StateFound, Value: []byte(strconv.FormatBool(q.Repo.String() == "actions/create-release"))}
	case facts.DependabotVersionUpdates, facts.RenovateManagerEnabled:
		return dependabotExampleAnswer(q)
	case facts.ActionRunsUsing:
		// v1 of actions/create-release declares node12; the
		// actions of the other examples are read as node24
		using := facts.RunsUsingNode24
		switch q.Repo.String() {
		case "actions/create-release":
			using = facts.RunsUsingNode12
		case "example-org/release-action": // the composite action of the undetected form remote-composite
			using = facts.RunsUsingComposite
		}
		b, _ := json.Marshal(using)
		return facts.RawAnswer{State: facts.StateFound, Value: b}
	case facts.ActionDefinition:
		return actionDefinitionAnswer(q)
	case facts.WorkflowDefinition:
		if a, ok := workflowDefinitionAnswer(q); ok {
			return a
		}
	case facts.RepoActionList:
		return facts.RawAnswer{State: facts.StateFound, Value: []byte(exampleActionList)}
	}
	return anyRef{}.Resolve(ctx, q)
}

// exampleActionList is the repo.action-list of every example but those of
// exampleActionLists. repo.action-list has no argument and limitFacts does
// not know the example, so every example gets one list: * and patterns
// with ! that block the names that the examples of action-list name as
// unlisted. The examples of the other rules name none of those, so
// action-list reports nothing in them.
// tj-actions/changed-files@v39 is the uses of coinbase/agentkit
// (agentkit-2025), and aquasec/trivy the image of trivy-image-2026.
const exampleActionList = `["*","!untrusted/*","!suspicious/*","!tj-actions/changed-files@v39","!docker://aquasec/trivy:*","!example-org/unlisted-*","!docker://example-org/unlisted-*","!example-org/partly-listed/hidden@*"]`

// exampleActionLists are the examples whose repo.action-list is not
// exampleActionList, by <what>/<rule>/<id>: the list as JSON, or "" for
// none (the undetected form list-unknown). The true positive of the
// upstream sisakulint's test has a list of the form owner/repo@* that
// users of the upstream write.
var exampleActionLists = map[string]string{
	"undetected/action-list/list-unknown":           "",
	"false-positive/action-list/wildcard-case":      `["*/Octocat@*"]`,
	"false-positive/action-list/blocked-case":       `["*","!actions/checkout@V4"]`,
	"false-positive/action-list/image-alias-listed": `["docker://alpine:*"]`,
	"true-positive/action-list/unlisted":            `["actions/checkout@*","actions/setup-go@*"]`,
}

// exampleVariables are the names of configuration variables that the
// examples answer, by <what>/<rule>/<id>: by the key "" the names of
// repo.configuration-variables, by the name of an environment those of
// repo.environment-configuration-variables. The examples not here answer
// neither, so unset-configuration-variable does not run in them.
var exampleVariables = map[string]map[string]string{
	"true-positive/unset-configuration-variable/empty-value.misspelled":    {"": `["DEPLOY_URL","NODE_VERSION"]`, "production": `["PRODUCTION_KEY_ID"]`},
	"true-positive/unset-configuration-variable/empty-value.remote-callee": {"": `["DEPLOY_URL","NODE_VERSION"]`, "production": `["PRODUCTION_KEY_ID"]`},
	"true-positive/unset-configuration-variable/empty-value.run-name":      {"": `[]`, "release": `["RELEASE_CHANNEL"]`},
	"true-positive/unset-configuration-variable/failed-from-json":          {"": `["NODE_VERSION"]`},
	"true-negative/unset-configuration-variable/empty-value":               {"": `["DEPLOY_URL","NODE_VERSION"]`, "production": `["PRODUCTION_KEY_ID"]`},
	"true-negative/unset-configuration-variable/failed-from-json":          {"": `["NODE_VERSION"]`},
	"undetected/unset-configuration-variable/environment-unknown":          {"": `[]`},
	"undetected/unset-configuration-variable/compared":                     {"": `["DEPLOY"]`},
	"undetected/unset-configuration-variable/dynamic-name":                 {"": `["US_ENDPOINT"]`},
	"undetected/unset-configuration-variable/environment-expression":       {"": `[]`, "production": `[]`, "staging": `[]`},
	"undetected/unset-configuration-variable/environment-before-start":     {"": `[]`, "production": `["RUNNER_LABEL"]`},
	"undetected/unset-configuration-variable/remote-caller-only":           {"": `[]`},
	"undetected/unset-configuration-variable/size-limit":                   {"": `["LARGE_CONFIG"]`},
	"undetected/unset-configuration-variable/fork-pull-request":            {"": `["LINT_LEVEL"]`},
	"undetected/unset-configuration-variable/remote-callee":                {"": `[]`},
	"undetected/unset-configuration-variable/other-job-environment":        {"": `[]`, "production": `["DEPLOY_HOST"]`},
	"undetected/unset-configuration-variable/unread-key":                   {"": `[]`},
	"false-positive/unset-configuration-variable/script-default":           {"": `[]`},
	"false-positive/unset-configuration-variable/action-empty-input":       {"": `[]`},
}

// exampleAllowedActions are the settings of allowed actions of GitHub
// (repo.allowed-actions) that the examples answer, by <what>/<rule>/<id>, as
// JSON. The examples not here answer none, so allowed-actions does not run
// in them; the true positive of remote-callee, made of the true positive
// unstarted-run, answers that one's setting.
var exampleAllowedActions = map[string]string{
	"true-positive/allowed-actions/unstarted-run":               allowedActionsPatterns,
	"true-positive/allowed-actions/failed-job":                  allowedActionsPatterns,
	"true-positive/allowed-actions/unpinned-action":             allowedActionsPinning,
	"true-negative/allowed-actions/unstarted-run":               allowedActionsPatterns,
	"true-negative/allowed-actions/failed-job":                  allowedActionsPatterns,
	"true-negative/allowed-actions/unpinned-action":             allowedActionsPinning,
	"true-negative/allowed-actions/unpinned-action.never-runs":  allowedActionsPinning,
	"undetected/allowed-actions/verified-creator":               `{"allowed_actions":"selected","github_owned_allowed":false,"verified_allowed":true,"patterns_allowed":[],"sha_pinning_required":false}`,
	"undetected/allowed-actions/lockfile-tag":                   `{"allowed_actions":"selected","github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":["actions/cache@v4"],"sha_pinning_required":false}`,
	"undetected/allowed-actions/remote-composite":               `{"allowed_actions":"selected","github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":["*","!gradle/actions/setup-gradle@*"],"sha_pinning_required":false}`,
	"undetected/allowed-actions/outside-actions-directory":      `{"allowed_actions":"selected","github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":["*","!example-org/*"],"sha_pinning_required":false}`,
	"undetected/allowed-actions/self-outside":                   `{"allowed_actions":"selected","github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":["*","!example-org/partly-listed/hidden@*"],"sha_pinning_required":false}`,
	"undetected/allowed-actions/metadata-image":                 allowedActionsPatterns,
	"undetected/allowed-actions/remote-callee":                  `{"allowed_actions":"selected","github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":["*"],"sha_pinning_required":false}`,
	"false-positive/allowed-actions/owner-unknown":              allowedActionsNone,
	"false-positive/allowed-actions/same-enterprise":            allowedActionsNone,
	"false-positive/allowed-actions/lockfile-sha":               `{"allowed_actions":"selected","github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":["actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830"],"sha_pinning_required":false}`,
	"false-positive/allowed-actions/other-repository-caller":    allowedActionsPatterns,
	"false-positive/allowed-actions/lockfile-pinned":            allowedActionsPinning,
	"false-positive/allowed-actions/job-never-runs":             allowedActionsPinning,
	"undetected/allowed-actions/composite-image":                allowedActionsPatterns,
	"undetected/allowed-actions/remote-called-pinning":          allowedActionsPinning,
	"true-positive/allowed-actions/unstarted-run.remote-callee": allowedActionsPatterns,
}

// The settings of allowed actions that several examples answer: patterns
// that allow gradle/* and docker://alpine:* but block
// gradle/actions/setup-gradle (the forms of the runs that the authors of
// the rule made on GitHub); all actions with a full commit SHA required;
// and no pattern.
const (
	allowedActionsPatterns = `{"allowed_actions":"selected","github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":["gradle/*","!gradle/actions/setup-gradle@*","docker://alpine:*"],"sha_pinning_required":false}`
	allowedActionsPinning  = `{"allowed_actions":"all","sha_pinning_required":true}`
	allowedActionsNone     = `{"allowed_actions":"selected","github_owned_allowed":false,"verified_allowed":false,"patterns_allowed":[],"sha_pinning_required":false}`
)

// exampleCompositeSave is a composite action whose step saves dist to the
// cache, which the examples of cache-poisoning call.
const exampleCompositeSave = "runs:\n  using: composite\n  steps:\n    - uses: actions/cache/save@v4\n      with:\n        key: dist-${{ github.sha }}\n        path: dist\n"

// workflowDefinitionAnswer answers workflow.definition for the examples
// that call a reusable workflow of another repository and read it, and for
// those whose rule does not read the answer (the undetected form
// remote-callee, TestSecurityLabGHSL2026229Remote); false
// for the other repositories, whose examples no one asks (the undetected
// forms of a reusable workflow of another repository with no answer).
func workflowDefinitionAnswer(q facts.WorkflowDefinition) (facts.RawAnswer, bool) {
	sha, _ := facts.ParseSHA(strings.Repeat("e", 40))
	v := facts.WorkflowFile{Commit: sha}
	if content, ok := remoteSourceOf(q.Repo.String()); ok {
		v.Content = content // remoteCalleeExamples
		b, _ := json.Marshal(v)
		return facts.RawAnswer{State: facts.StateFound, Value: b}, true
	}
	if r := q.Repo.String(); strings.HasPrefix(r, "example-org/") && strings.HasSuffix(r, "-unknown") {
		return facts.RawAnswer{State: facts.StateUnknown, Reason: "the token cannot read the file"}, true // remoteCalleeExamples
	}
	switch q.Repo.String() {
	case "example-org/self-hosted-workflow":
		v.Content = "on: workflow_call\njobs:\n  build:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: make\n"
	case "example-org/cache-write-workflow":
		v.Content = "on: workflow_call\njobs:\n  build:\n    runs-on: ubuntu-latest\n    cache-mode: write\n    steps:\n      - run: make\n"
	case "example-org/checkout-cache-workflow":
		v.Content = "on: workflow_call\njobs:\n  build:\n    runs-on: ubuntu-latest\n    cache-mode: write\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - uses: actions/cache/save@v4\n        with:\n          key: dist-${{ github.sha }}\n          path: dist\n"
	case "example-org/shared-workflow":
		v.Content = "on:\n  workflow_call:\n    inputs:\n      dry-run:\n        type: boolean\n        required: true\npermissions: {contents: read}\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n      - run: ./deploy.sh\n"
	case "example-org/release-workflow":
		v.Content = "on: workflow_call\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/create-release@v1\n"
	case "example-org/nested-workflow":
		v.Content = "on: workflow_call\njobs:\n  inner:\n    uses: actions/create-release/.github/workflows/release.yml@v1\n"
	case "example-org/two-jobs-workflow": // TestRemoteDuplicates
		v.Content = "on: workflow_call\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/create-release@v1\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/create-release@v1\n"
	case "example-org/nested-cache-workflow":
		v.Content = "on: workflow_call\njobs:\n  inner:\n    uses: example-org/cache-write-workflow/.github/workflows/build.yml@v1\n"
	case "ipdxco/unified-github-workflows": // TestSecurityLabGHSL2026229Remote: the steps version and prev of GHSL-2026-229
		v.Content = "on: workflow_call\njobs:\n  release-check:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v5\n      - id: version\n        env:\n          HEAD_SHA: ${{ github.event.pull_request.head.sha }}\n        run: |\n          prefix=\"v\"\n          echo \"prefix=$prefix\" | tee -a $GITHUB_OUTPUT\n          git fetch origin \"$HEAD_SHA\"\n          git checkout \"$HEAD_SHA\" -- version.json\n          version=\"$(yq -r '.version | select(type == \"!!str\")' version.json)\"\n          git checkout HEAD -- version.json\n          version=\"${version#v}\"\n          echo \"version=$version\" | tee -a $GITHUB_OUTPUT\n          echo \"tag=${prefix}${version}\" | tee -a $GITHUB_OUTPUT\n      - id: prev\n        env:\n          PREFIX: ${{ steps.version.outputs.prefix }}\n        run: |\n          git fetch origin --tags\n          vs=$(git tag | grep \"^${PREFIX}\" | sed \"s#^${PREFIX}#v#\" | paste -sd , -)\n          echo \"vs=$vs\"\n"
	case "example-org/code-injection-workflow":
		v.Content = "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"\n"
	case "example-org/output-clobbering-workflow":
		v.Content = "on: workflow_call\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          T: ${{ github.event.pull_request.title }}\n        run: echo \"t=$T\" >> \"$GITHUB_OUTPUT\"\n"
	case "example-org/argument-injection-workflow":
		v.Content = "on: workflow_call\njobs:\n  unpack:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          HEAD_REF: ${{ format('{0}', github.head_ref) }}\n        run: tar -xf archive.tar notes.txt \"$HEAD_REF\"\n"
	case "example-org/composite-workflow": // remote-called-composite of action-list
		v.Content = "on: workflow_call\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: example-org/composite-in-workflow@v1\n"
	case "example-org/remote-checkout-workflow": // remote-not-executed of untrusted-checkout
		v.Content = "on: workflow_call\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          allow-unsafe-pr-checkout: true\n          path: pr\n      - run: wc -l pr/README.md\n"
	case "example-org/remote-download-workflow": // remote-not-executed of artifact-poisoning
		v.Content = "on: workflow_call\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          run-id: ${{ github.event.workflow_run.id }}\n          github-token: ${{ github.token }}\n      - run: wc -l report.txt\n"
	case "example-org/unreachable-workflow":
		return facts.RawAnswer{State: facts.StateUnknown, Reason: "github: .github/workflows/build.yml of example-org/unreachable-workflow could not be read: HTTP 403"}, true
	default:
		return facts.RawAnswer{}, false
	}
	b, _ := json.Marshal(v)
	return facts.RawAnswer{State: facts.StateFound, Value: b}, true
}

// unaskedDefinitions are the actions of the undetected forms of an action
// of another repository whose action.definition has no answer
// (remote-composite-unanswered of cache-poisoning, remote-composite of
// deprecated-node-runtime and archived-uses, remote-composite of
// known-vulnerable-actions, remote-action of unpinned-images): the facts
// of their examples do not have it, as a run that no one asks.
var unaskedDefinitions = []string{"example-org/unasked-composite", "example-org/release-action", "example-org/composite-action", "actions/hello-world-docker-action", "example-org/act"}

// actionDefinitionAnswer answers action.definition for the examples, by
// the repository: the composite actions of the examples of cache-poisoning,
// and a JavaScript action on node24 for the others (as action.runs-using).
func actionDefinitionAnswer(q facts.ActionDefinition) facts.RawAnswer {
	sha, _ := facts.ParseSHA(strings.Repeat("e", 40))
	v := facts.ActionFile{Commit: sha, File: facts.ActionFileYML, Content: "runs:\n  using: node24\n  main: index.js\n"}
	switch q.Repo.String() {
	case "example-org/cache-composite", "example-org/unasked-composite":
		v.Content = exampleCompositeSave
	case "example-org/node-composite":
		v.Content = "runs:\n  using: composite\n  steps:\n    - uses: actions/create-release@v1\n"
	case "example-org/vulnerable-composite":
		v.Content = "runs:\n  using: composite\n  steps:\n    - uses: actions/download-artifact@eaceaf801fd36c7dee90939fad912460b18a1ffe # v4.1.2\n"
	case "untrusted/pre-action":
		v.Content = "runs:\n  using: node24\n  pre: pre.js\n  main: index.js\n"
	case "example-org/docker-action":
		v.Content = "runs:\n  using: docker\n  image: docker://ghcr.io/o/scan:1\n"
	case "example-org/substituted-docker-action":
		v.Content, v.ArchiveSubstituted = "runs:\n  using: docker\n  image: docker://ghcr.io/o/scan:1\n", true
	case "example-org/codex-sandbox-composite":
		v.Content = "runs:\n  using: composite\n  steps:\n    - uses: openai/codex-action@v1\n      with:\n        openai-api-key: ${{ inputs.openai-api-key }}\n        prompt: \"Answer issue #${{ github.event.issue.number }}\"\n        sandbox: danger-full-access\n"
	case "example-org/claude-tools-composite":
		v.Content = "runs:\n  using: composite\n  steps:\n    - uses: anthropics/claude-code-action@v1\n      with:\n        github_token: ${{ github.token }}\n        allowed_non_write_users: \"*\"\n        prompt: \"Triage issue #${{ github.event.issue.number }}\"\n        claude_args: --allowedTools \"Bash,Read\"\n"
	case "example-org/claude-prompt-composite":
		v.Content = "runs:\n  using: composite\n  steps:\n    - uses: anthropics/claude-code-action@v1\n      with:\n        anthropic_api_key: ${{ inputs.anthropic-api-key }}\n        prompt: \"Triage this issue: ${{ github.event.issue.title }}\"\n"
	case "example-org/claude-note-composite":
		v.Content = "inputs:\n  anthropic-api-key:\n    description: The API key of Anthropic.\n  note:\n    description: A note for the triage.\nruns:\n  using: composite\n  steps:\n    - uses: anthropics/claude-code-action@v1\n      with:\n        anthropic_api_key: ${{ inputs.anthropic-api-key }}\n        prompt: \"Triage the open issues. ${{ inputs.note }}\"\n        claude_args: --allowedTools Bash\n"
	case "example-org/claude-note-unsafe-composite":
		v.Content = "inputs:\n  anthropic-api-key:\n    description: The API key of Anthropic.\n  note:\n    description: A note for the triage.\nruns:\n  using: composite\n  steps:\n    - uses: anthropics/claude-code-action@v1\n      with:\n        anthropic_api_key: ${{ inputs.anthropic-api-key }}\n        prompt: \"Triage the open issues. ${{ inputs.note }}\"\n        claude_args: --dangerously-skip-permissions\n"
	case "example-org/codex-fix-composite":
		v.Content = "runs:\n  using: composite\n  steps:\n    - uses: openai/codex-action@v1\n      with:\n        openai-api-key: ${{ inputs.openai-api-key }}\n        allow-users: \"*\"\n        sandbox: danger-full-access\n        prompt: \"Fix issue #${{ github.event.issue.number }}\"\n"
	case "example-org/substituted-agent-composite":
		v.Content, v.ArchiveSubstituted = "runs:\n  using: composite\n  steps:\n    - uses: openai/codex-action@v1\n      with:\n        allow-users: \"*\"\n        sandbox: danger-full-access\n        prompt: \"Fix issue #${{ github.event.issue.number }}\"\n", true
	case "example-org/pinned-substituted-action":
		v.Content, v.ArchiveSubstituted = "runs:\n  using: composite\n  steps:\n    - run: echo 'E6-DECORATE[ (tag: v9)]'\n      shell: bash\n", true
	case "example-org/two-save-composite": // TestRemoteDuplicates
		v.Content = "runs:\n  using: composite\n  steps:\n    - name: Save\n      uses: actions/cache/save@v4\n      with:\n        key: a-${{ github.sha }}\n        path: dist\n    - name: Save\n      uses: actions/cache/save@v4\n      with:\n        key: b-${{ github.sha }}\n        path: build\n"
	case "example-org/two-agent-composite": // TestRemoteDuplicates
		v.Content = "runs:\n  using: composite\n  steps:\n    - uses: anthropics/claude-code-action@v1\n      with:\n        prompt: \"Triage: ${{ github.event.issue.title }}\"\n    - uses: anthropics/claude-code-action@v1\n      with:\n        prompt: \"Triage: ${{ github.event.issue.title }}\"\n"
	case "example-org/guarded-outer-composite": // TestRemoteIfsBetween
		v.Content = "runs:\n  using: composite\n  steps:\n    - if: github.event_name == 'push'\n      uses: example-org/cache-composite@v1\n"
	case "example-org/docker-step-composite":
		v.Content = "runs:\n  using: composite\n  steps:\n    - uses: docker://ghcr.io/o/scan:1\n"
	case "example-org/pinned-docker-action":
		v.Content = "runs:\n  using: docker\n  image: docker://ghcr.io/o/scan@sha256:" + strings.Repeat("a", 64) + "\n"
	case "example-org/bloat-composite":
		v.Content = "runs:\n  using: composite\n  steps:\n    - uses: actions/cache@v4\n      with:\n        path: build\n        key: build-${{ github.run_id }}\n        restore-keys: build-\n"
	case "example-org/unpinned-step-composite": // remote-composite-steps of commit-sha
		v.Content = "runs:\n  using: composite\n  steps:\n    - uses: actions/setup-go@v5\n"
	case "example-org/title-composite": // remote-composite-steps of code-injection
		v.Content = "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo \"${{ github.event.issue.title }}\"\n"
	case "example-org/composite-in-workflow": // remote-called-composite of action-list
		v.Content = "runs:\n  using: composite\n  steps:\n    - uses: example-org/unlisted-step@v1\n"
	case "example-org/current-composite":
		v.Content = "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n"
	case "example-org/substituted-composite":
		v.Content, v.ArchiveSubstituted = exampleCompositeSave, true
	case "example-org/unreachable-composite":
		return facts.RawAnswer{State: facts.StateUnknown, Reason: "github: the archive is larger than 100 MiB"}
	case "example-org/ignored-composite": // export-ignore: the archive has no file there
		return facts.RawAnswer{State: facts.StateAbsent}
	}
	b, _ := json.Marshal(v)
	return facts.RawAnswer{State: facts.StateFound, Value: b}
}

// dependabotExampleFacts answer the two facts of the update tools for the
// examples of dependabot-github-actions, by the path of the example:
// Dependabot reads the file, and Renovate handles it. The examples of the
// other rules are read by Dependabot, so that the catalog shows no finding
// of dependabot-github-actions on them.
var dependabotExampleFacts = map[string][2]bool{
	"no-update-tool.yml":            {false, false},
	"unversioned-sha.yml":           {false, true},
	"no-update-tool.dependabot.yml": {true, false},
	"outside-config.yml":            {false, false},
	"other-ref.yml":                 {false, false},
	"fork.yml":                      {true, false},
	"not-running.yml":               {false, true},
	"renovate-line-form.yml":        {false, true},
	"folded-uses.yml":               {false, false},
	"hex-ref.yml":                   {false, true},
	"ignored-dependency.yml":        {true, false},
	"default-branch.yml":            {true, false},
}

func dependabotExampleAnswer(q facts.Query) facts.RawAnswer {
	var p string
	renovate := false
	switch q := q.(type) {
	case facts.DependabotVersionUpdates:
		p = q.InputPath.String()
	case facts.RenovateManagerEnabled:
		p, renovate = q.InputPath.String(), true
	}
	v, ok := dependabotExampleFacts[p]
	if !ok {
		v = [2]bool{true, false}
	}
	if renovate {
		return facts.RawAnswer{State: facts.StateFound, Value: []byte(strconv.FormatBool(v[1]))}
	}
	return facts.RawAnswer{State: facts.StateFound, Value: []byte(strconv.FormatBool(v[0]))}
}

// flipped answers the kinds of facts kinds with the other value than the
// assumed one, and the rest as variableFacts: what a false positive form's
// FactKinds say removes it. A kind whose value is not a boolean has no
// other value, and is answered as the rest.
type flipped struct {
	kinds   []facts.Kind
	vars    map[string]string
	allowed string
}

func (f flipped) Resolve(ctx context.Context, q facts.Query) facts.RawAnswer {
	if slices.Contains(f.kinds, q.Kind()) {
		for _, i := range facts.Kinds() {
			if i.Kind == q.Kind() && isBooleanKind(i.Kind) {
				v := "true"
				if string(i.AssumedValue) == "true" {
					v = "false"
				}
				return facts.RawAnswer{State: facts.StateFound, Value: []byte(v)}
			}
		}
	}
	return variableFacts{f.vars, f.allowed}.Resolve(ctx, q)
}

// isBooleanKind is whether the value of the facts of k is a boolean.
func isBooleanKind(k facts.Kind) bool {
	return k != facts.KindRepoActionList && k != facts.KindRepoConfigurationVariables && k != facts.KindRepoEnvironmentConfigurationVariables && k != facts.KindRepoAllowedActions
}

// variableFacts answers repo.configuration-variables and
// repo.environment-configuration-variables from vars (the names of an
// example of exampleVariables: the key "" for the repository, an
// environment's name for the environment), with no answer for the others,
// and the rest as limitFacts; and repo.allowed-actions from allowed (the
// setting of an example of exampleAllowedActions), with no answer when
// allowed is empty.
type variableFacts struct {
	vars    map[string]string
	allowed string
}

func (v variableFacts) Resolve(ctx context.Context, q facts.Query) facts.RawAnswer {
	key, ok := "", false
	switch q := q.(type) {
	case facts.RepoAllowedActions:
		if v.allowed == "" {
			return facts.RawAnswer{State: facts.StateUnknown}
		}
		return facts.RawAnswer{State: facts.StateFound, Value: []byte(v.allowed)}
	case facts.RepoConfigurationVariables:
		ok = true
	case facts.RepoEnvironmentConfigurationVariables:
		key, ok = q.Environment.String(), true
	}
	if !ok {
		return limitFacts{}.Resolve(ctx, q)
	}
	if list, ok := v.vars[key]; ok {
		return facts.RawAnswer{State: facts.StateFound, Value: []byte(list)}
	}
	return facts.RawAnswer{State: facts.StateUnknown}
}

// inputOf is the example e as the input of a run.
func inputOf(t *testing.T, e lint.Example) lint.Inputs {
	t.Helper()
	if len(e.Others) == 0 {
		in, err := lint.Single(lint.InputBytes{Name: e.Name, InputKind: e.InputKind, Bytes: []byte(e.Text)})
		if err != nil {
			t.Fatal(err)
		}
		return in
	}
	// several files are the whole repository
	fsys := fstest.MapFS{e.Name.String(): {Data: []byte(e.Text)}}
	for _, o := range e.Others {
		fsys[o.Name.String()] = &fstest.MapFile{Data: []byte(o.Text)}
	}
	in, err := lint.Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// runWith runs rule alone on in, with the facts r answers.
func runWith(t *testing.T, rule lint.Rule, in lint.Inputs, r facts.Resolver) lint.Report {
	t.Helper()
	reg, err := lint.NewRegistry([]lint.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	return lint.Run(context.Background(), in, reg, r)
}

// runAlone runs rule alone on in, with limitFacts.
func runAlone(t *testing.T, rule lint.Rule, in lint.Inputs) lint.Report {
	t.Helper()
	return runWith(t, rule, in, limitFacts{})
}

// kindsOf are the kinds of rep's findings.
func kindsOf(rep lint.Report) []lint.FindingKindID {
	var out []lint.FindingKindID
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		out = append(out, f.Args.KindID())
	}
	return out
}

// TestExamples holds each rule's examples to its declarations, run with
// the facts each has (lint.Registry.CheckExamples).
func TestExamples(t *testing.T) {
	for _, m := range allMetas() {
		if missing := missingExamples(m); len(missing) != 0 {
			t.Errorf("%s: no file in examples/ for %v", m.ID, missing)
		}
	}
	if t.Failed() {
		t.FailNow() // CheckExamples panics on a declaration without an example
	}
	checks := sharedChecks(t).Of()
	if len(checks) == 0 {
		t.Fatal("no example checked")
	}
	for _, c := range checks {
		if !c.Holds {
			t.Errorf("the %s %s of %s (%s): %s", c.What, c.Declaration, c.Rule, c.Example.Name, c.Why)
		}
	}
}

// swapped is a rule whose Meta is m. The rule it embeds is not a
// lint.ExampledRule (an exampled's Rule), so that the registry shows the
// examples of m, not those of the rule's ExampledMeta.
type swapped struct {
	lint.Rule
	m lint.Meta
}

func (s swapped) Meta() lint.Meta { return s.m }

// TestCheckExamplesFails: a true negative on which the rule reports does
// not hold, and says why.
func TestCheckExamplesFails(t *testing.T) {
	rule := ruleOf(t, CommitSHAID)
	m := exampledMeta(rule)
	m.FindingKinds = slices.Clone(m.FindingKinds)
	k := &m.FindingKinds[0]
	k.TrueNegatives = []lint.Example{k.TruePositives[0]}
	all := All()
	for i, r := range all {
		if r.Meta().ID == CommitSHAID {
			all[i] = swapped{rule.(*exampled).Rule, m} // the others stay: an undetected form names another rule
		}
	}
	reg, err := lint.NewRegistry(all)
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	for _, c := range reg.CheckExamples(context.Background()) {
		if !c.Holds {
			bad = append(bad, c.What.String()+" "+c.Declaration.String()+": "+c.Why)
		}
	}
	if len(bad) != 1 || !strings.HasPrefix(bad[0], "true-negative "+k.ID.String()+": findings") {
		t.Errorf("want the true negative alone not to hold, with its findings: %q", bad)
	}
}

// TestRunExample: RunExample runs every rule of the registry on an
// example, and what the rule of the declaration gives there is what it
// gives alone (the example catalog shows both).
func TestRunExample(t *testing.T) {
	reg, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ofRule := func(rep lint.Report, id lint.RuleID) []string {
		var out []string
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			if f.Rule == id {
				out = append(out, fmt.Sprint("finding ", f.Fingerprint, " ", f.Certainty))
			}
		}
		for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
			if g.Rule == id {
				out = append(out, fmt.Sprint("inconclusive ", g.InconclusiveKind, g.Location.File.Input, g.Location.Span, g.Note))
			}
		}
		slices.Sort(out)
		return out
	}
	seen := false
	for _, c := range sharedChecks(t).Of() {
		for _, run := range c.Runs {
			all, err := reg.RunExampleAs(ctx, c.Example, run)
			if err != nil {
				t.Fatalf("%s %s of %s: %v", c.What, c.Declaration, c.Rule, err)
			}
			if len(all.Report.Errors) != 0 {
				t.Errorf("the %s %s of %s (%v): errors with every rule %+v", c.What, c.Declaration, c.Rule, run.Flipped, all.Report.Errors)
			}
			if got, want := ofRule(all.Report, c.Rule), ofRule(run.Report, c.Rule); !slices.Equal(got, want) {
				t.Errorf("the %s %s of %s (%v): alone %v, with every rule %v", c.What, c.Declaration, c.Rule, run.Flipped, want, got)
			}
			if c.Rule == EnvvarInjectionID && c.What == lint.ExampleUndetected && c.Declaration.String() == "no-line-break" {
				seen = true
				if !slices.Contains(kindsOf(all.Report), kindCodeInjectionControlled) {
					t.Errorf("no-line-break of envvar-injection: with every rule %v, without %s", kindsOf(all.Report), kindCodeInjectionControlled)
				}
			}
		}
	}
	if !seen {
		t.Error("no run of the undetected form no-line-break of envvar-injection")
	}
}

// TestExampleFiles: every file of examples/<what>/<rule>/ is the example
// of a declaration of the rule, and every <rule> is a rule; a labeled
// example of a form or a kind of place (<id>.<label>) follows the main one
// (<id>).
func TestExampleFiles(t *testing.T) {
	declared := map[string][]string{} // <what>/<rule> to the IDs of its declarations
	for _, m := range allMetas() {
		id := m.ID.String()
		for _, k := range m.FindingKinds {
			kind := strings.TrimPrefix(k.ID.String(), id+".")
			declared["true-positive/"+id] = append(declared["true-positive/"+id], kind)
			declared["true-negative/"+id] = append(declared["true-negative/"+id], kind)
		}
		for _, l := range m.UndetectedForms {
			declared["undetected/"+id] = append(declared["undetected/"+id], l.ID.String())
		}
		for _, k := range m.InconclusiveKinds {
			declared["inconclusive/"+id] = append(declared["inconclusive/"+id], k.ID.String())
		}
		for _, f := range m.FalsePositiveForms {
			declared["false-positive/"+id] = append(declared["false-positive/"+id], f.ID.String())
		}
	}
	seen := map[string]bool{}       // <what>/<rule>/<id> of a main example (no label)
	needMain := map[string]string{} // <what>/<rule>/<id> of a declaration's labeled example to its path
	err := fs.WalkDir(examples, "examples", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(p, ".facts.json") {
			return nil // the answers of an example; TestExampleFacts holds them to it
		}
		// examples/<what>/<rule>/<id>: a file, or a directory of several
		several := d.IsDir() && strings.Count(p, "/") == 3
		if d.IsDir() && !several {
			return nil
		}
		dir := strings.TrimPrefix(path.Dir(p), "examples/")
		name := path.Base(p)
		id, ok := name, several
		if !several {
			id, ok = strings.CutSuffix(name, ".action.yml")
			if !ok {
				id, ok = strings.CutSuffix(name, ".yml")
			}
		}
		if !ok {
			t.Errorf("%s is not a .yml file", p)
			return nil
		}

		id, label, labeled := strings.Cut(id, ".") // <kind>.<label>, <form>.<label>
		if labeled && !ident.IsKebab(label) {
			t.Errorf("%s: the label %q is not kebab-case", p, label)
		}
		switch {
		case strings.HasPrefix(dir, "true-"):
		case labeled:
			needMain[dir+"/"+id] = p
		case seen[dir+"/"+id]:
			t.Errorf("%s: a second file of %s in %s, which no test would run", p, id, dir)
		}
		if !labeled {
			seen[dir+"/"+id] = true
		}
		ids := []string{id}
		if strings.HasPrefix(dir, "true-") {
			ids = exampleKinds(id) // <kind>+<kind> for a true negative of several
			if len(ids) > 1 && !strings.HasPrefix(dir, "true-negative/") {
				t.Errorf("%s: only a true negative is of several kinds", p)
			}
		}
		for _, id := range ids {
			if !slices.Contains(declared[dir], id) {
				t.Errorf("%s is the example of no declaration (%s of %s)", p, id, dir)
			}
		}
		if several {
			return fs.SkipDir
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for id, p := range needMain {
		if !seen[id] {
			t.Errorf("%s: no main example of %s (the file without a label), which the labeled ones follow", p, id)
		}
	}
	err = fs.WalkDir(examples, "examples", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".facts.json") {
			return err
		}
		dir := path.Dir(p)
		if strings.Count(dir, "/") != 2 {
			t.Errorf("%s is inside an example of several files, which would read it as a file of the repository", p)
			return nil
		}
		parts := strings.Split(dir, "/") // examples/<what>/<rule>
		for _, n := range exampleFiles(parts[1], parts[2]) {
			if path.Join(dir, factsName(n.id)) == p {
				return nil
			}
		}
		t.Errorf("%s is the facts of no example (the name is <id>.facts.json)", p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestExampledRules: every rule is a lint.ExampledRule whose Meta has no
// example. Giving the examples copies the slices of the declarations
// first, which the Metas of rules share (envpathLimits, valueGaps,
// fileGaps): after every rule's ExampledMeta is asked for, the Metas have
// none.
func TestExampledRules(t *testing.T) {
	for _, r := range All() {
		exampledMeta(r)
	}
	for _, r := range All() {
		m := r.Meta()
		if missing := missingExamples(m); len(missing) != declarations(m) {
			t.Errorf("%s: the Meta has examples: only %v lack one", m.ID, missing)
		}
		if m := r.(*exampled).Rule.Meta(); len(missingExamples(m)) != declarations(m) {
			t.Errorf("%s: the Meta of the rule it embeds has examples", m.ID)
		}
	}
}

// TestExampleFilesKept: what a caller does to the examples exampleFiles
// gives does not change what it gives next: it reads each directory once.
func TestExampleFilesKept(t *testing.T) {
	for _, r := range All() {
		id := r.Meta().ID.String()
		first := exampleFiles("true-positive", id)
		if len(first) < 2 {
			continue
		}
		want := first[0].id
		slices.Reverse(first)
		if got := exampleFiles("true-positive", id)[0].id; got != want {
			t.Errorf("the first example of %s is %s after a caller reversed them, not %s", id, got, want)
		}
		return
	}
	t.Fatal("no rule has two true positives")
}

// exampledMeta is r's Meta with its examples.
func exampledMeta(r lint.Rule) lint.Meta { return r.(lint.ExampledRule).ExampledMeta() }

// missingExamples are the declarations of m without an example.
func missingExamples(m lint.Meta) []string {
	var out []string
	for _, k := range m.FindingKinds {
		if len(k.TruePositives) == 0 {
			out = append(out, "the true positive of "+k.ID.String())
		}
		if len(k.TrueNegatives) == 0 {
			out = append(out, "the true negative of "+k.ID.String())
		}
	}
	for _, l := range m.UndetectedForms {
		if len(l.Examples) == 0 {
			out = append(out, "the undetected form "+l.ID.String())
		}
	}
	for _, k := range m.InconclusiveKinds {
		if len(k.Examples) == 0 {
			out = append(out, "the inconclusive kind "+k.ID.String())
		}
	}
	for _, f := range m.FalsePositiveForms {
		if len(f.Examples) == 0 {
			out = append(out, "the false positive form "+f.ID.String())
		}
	}
	return out
}

// declarations is how many examples m declares at the least: two for each
// kind of finding, one for each form and kind of place.
func declarations(m lint.Meta) int {
	return 2*len(m.FindingKinds) + len(m.UndetectedForms) + len(m.InconclusiveKinds) + len(m.FalsePositiveForms)
}

// ruleOf is the rule id of All.
func ruleOf(t *testing.T, id lint.RuleID) lint.Rule {
	t.Helper()
	for _, r := range All() {
		if r.Meta().ID == id {
			return r
		}
	}
	t.Fatalf("%s is not a rule", id)
	return nil
}

// TestExampleFacts: each example's facts file is what the generator
// (limitFacts, and flipped for the kinds of facts of its declaration)
// answers to what every rule asks of it. go test -update writes them. The
// rules run in parallel, a subtest each.
func TestExampleFacts(t *testing.T) {
	for _, m := range allMetas() {
		id := m.ID.String()
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			kinds := map[string][]facts.Kind{} // <what>/<id> to the kinds to flip
			for _, k := range m.FindingKinds {
				kinds["true-positive/"+strings.TrimPrefix(k.ID.String(), id+".")] = k.FactKinds
			}
			for _, f := range m.FalsePositiveForms {
				kinds["false-positive/"+f.ID.String()] = append(slices.Clone(f.FactKinds), m.FalsePositiveFlip(f)...)
			}
			for _, what := range []string{"true-positive", "true-negative", "false-positive", "undetected", "inconclusive"} {
				for _, n := range exampleFiles(what, id) {
					decl, _, _ := strings.Cut(n.id, ".") // <kind>.<label>
					list, ok := exampleActionLists[what+"/"+id+"/"+n.id]
					if !ok {
						list = exampleActionList
					}
					allowed := exampleAllowedActions[what+"/"+id+"/"+n.id]
					if what == "false-positive" && n.id == actionsNotAllowed.String() {
						allowed = actionsNotAllowedSetting
					}
					want := generatedFacts(t, n.e, kinds[what+"/"+decl], list, exampleVariables[what+"/"+id+"/"+n.id], allowed)
					p := path.Join("examples", what, id, factsName(n.id))
					if *update {
						if err := os.WriteFile(p, want, 0o644); err != nil {
							t.Fatal(err)
						}
						continue
					}
					got, err := os.ReadFile(p)
					if err != nil {
						t.Errorf("%s: %v (go test ./actions/rules/ -run TestExampleFacts -update writes it)", p, err)
						continue
					}
					if !bytes.Equal(got, want) {
						t.Errorf("%s is not what the generator answers (go test ./actions/rules/ -run TestExampleFacts -update):\n%s", p, want)
					}
				}
			}
		})
	}
}

// generatedFacts are the facts every rule asks of e and limitFacts's
// answers, also those they ask when the kinds flip are answered the other
// way: the example catalog runs every rule on e (lint.Registry.RunExample),
// and the check runs the rule of the declaration and the rule its
// disposition names. An unknown answer says so without the generator's
// words.
func generatedFacts(t *testing.T, e lint.Example, flip []facts.Kind, actionList string, vars map[string]string, allowed string) []byte {
	t.Helper()
	in := inputOf(t, e)
	asked := map[string]facts.Entry{}
	add := func(rep lint.Report) {
		for _, x := range rep.Facts {
			k, err := facts.EncodeQuery(x.Query)
			if err != nil {
				t.Fatal(err)
			}
			if q, ok := x.Query.(facts.ActionDefinition); ok && slices.Contains(unaskedDefinitions, q.Repo.String()) {
				continue // no one asked it (actionDefinitionAnswer)
			}
			if q, ok := x.Query.(facts.WorkflowDefinition); ok {
				if _, answered := workflowDefinitionAnswer(q); !answered {
					continue // no one asked it (workflowDefinitionAnswer)
				}
			}
			a := variableFacts{vars, allowed}.Resolve(context.Background(), x.Query)
			switch x.Query.(type) {
			case facts.RepoConfigurationVariables, facts.RepoEnvironmentConfigurationVariables:
				if a.State == facts.StateUnknown {
					continue // the example has no names (exampleVariables)
				}
			case facts.RepoAllowedActions:
				if a.State == facts.StateUnknown {
					continue // the example has no setting (exampleAllowedActions)
				}
			}
			if _, ok := x.Query.(facts.RepoActionList); ok {
				if actionList == "" {
					continue // the run has no list (exampleActionLists)
				}
				a = facts.RawAnswer{State: facts.StateFound, Value: []byte(actionList)}
			}
			if a.State == facts.StateUnknown {
				a.Reason = "the example does not answer it"
			}
			asked[string(k)] = facts.Entry{Query: x.Query, RawAnswer: a}
		}
	}
	for _, rule := range All() {
		add(runWith(t, rule, in, variableFacts{vars, allowed}))
		if len(flip) != 0 {
			add(runWith(t, rule, in, flipped{flip, vars, allowed}))
		}
	}
	for _, q := range Quality() {
		add(runQualityWith(t, q, in, variableFacts{vars, allowed}))
		if len(flip) != 0 {
			add(runQualityWith(t, q, in, flipped{flip, vars, allowed}))
		}
	}
	var es []facts.Entry
	for _, k := range slices.Sorted(maps.Keys(asked)) {
		es = append(es, asked[k])
	}
	b, err := facts.EncodeFile(es)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestExampleLocations: Examples lists every example where it is, with the
// text of its declaration, in the order a reviewer reads them.
func TestExampleLocations(t *testing.T) {
	all := Examples()
	if len(all) == 0 {
		t.Fatal("no example")
	}
	t.Logf("%d examples", len(all))
	order := []lint.ExampleWhat{lint.ExampleFalsePositive, lint.ExampleUndetected, lint.ExampleInconclusive, lint.ExampleTruePositive, lint.ExampleTrueNegative}
	for i, x := range all {
		b, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(x.Path)))
		if err != nil || string(b) != x.Example.Text {
			t.Errorf("%s is not the main file of %s %s/%s: %v", x.Path, x.What, x.Rule, x.ID, err)
		}
		if x.Declaration == "" {
			t.Errorf("%s: no declaration text", x.Path)
		}
		if i > 0 {
			a := all[i-1]
			if a.Rule.String() > x.Rule.String() || a.Rule == x.Rule && (slices.Index(order, a.What) > slices.Index(order, x.What) || a.What == x.What && a.ID >= x.ID) {
				t.Errorf("%s before %s", a.Path, x.Path)
			}
		}
	}
}

// TestDeclarationExamples: the main example of a declaration first, then
// the labeled ones in the order of their names; none without the main one,
// and not the examples of another declaration whose ID starts the same.
func TestDeclarationExamples(t *testing.T) {
	x := func(id string) namedExample {
		return namedExample{id: id, e: lint.Example{Name: facts.MustCleanInputPath(id + ".yml")}}
	}
	names := func(es []lint.Example) []string {
		var out []string
		for _, e := range es {
			out = append(out, e.Name.String())
		}
		return out
	}
	xs := []namedExample{x("form.ghsl-2026-229"), x("form-other"), x("form"), x("form.b"), x("form-other.a")}
	if got := names(declarationExamplesOf(xs, "form")); !slices.Equal(got, []string{"form.yml", "form.b.yml", "form.ghsl-2026-229.yml"}) {
		t.Errorf("form: %v", got)
	}
	if got := declarationExamplesOf([]namedExample{x("form.b")}, "form"); got != nil {
		t.Errorf("no main example: %v", names(got))
	}
}
