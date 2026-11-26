package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/githubtest"
	"github.com/gh-intel/sisakulint/actions/internal/jsonschema"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/prcode"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

var update = flag.Bool("update", false, "write testdata/e2e.golden.json, testdata/registry.golden.json, testdata/explain.golden.md, testdata/attack-runs.golden and testdata/advisory-examples.golden")

const (
	shaCheckout = "11bd71901bbe5b1630ceea73d27597364c9af683"
	shaMain     = "019216bb322ee2a2b2259739ceacae26020c46bb"
	shaInner    = "ee770a9615648ecfcf3ca4bf8b549375d3be713e"
	shaFork     = "b3154b9543ce6392fe65a19ce523c4d4adabca7b" // only in a fork of actions/checkout
	shaUnseen   = "9076cea773bf444a82df8da514ed69aad39f7b10" // of a repository the fake does not show
)

var e2eFiles = fstest.MapFS{
	// known-vulnerable-actions: an action at a commit of each severity GitHub
	// gives advisories (fakeGitHub answers with the advisories of 2026-10-15,
	// their ranges cut to below the version that fixes them; the last is
	// made up)
	".github/workflows/vulnerable.yml": {Data: []byte(`on: push
permissions: {}
jobs:
  vulnerable:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@eaceaf801fd36c7dee90939fad912460b18a1ffe # v4.1.2
      - uses: tj-actions/branch-names@ab304d8562e2f137165e1d930e6d22d431189074 # v7.0.6
      - uses: lycheeverse/lychee-action@2bb232618be239862e31382c5c0eaeba12e5e966 # v2.0.1
      - uses: Azure/setup-kubectl@6025c840858f1afa584a5190a4426c338f59e503 # v2.1
      - uses: example-org/example-action@1111111111111111111111111111111111111111 # v1.0.0
`)},
	".github/workflows/cache.yml": {Data: []byte(`on: pull_request_target
cache-mode: write
jobs:
  bench:
    runs-on: ubuntu-latest
    environment: bench
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: actions/cache@v4
        with:
          path: dist
          key: dist-${{ github.head_ref }}
      - uses: actions/cache/save@v4
        with:
          path: ${{ github.event.pull_request.title }}
          key: saved-${{ github.run_id }}
`)},
	".github/workflows/quality.yml": {Data: []byte(`on: [push, pull_request]
permissions: {contents: read}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: npm-${{ hashFiles('package-lock.json') }}
          restore-keys: npm-
      - uses: actions/dependency-review-action@v4
        with:
          warn-only: true
          vulnerability-check: false
          license-check: false
          deny-licenses: GPL-3.0
          comment-summary-in-pr: always
  conditional:
    runs-on: ubuntu-latest
    if: ${{ github.event_name == 'push' }} && ${{ github.ref == 'refs/heads/main' }}
    env:
      DATABASE=URL: postgres://db
      GITHUB_SHA: fixed
    steps:
      - run: echo
      - run: |
          echo "::set-output name=version::1.0.0"
          echo "::add-path::/opt/tool/bin"
  node:
    runs-on: ubuntu-latest
    env:
      ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION: 'true'
    steps:
      - uses: actions/setup-node@v5
        with:
          node-version: 20
  paths:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node/./@v5
      - uses: actions/setup-node/../v4@v5
      - uses: ./../repo/.github/actions/old-node
`)},
	".github/actions/old-node/action.yml": {Data: []byte(`name: old-node
description: an action that declares node20
runs:
  using: node20
  main: index.js
`)},
	// expression: a ${{ }} of each kind, which fails or writes Object or
	// Array when the workflow runs
	".github/workflows/expression.yml": {Data: []byte(`on: push
permissions: {contents: read}
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: ${{ vars.TIMEOUT }}
    steps:
      - run: make test
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    env: ${{ vars.BUILD_ENV }}
    steps:
      - run: echo "outcomes=${{ steps.*.outcome }}"
      - run: echo "${{ fromJSON(steps) }}"
      - id: flaky
        run: echo "allow=true" >> "$GITHUB_OUTPUT"
      - run: make flaky-test
        continue-on-error: ${{ steps.flaky.outputs.allow }}
  deploy:
    uses: ./.github/workflows/expression-called.yml
`)},
	// unset-configuration-variable and expression: a name that no level
	// defines (given answers repo.configuration-variables), and one that no
	// level can define
	".github/workflows/variables.yml": {Data: []byte(`on: push
permissions: {contents: read}
jobs:
  deploy:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: ./deploy.sh "${{ vars.DEPLOY_ULR }}"
      - run: ./test.sh ${{ join(fromJSON(vars.TEST_SHARDS), ' ') }}
      - run: echo "${{ vars.GITHUB_X }}"
`)},
	".github/workflows/expression-called.yml": {Data: []byte(`on:
  workflow_call:
    inputs:
      dry-run:
        type: boolean
        default: ${{ vars.DRY_RUN }}
permissions: {contents: read}
jobs:
  deploy:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - run: ./deploy.sh
`)},
	".github/workflows/exposed.yml": {Data: []byte(`on: issues
jobs:
  deploy:
    runs-on: [self-hosted, linux]
    environment: production
    steps:
      - run: ./deploy
        env:
          K: ${{ secrets.DEPLOY_KEY }}
`)},
	".github/workflows/least-privilege.yml": {Data: []byte(`on: push
jobs:
  release:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: make release
  remote:
    permissions: {}
    uses: octo/shared/.github/workflows/deploy.yml@` + shaInner + `
    secrets: inherit
  local:
    permissions: {}
    uses: ./.github/workflows/called.yml
    secrets: inherit
`)},
	".github/workflows/called.yml": {Data: []byte(`on: workflow_call
permissions: {}
jobs:
  called:
    runs-on: ubuntu-latest
    steps:
      - run: echo called
        env:
          ALL: ${{ toJSON(secrets) }}
`)},
	".github/workflows/bot.yml": {Data: []byte(`on: pull_request_target
permissions: {}
jobs:
  dependabot:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - if: contains('alice bob', github.event.pull_request.user.login)
        run: echo approved
      - if: contains(github.event.pull_request.user.login, 'alice')
        run: echo approved
`)},
	".github/workflows/download.yml": {Data: []byte(`on:
  workflow_run:
    workflows: [ci]
    types: [completed]
jobs:
  run:
    runs-on: ubuntu-latest
    environment: prod
    steps:
      - uses: actions/download-artifact@0123456789abcdef0123456789abcdef01234567
        with:
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ github.token }}
          path: ${{ runner.temp }}/artifacts
      - run: npm ci
  fix:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ github.token }}
      - run: npm ci
  approved:
    runs-on: ubuntu-latest
    environment: prod
    steps:
      - uses: actions/download-artifact@v4
        with:
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ github.token }}
      - run: echo done
  data:
    runs-on: ubuntu-latest
    environment: prod
    steps:
      - uses: actions/download-artifact@0123456789abcdef0123456789abcdef01234567
        with:
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ github.token }}
          path: ${{ runner.temp }}/data
      - run: echo done
`)},
	".github/workflows/images.yml": {Data: []byte(`on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/o/build:1
      credentials:
        username: u
        password: hunter2
    services:
      redis: redis
      db:
        image: ghcr.io/o/db@sha256:0000000000000000000000000000000000000000000000000000000000000000
        credentials:
          username: u
          password: ${{ vars.REGISTRY_PASSWORD }}
    steps:
      - uses: docker://alpine:3
`)},
	".github/workflows/ci.yml": {Data: []byte(`on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@` + shaCheckout + ` # v4.2.2
      - uses: actions/checkout@` + shaFork + `
      - uses: private/action@` + shaUnseen + `
      - uses: gone/repo/sub@v1
      - uses: down/repo@v1
      - uses: ./.github/actions/build
      - uses: docker://alpine:3
  call:
    uses: owner/repo/.github/workflows/release.yml@main
`)},
	".github/workflows/agent.yml": {Data: []byte(`on:
  issues:
    types: [opened]
  issue_comment:
    types: [created]
jobs:
  claude:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        env:
          CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: "0"
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: "*"
          allowed_bots: "*"
          claude_args: --dangerously-skip-permissions
  codex:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@v1
        with:
          safety-strategy: unsafe
  gemini:
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/run-gemini-cli@v0
        env:
          ISSUE_TITLE: ${{ github.event.issue.title }}
        with:
          prompt: "Label: ${{ github.event.issue.body }}"
  bot:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        env:
          COMMENT: ${{ github.event.comment.body }}
        with:
          allowed_bots: "*"
          prompt: "Answer: ${{ github.event.comment.body }}"
  tools:
    if: github.event_name == 'issues'
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_bots: "*"
          prompt: "Triage #${{ github.event.issue.number }}"
          claude_args: --allowedTools "Bash,WebFetch,Bash(gh issue edit:*)" --append-system-prompt "${{ github.event.issue.title }}"
  later:
    if: github.event_name == 'issues'
    runs-on: [self-hosted, linux]
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_bots: "*"
          prompt: "Fix #${{ github.event.issue.number }}"
          claude_args: --allowedTools Bash
      - run: npm publish
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
  edit:
    if: github.event_name == 'issues'
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_bots: "*"
          prompt: "Fix #${{ github.event.issue.number }}"
          claude_args: --permission-mode acceptEdits
      - run: npm test
  auto:
    if: github.event_name == 'issues'
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_bots: "*"
          prompt: "Triage #${{ github.event.issue.number }}"
          claude_args: --permission-mode auto --allowedTools Read
`)},
	".github/workflows/triage.yml": {Data: []byte(`on: issues
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - id: label
        run: echo "title=${{ github.event.issue.title }}"
      - run: echo '${{ github.event.issue.body }}' "${{ steps.label.outputs.name }}"
`)},
	".github/workflows/argument.yml": {Data: []byte(`on: [gollum, pull_request_target]
permissions: {}
jobs:
  unpack:
    runs-on: ubuntu-latest
    steps:
      - env:
          PAGE: ${{ github.event.pages[0].title }}
          NAME: ${{ github.event.pages[0].page_name }}
          HEAD_REF: ${{ github.head_ref }}
        run: |
          tar -xf archive.tar notes.txt "$HEAD_REF"
          tar -xf archive.tar notes.txt "$PAGE"
          tar -xf archive.tar notes.txt "$NAME"
`)},
	// request-forgery: each kind on issue_comment, and on gollum alone,
	// which holds on repo.wiki-open; secret-exfiltration: a fixed host
	".github/workflows/request.yml": {Data: []byte(`on: [gollum, issue_comment]
permissions: {}
jobs:
  status:
    runs-on: ubuntu-latest
    env:
      DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
    steps:
      - env:
          BODY: ${{ github.event.comment.body }}
          PAGE: ${{ github.event.pages[0].title }}
        run: |
          curl -fsS -H "Authorization: Bearer $DEPLOY_TOKEN" "https://$BODY/status"
          curl -fsS -H "Authorization: Bearer $DEPLOY_TOKEN" "https://$PAGE/status"
          curl -fsS -H "Authorization: Bearer $DEPLOY_TOKEN" https://deploy.example.com/status
      - uses: octokit/request-action@dad4362715b7fb2ddedf9772c8670824af564f0d
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          route: ${{ github.event.comment.body }}
          url: ${{ github.event.pages[0].title }}
  probe:
    runs-on: [self-hosted, linux]
    steps:
      - shell: bash
        env:
          BODY: ${{ github.event.comment.body }}
          PAGE: ${{ github.event.pages[0].title }}
        run: |
          curl -fsS "http://$BODY/healthz"
          curl -fsS "http://$PAGE/healthz"
`)},
	".github/workflows/wiki.yml": {Data: []byte(`on: [gollum, issues]
jobs:
  w:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pages[0].title }}" "${{ github.event.issue.title }}"
      - shell: pwsh
        run: echo "${{ github.event.pages[0].title }}"
`)},
	// code-injection.env-variable (issues) and code-injection.env-variable-wiki
	// (gollum alone, with the condition of the wiki): eval reads the values
	// of the variables of env as code
	".github/workflows/env-variable.yml": {Data: []byte(`on: [gollum, issues]
permissions: {}
jobs:
  e:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.issue.title }}
          PAGE: ${{ github.event.pages[0].title }}
        run: eval "echo $TITLE $PAGE"
`)},
	".github/workflows/outputs.yml": {Data: []byte(`on: [issues, gollum]
jobs:
  o:
    runs-on: ubuntu-latest
    steps:
      - env:
          BODY: ${{ github.event.issue.body }}
        run: |
          echo "body=$BODY" >> "$GITHUB_OUTPUT"
          echo "title=${{ github.event.issue.title }}" >> "$GITHUB_ENV"
          jq -r . <<< "$BODY" >> "$GITHUB_OUTPUT"
          echo "$BODY/bin" >> "$GITHUB_PATH"
      - env:
          PAGE: ${{ github.event.pages[0].title }}
        run: |
          echo "page=$PAGE" >> "$GITHUB_OUTPUT"
          echo "page=$PAGE" >> "$GITHUB_ENV"
          echo "$PAGE" >> "$GITHUB_PATH"
`)},
	// a workflow on status alone: its findings ask repo.fork-pr-app-checks
	// and repo.merge-commit-app-checks
	".github/workflows/app-commit.yml": {Data: []byte(`on: status
permissions: {}
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.commit.commit.message }}"
`)},
	".github/workflows/pwn.yml": {Data: []byte(`on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    environment: preview
    steps:
      - uses: actions/checkout@` + shaCheckout + ` # v4.2.2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci
  diff:
    runs-on: ubuntu-latest
    environment: preview
    steps:
      - uses: actions/checkout@` + shaCheckout + ` # v4.2.2
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          path: pr
      - uses: actions/upload-artifact@v4
        with:
          path: pr/dist
  deploy:
    runs-on: ubuntu-latest
    environment: preview
    steps:
      - uses: actions/checkout@` + shaCheckout + ` # v4.2.2
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          ref: ${{ github.event.pull_request.head.ref }}
      - run: npm ci
`)},
	".github/workflows/labeled.yml": {Data: []byte(`on:
  pull_request_target:
    types: [labeled]
jobs:
  head:
    if: github.event.label.name == 'safe-to-test'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@` + shaCheckout + ` # v4.2.2
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/head
      - run: npm ci
  merge:
    if: github.event.label.name == 'safe-to-test'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@` + shaCheckout + ` # v4.2.2
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
      - run: npm ci
`)},
	// ai-action-unrestricted-trigger.labeler-token-owner: actions/labeler
	// adds agent-review with a personal access token to a pull request that
	// changes a file under site/, which starts the agent of labeled-agent.yml
	".github/labeler.yml": {Data: []byte(`agent-review:
  - changed-files:
      - any-glob-to-any-file: 'site/**'
`)},
	".github/workflows/labeler.yml": {Data: []byte(`on: pull_request_target
permissions: {}
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@8558fd74291d67161a8a78ce36a881fa63b766a9 # v5.0.0
        with:
          repo-token: ${{ secrets.LABELER_PAT }}
`)},
	".github/workflows/labeled-agent.yml": {Data: []byte(`on:
  pull_request_target:
    types: [labeled]
permissions: {}
jobs:
  agent:
    if: github.event.label.name == 'agent-review'
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@6fed3ca145920b639991cb756090506e1bcaf515 # v1.0.245
        with:
          github_token: ${{ github.token }}
          prompt: Review the pull request
`)},
	".github/workflows/artifact.yml": {Data: []byte(`on: push
jobs:
  token:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@` + shaMain + `
      - uses: actions/upload-artifact@v4
        with: {path: ., include-hidden-files: true}
      - run: echo after
  pat:
    runs-on: ubuntu-latest
    permissions: {contents: read}
    steps:
      - uses: actions/checkout@` + shaMain + `
        with: {token: '${{ secrets.PAT }}', path: pat}
      - uses: google-github-actions/auth@v2
        with: {credentials_json: '${{ secrets.GCP }}'}
      - uses: google-github-actions/auth@v2
        with: {workload_identity_provider: p}
      - uses: actions/upload-artifact@v4
        with: {path: ., include-hidden-files: true}
      - run: echo after
`)},
	".github/workflows/secrets.yml": {Data: []byte(`on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
        env:
          ALL: ${{ toJSON(secrets) }}
          CLIENT_SECRET: ${{ fromJSON(secrets.AZURE_CREDENTIALS).clientSecret }}
      - run: echo "token starts with ${TOKEN:0:4}"
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
`)},
	".github/workflows/unsecure.yml": {Data: []byte(`on: [issues, gollum]
jobs:
  notify:
    runs-on: ubuntu-latest
    env:
      ACTIONS_ALLOW_UNSECURE_COMMANDS: true
    steps:
      - run: echo "$TITLE"
        env:
          TITLE: ${{ github.event.issue.title }}
      - run: echo "${{ github.event.pages[0].title }}"
      - run: echo "$NAME"
        env:
          NAME: ${{ github.event.pages[0].page_name }}
      - run: ./notify.sh
`)},
	".github/actions/build/action.yml": {Data: []byte(`name: build
description: builds
runs:
  using: composite
  steps:
    - uses: inner/action@v2
    - run: make
      shell: bash
    - run: git checkout ${{ github.head_ref }}
      shell: bash
`)},
}

// fakeGitHub knows the tags and branches below, and down/repo is broken.
// Of actions/checkout it shows the refs, and a commit only in a fork; of
// private/action, nothing (a repository the token cannot see).
func fakeGitHub(t *testing.T) facts.Resolver {
	t.Helper()
	refs := map[string]string{
		"/repos/actions/checkout/commits/refs/tags/v4": shaCheckout,
		"/repos/owner/repo/commits/refs/heads/main":    shaMain,
		"/repos/inner/action/commits/refs/tags/v2":     shaInner,
	}
	// v4.2.2 has none of the commits of the guard of actions/checkout
	for _, c := range prcode.GuardCommits() {
		refs["/repos/actions/checkout/compare/"+c.String()+"..."+shaCheckout] = `{"status":"behind"}`
	}
	s := githubtest.New(t, refs, "down/repo")
	s.Network("actions/checkout", githubtest.Repo{
		Refs: map[string]string{"refs/heads/main": shaMain, "refs/tags/v4": shaCheckout, "refs/tags/v4.2.2": shaCheckout},
		Has:  map[string][]string{shaFork: nil},
	})
	for _, v := range vulnerableE2E {
		s.Network(v.repo, githubtest.Repo{Refs: map[string]string{"refs/tags/" + v.tag: v.sha, "refs/tags/" + v.fixed: v.fixedSHA}})
		refs["/repos/"+v.repo+"/commits/refs/tags/"+v.fixed] = v.fixedSHA
		body := `[{"ghsa_id":"` + v.ghsa + `","severity":"` + v.severity + `","withdrawn_at":null,"vulnerabilities":[{"package":{"ecosystem":"actions","name":"` + v.repo + `"},"vulnerable_version_range":"< ` + strings.TrimPrefix(v.fixed, "v") + `","first_patched_version":"` + strings.TrimPrefix(v.fixed, "v") + `"}]}]`
		s.Advisories(v.repo, body)
		s.Advisories(v.repo+"@"+v.tag, body)
	}
	return s.Resolver()
}

// vulnerableE2E are the actions of vulnerable.yml of e2eFiles, and what
// fakeGitHub answers of them: a tag of the commit, an advisory of its
// version, and the tag of the version that fixes it.
var vulnerableE2E = []struct{ repo, sha, tag, ghsa, severity, fixed, fixedSHA string }{
	{"actions/download-artifact", "eaceaf801fd36c7dee90939fad912460b18a1ffe", "v4.1.2", "GHSA-cxww-7g56-2vh6", "high", "v4.1.3", "87c55149d96e628cc2ef7e6fc2aab372015aec85"},
	{"tj-actions/branch-names", "ab304d8562e2f137165e1d930e6d22d431189074", "v7.0.6", "GHSA-8v8w-v8xg-79rf", "critical", "v7.0.7", "6c999acf206f5561e19f46301bb310e9e70d8815"},
	{"lycheeverse/lychee-action", "2bb232618be239862e31382c5c0eaeba12e5e966", "v2.0.1", "GHSA-65rg-554r-9j5x", "medium", "v2.0.2", "7cd0af4c74a61395d455af97419279d86aafaede"},
	{"azure/setup-kubectl", "6025c840858f1afa584a5190a4426c338f59e503", "v2.1", "GHSA-p756-rfxh-x63h", "low", "v3", "901a10e89ea615cf61f57ac05cecdf23e7de06d8"},
	{"example-org/example-action", "1111111111111111111111111111111111111111", "v1.0.0", "GHSA-2222-3333-4444", "unknown", "v1.0.1", "2222222222222222222222222222222222222222"},
}

func schemaSet(t *testing.T) *jsonschema.Set {
	t.Helper()
	files := map[string][]byte{}
	for name, p := range map[string]string{
		facts.SchemaName:   "../facts/schema/facts-v0.json",
		"report-v0.json":   "../lint/schema/report-v0.json",
		"registry-v0.json": "../lint/schema/registry-v0.json",
		"findings-v0.json": "schema/findings-v0.json",
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = b
	}
	s, err := jsonschema.Load(files, jsonschema.Options{SchemaAnnotations: []string{"x-value"}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func indent(t *testing.T, v any) []byte {
	t.Helper()
	b, err := v.(json.Marshaler).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "  "); err != nil {
		t.Fatal(err)
	}
	return append(out.Bytes(), '\n')
}

// TestEndToEnd is the whole path: a repository
// enumerated, commit-sha run with a file of facts laid over the GitHub API,
// the report as JSON, the facts written and replayed without the network,
// and the fixes applied.
func TestEndToEnd(t *testing.T) {
	ctx := context.Background()
	in, err := lint.Enumerate(e2eFiles)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	// the repository's own list of uses (repo.action-list), which the
	// GitHub API does not answer: it lets action-list report one action, one
	// image of a step and the image of a service; the names of the configuration variables, and the setting
	// of allowed actions of GitHub (repo.allowed-actions: it blocks an
	// action of a workflow and one of the composite action, and requires a
	// full commit SHA), which the fake GitHub API does not answer
	given, err := facts.LoadStore([]byte(`{"schema": "sisakulint/facts/v0", "facts": [{"query": {"kind": "repo.action-list"}, "state": "found", "value": ["*", "!lycheeverse/*", "!docker://alpine:*", "!docker://redis"]}, {"query": {"kind": "repo.configuration-variables"}, "state": "found", "value": ["BUILD_ENV", "DEPLOY_URL", "DRY_RUN", "TIMEOUT"]}, {"query": {"kind": "repo.allowed-actions"}, "state": "found", "value": {"allowed_actions": "selected", "github_owned_allowed": true, "verified_allowed": false, "patterns_allowed": ["*", "!lycheeverse/*", "!inner/*"], "sha_pinning_required": true}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	rep := lint.Run(ctx, in, reg, facts.First(given, fakeGitHub(t)))
	got := indent(t, rep)
	if *update {
		if err := os.WriteFile("testdata/e2e.golden.json", got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("testdata/e2e.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the report is not testdata/e2e.golden.json (go test -update writes it):\n%s", got)
	}

	s := schemaSet(t)
	if err := s.Validate("report-v0.json", "#", got); err != nil {
		t.Errorf("the report does not fit report-v0.json: %v", err)
	}
	var args struct {
		Findings []struct {
			Certainty string
			Args      json.RawMessage
		}
	}
	if err := json.Unmarshal(got, &args); err != nil {
		t.Fatal(err)
	}
	inconclusive := 0
	for _, f := range args.Findings {
		// the args of an inconclusive finding are only its kind, which
		// report-v0.json checks: findings-v0.json lists the finding kinds
		if f.Certainty == "inconclusive" {
			inconclusive++
			continue
		}
		if err := s.Validate("findings-v0.json", "#/$defs/args", f.Args); err != nil {
			t.Errorf("the args %s do not fit findings-v0.json: %v", f.Args, err)
		}
	}
	if inconclusive == 0 {
		t.Error("the end-to-end report has no inconclusive finding, whose args report-v0.json checks")
	}
	regJSON := indent(t, reg)
	if err := s.Validate("registry-v0.json", "#", regJSON); err != nil {
		t.Errorf("the registry does not fit registry-v0.json: %v", err)
	}
	for _, b := range [][]byte{got, regJSON} {
		for _, bad := range []string{"docs/research", "docs/superpowers", "docs/backlog"} {
			if bytes.Contains(b, []byte(bad)) {
				t.Errorf("the JSON refers to %s, which is not there when the package is taken out", bad)
			}
		}
	}

	// the facts asked, written as a file of facts, answer the same run without the network
	file, err := facts.EncodeFile(rep.Facts)
	if err != nil {
		t.Fatal(err)
	}
	store, err := facts.LoadStore(file)
	if err != nil {
		t.Fatal(err)
	}
	// the same answers, from the file now
	source := regexp.MustCompile(`,\s*"source": "[a-z]+"`)
	if again := indent(t, lint.Run(ctx, in, reg, store)); !bytes.Equal(source.ReplaceAll(again, nil), source.ReplaceAll(got, nil)) {
		t.Errorf("the replay differs:\n%s", again)
	}

	applied, err := lint.ApplyFixes(ctx, in, reg, store, rep, lint.SafetySafe)
	if err != nil {
		t.Fatal(err)
	}
	out := applied.Files
	fixed := fstest.MapFS{}
	for n, f := range e2eFiles {
		fixed[n] = f
		if b, ok := out[facts.MustCleanInputPath(n)]; ok {
			fixed[n] = &fstest.MapFile{Data: b}
		}
	}
	in2, _ := lint.Enumerate(fixed)
	for _, f := range lint.Run(ctx, in2, reg, store).Findings {
		m, _ := reg.Meta(f.Rule)
		safe := slices.ContainsFunc(m.FixKinds, func(k lint.FixKind) bool {
			return f.Fix != nil && k.ID == f.Fix.KindID && k.Safety == lint.SafetySafe
		})
		if safe {
			t.Errorf("after the safe fixes, a finding that had a safe fix: %s", f.Detected())
		}
	}
}

// TestRegistryGolden keeps the registry in testdata/registry.golden.json:
// the one place to read every rule's IDs (rule, fix, limit, kind of place
// not examined), and a diff when one changes.
func TestRegistryGolden(t *testing.T) {
	reg, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	got := indent(t, reg)
	if *update {
		if err := os.WriteFile("testdata/registry.golden.json", got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("testdata/registry.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the registry is not testdata/registry.golden.json (go test -update writes it):\n%s", got)
	}
}

// TestRegistryFullGolden keeps the registry with the facts of the examples
// (--registry=full) in testdata/registry-full.golden.json; every example
// has its facts, and the output fits the same schema as the default.
func TestRegistryFullGolden(t *testing.T) {
	reg, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	b, err := reg.MarshalJSONFull()
	if err != nil {
		t.Fatal(err)
	}
	if err := schemaSet(t).Validate("registry-v0.json", "#", b); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "  "); err != nil {
		t.Fatal(err)
	}
	got := append(out.Bytes(), '\n')
	if *update {
		if err := os.WriteFile("testdata/registry-full.golden.json", got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("testdata/registry-full.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the full registry is not testdata/registry-full.golden.json (go test -update writes it)")
	}
	if !bytes.Contains(b, []byte(`"facts":[`)) {
		t.Error("no example has its facts")
	}
}

// TestMetaJSON: MetaJSON is each rule's and quality rule's object of the
// registry's JSON without its examples, and nothing else left out.
func TestMetaJSON(t *testing.T) {
	reg, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	b, err := reg.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules        []map[string]any `json:"rules"`
		QualityRules []map[string]any `json:"quality_rules"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	metas, err := reg.MetaJSON()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(doc.Rules) + len(doc.QualityRules); len(metas) != n || len(doc.QualityRules) == 0 {
		t.Errorf("%d rules in MetaJSON, %d in the registry, %d of them quality rules", len(metas), n, len(doc.QualityRules))
	}
	drop := func(o map[string]any, list string, keys ...string) {
		for _, x := range o[list].([]any) {
			for _, k := range keys {
				delete(x.(map[string]any), k)
			}
		}
	}
	for _, want := range append(doc.Rules, doc.QualityRules...) {
		id := lint.MustRuleID(want["id"].(string))
		raw, ok := metas[id]
		if !ok {
			t.Errorf("no %s in MetaJSON", id)
			continue
		}
		drop(want, "finding_kinds", "true_positives", "true_negatives")
		for _, list := range []string{"undetected_forms", "inconclusive_kinds", "false_positive_forms"} {
			if _, ok := want[list]; ok {
				drop(want, list, "examples")
			}
		}
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: MetaJSON is not the registry's object without its examples:\n%s", id, raw)
		}
		keys := []string{"citations", "threat", "finding_kinds"}
		if reg.IsQuality(id) {
			keys = []string{"citations", "finding_kinds"}
		}
		for _, k := range keys {
			if _, ok := got[k]; !ok {
				t.Errorf("%s: no %s", id, k)
			}
		}
	}
}

// Every kind of findings-v0.json is reported by the end-to-end run, so
// that a kind no rule reports, or one whose form has no test, is seen.
func TestEveryKindReported(t *testing.T) {
	b, err := os.ReadFile("testdata/e2e.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range allFindingKinds {
		if !bytes.Contains(b, []byte(`"kind_id": "`+k.String()+`"`)) {
			t.Errorf("no finding of %s in testdata/e2e.golden.json", k)
		}
	}
}

// TestKindLinksUsed: what each kind declares is used by the end-to-end
// run, so that a declaration is not a claim nothing makes: every fix it
// refers to is given by a finding of it, every kind of fact it declares is
// asked by the condition of one, and the events of its findings are of the
// actors it refers to.
func TestKindLinksUsed(t *testing.T) {
	b, err := os.ReadFile("testdata/e2e.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Findings []struct {
			Args struct {
				Kind string `json:"kind_id"`
				// the events a finding is on, under the name of its kind's set
				ControlledOn []string `json:"controlled_on"`
				PRCodeOn     []string `json:"pr_code_on"`
				PrivilegedOn []string `json:"privileged_on"`
			} `json:"args"`
			Fix *struct {
				Kind string `json:"kind_id"`
			} `json:"fix"`
			Condition any `json:"condition"`
			Location  struct {
				File struct {
					Input string `json:"input"`
				} `json:"file"`
			} `json:"location"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatal(err)
	}
	targetOnly := pullRequestTargetOnlyInputs(t)
	appOnly := appCommitOnlyInputs(t)
	targetAsked, appAsked := 0, map[facts.Kind]int{}
	appChecksKinds := []facts.Kind{facts.KindRepoForkPRAppChecks, facts.KindRepoMergeCommitAppChecks}
	for _, r := range All() {
		m := r.Meta()
		for _, k := range m.FindingKinds {
			fixes, asked, events := map[string]bool{}, map[string]bool{}, map[string]bool{}
			declared := slices.Contains(k.FactKinds, facts.KindRepoPullRequestTargetAllowed)
			for _, f := range rep.Findings {
				if f.Args.Kind != k.ID.String() {
					continue
				}
				if f.Fix != nil {
					fixes[f.Fix.Kind] = true
				}
				own := map[string]bool{}
				factKinds(f.Condition, own)
				// the engine adds repo.pull-request-target-allowed to the
				// condition of a finding of a kind that declares it, in a
				// workflow whose on has pull_request_target alone, and to no
				// other (TestPullRequestTargetCondition of package lint)
				if want := declared && targetOnly[f.Location.File.Input]; own[facts.KindRepoPullRequestTargetAllowed.String()] != want {
					t.Errorf("a finding of %s in %s asks %s: %v, want %v", k.ID, f.Location.File.Input, facts.KindRepoPullRequestTargetAllowed, !want, want)
				} else if want {
					targetAsked++
				}
				// the same of repo.fork-pr-app-checks and
				// repo.merge-commit-app-checks, each in a workflow whose on has
				// only events among status, check_suite and check_run
				// (TestAppChecksCondition of package lint)
				for _, x := range appChecksKinds {
					if want := slices.Contains(k.FactKinds, x) && appOnly[f.Location.File.Input]; own[x.String()] != want {
						t.Errorf("a finding of %s in %s asks %s: %v, want %v", k.ID, f.Location.File.Input, x, !want, want)
					} else if want {
						appAsked[x]++
					}
				}
				for x := range own {
					asked[x] = true
				}
				for _, e := range slices.Concat(f.Args.ControlledOn, f.Args.PRCodeOn, f.Args.PrivilegedOn) {
					events[e] = true
				}
			}
			for _, x := range k.Fixes {
				if !fixes[x.String()] {
					t.Errorf("%s refers to the fix %s, which no finding of it in testdata/e2e.golden.json gives", k.ID, x)
				}
			}
			for _, x := range k.FactKinds {
				// a kind with no finding in a workflow on pull_request_target
				// alone among e2eFiles does not ask
				// repo.pull-request-target-allowed there: the check above
				// holds each finding to it, and the example of the false
				// positive form pull-request-target-blocked of each rule
				// answers it the other way (TestExamples)
				// the same of repo.fork-pr-app-checks,
				// repo.merge-commit-app-checks and a workflow on status,
				// check_suite or check_run alone: the check above holds each
				// finding to it, and the true positive on those events of each
				// rule that declares a fact (<kind>.status-commit.yml) is
				// such a workflow, for one kind of the rule (TestExamples)
				if !asked[x.String()] && x != facts.KindRepoPullRequestTargetAllowed && !slices.Contains(appChecksKinds, x) {
					t.Errorf("%s declares the fact %s, which no condition of its findings in testdata/e2e.golden.json asks", k.ID, x)
				}
			}
			of := map[string]bool{}
			for _, a := range m.Threat.Actors {
				if slices.Contains(k.Attackers, a.Attacker) {
					for _, e := range a.Events {
						of[e.String()] = true
					}
				}
			}
			for e := range events {
				if !of[e] {
					t.Errorf("a finding of %s is on %s, which no actor it refers to takes", k.ID, e)
				}
			}
		}
	}
	if targetAsked == 0 {
		t.Error("no finding in testdata/e2e.golden.json asks repo.pull-request-target-allowed")
	}
	for _, x := range appChecksKinds {
		if appAsked[x] == 0 {
			t.Errorf("no finding in testdata/e2e.golden.json asks %s", x)
		}
	}
}

// appCommitOnlyInputs are the workflows of e2eFiles whose on has only
// events among status, check_suite and check_run.
func appCommitOnlyInputs(t *testing.T) map[string]bool {
	t.Helper()
	in, err := lint.Enumerate(e2eFiles)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, x := range in.List {
		w := x.Workflow
		if w == nil || w.On.Status != workflow.Present {
			continue
		}
		only := false
		for _, ev := range w.On.Value.Events {
			n, err := workflow.ParseEventName(ev.Name.AsString())
			if err != nil {
				continue // a name GitHub does not know is not counted, as the engine
			}
			if !slices.Contains(appCommitEvents, n) {
				only = false
				break
			}
			only = true
		}
		out[x.Name.String()] = only
	}
	return out
}

// pullRequestTargetOnlyInputs are the workflows of e2eFiles whose on has
// pull_request_target and no other event.
func pullRequestTargetOnlyInputs(t *testing.T) map[string]bool {
	t.Helper()
	in, err := lint.Enumerate(e2eFiles)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, x := range in.List {
		w := x.Workflow
		if w == nil || w.On.Status != workflow.Present {
			continue
		}
		only := len(w.On.Value.Events) > 0
		for _, ev := range w.On.Value.Events {
			// a name GitHub does not know is not counted, as the engine
			if n, err := workflow.ParseEventName(ev.Name.AsString()); err == nil && n != workflow.EventNamePullRequestTarget {
				only = false
			}
		}
		out[x.Name.String()] = only
	}
	return out
}

// factKinds adds to out the kind of each fact the condition c (as the JSON
// of a report has it) asks about.
func factKinds(c any, out map[string]bool) {
	switch c := c.(type) {
	case map[string]any:
		if f, ok := c["query"].(map[string]any); ok {
			if k, ok := f["kind"].(string); ok {
				out[k] = true
			}
		}
		for _, v := range c {
			factKinds(v, out)
		}
	case []any:
		for _, v := range c {
			factKinds(v, out)
		}
	}
}
