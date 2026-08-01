+++
title = "Immutable pull-request snapshot scanning"
date = 2026-08-01
draft = false
+++

# Immutable pull-request snapshot scanning

Date: 2026-08-01

## Problem

The original sisakulint-agent integration sends changed workflow contents to
sisakulint-api. That request has no general repository model. Rules which need
`.github/dependabot.yaml`, Renovate configuration, root lockfiles, local actions,
or local reusable workflows either skip checks or make decisions from incomplete
context. Adding one special agent-side fetch per rule does not scale and can scan
a different revision from the workflow itself.

## Decision

Repository acquisition belongs to sisakulint's remote implementation. The API
is a transport/execution boundary, and the agent remains GitHub orchestration.

The agent sends this descriptor to the existing `/lint` or `/fix` endpoint:

```json
{
  "repository": {
    "owner": "sisaku-security",
    "repo": "sisakulint-agent",
    "pullNumber": 18,
    "expectedHeadSha": "0123456789abcdef0123456789abcdef01234567",
    "targets": [".github/workflows/deploy.yml"]
  }
}
```

The short-lived GitHub App installation token is carried in the HTTP
`Authorization: Bearer` header. sisakulint-api injects it only into the child
process environment and never places it in command arguments or responses.
Legacy `files` requests remain supported.

## Scan semantics

- Snapshot revision: the PR's current `head.sha`, verified against
  `expectedHeadSha` from the webhook before archive download. The PR's head and
  base SHA are read again after the mutable files endpoint is paginated; a
  change to either side aborts before archive resolution.
- Analysis scope: every workflow in the complete head snapshot. This enables
  project rules and cross-file analysis.
- Report scope: changed, non-removed workflow paths listed in `targets`.
- Fix scope: the same explicit targets. sisakulint never writes to GitHub; the
  agent previews and commits returned target changes. Project-file fixers such
  as Dependabot configuration creation are disabled in this mode because the
  workflow-only response cannot persist those mutations.
- Context-only changes: do not currently produce a report when no workflow was
  changed. Base/head finding comparison is a follow-up below.

## Snapshot safety constraints

- Capture the mutable PR revision, then download the archive by its full head
  SHA only after the changed-file listing is revalidated.
- Revalidate both PR head and base after listing changed files so the target
  list and immutable archive cannot describe different PR revisions.
- Cap compressed data at 100 MiB, extracted data at 400 MiB, individual files
  at 50 MiB, and archive entries at 100,000.
- Refuse PRs beyond GitHub's 3,000-file listing cap instead of treating a
  truncated target list as complete.
- Require one archive top-level directory and reject absolute paths, `..`
  components, duplicates, links, devices, and FIFOs.
- Ignore only POSIX PAX metadata records; never execute hooks, repository code,
  or submodules.
- Use a separate unauthenticated client for the pre-signed archive URL so a
  GitHub token cannot cross the API redirect boundary.
- Create an empty `.git` marker only after extraction for sisakulint project
  discovery.

## Result and writeback concurrency

- Repository-mode lint treats the sisakulint exit status and SARIF document as
  one contract. A finding exit without results, a clean exit with results,
  missing locations, and results for paths outside `targets` all fail closed.
- Each scan invocation uses a head-specific comment instead of reusing one
  mutable comment across revisions. Before publishing, the agent verifies that
  the PR still points to the scanned head SHA; stale comments are minimized and
  cannot overwrite a newer invocation's result or failure message.
- Before autofix and between each write, the agent checks the expected branch
  head. Contents API updates use the blob SHA read from the scanned revision,
  never a freshly fetched mutable blob SHA, so a concurrent edit to the same
  workflow produces a conflict instead of being overwritten.

## Rollout order

The three changes are intentionally deployable only in this order:

1. Merge sisakulint and release `v0.3.6`.
2. Merge sisakulint-api, whose container pins `v0.3.6`, and verify `/health` plus
   one repository-mode `/lint` call.
3. Rebase/replace sisakulint-agent PR #18 with the repository-descriptor client,
   then deploy it.

The agent requires `resolvedHeadSha` and one result per target, so deploying it
against the legacy API fails visibly instead of silently reporting a clean scan.

## Acceptance evidence

- Unit tests cover PR URL parsing, head-SHA mismatch, revision changes during
  file pagination, archive traversal/link rejection, PAX headers, full-context
  extraction, report filtering, API input validation, token forwarding,
  fail-closed SARIF validation, stale writeback, original-blob compare-and-swap,
  SARIF snippets, and legacy-response rejection.
- A live private-repository scan of sisakulint-agent PR #18 materialized the
  exact expected head SHA successfully.
- A live cross-repository (fork) PR also materialized its head SHA through the
  base repository archive endpoint.
- A live scan of a workflow-changing PR reported only its changed workflow and
  detected the `gomod` ecosystem from the snapshot's root `go.sum`, proving that
  repository context was used without transporting that file through the API.

## Follow-ups

1. Scan both base and head and compare stable finding fingerprints so
   context-only changes can report newly introduced findings without flooding a
   PR with pre-existing issues.
2. Add service-to-service authentication for sisakulint-api independently of
   the forwarded GitHub installation credential.
3. Replace per-file Contents API autofix commits with one Git tree/commit for
   atomic multi-file updates.
4. Decide whether safely materialized in-repository symlinks are worth
   supporting; the MVP fails closed on all link entries.
5. Add archive and lint duration/size metrics before raising any snapshot limit.
