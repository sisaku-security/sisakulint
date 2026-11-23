package rules

import (
	"slices"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// What the Meta of the rules share.

// metric is the metric of value v, and why it has that value.
func metric[T any](v T, reason string, cites ...lint.Citation) lint.Metric[T] {
	return lint.Metric[T]{Value: v, Reason: reason, Cites: cites}
}

// repos reads each of names as a repository; it panics on one that is not.
func repos(names ...string) []facts.Repo {
	var out []facts.Repo
	for _, n := range names {
		r, err := facts.ParseRepo(n)
		if err != nil {
			panic(err)
		}
		out = append(out, r)
	}
	return out
}

var (
	// the version of the GitHub-hosted runner the observations of the rules
	// ran on
	runner = lint.MustVersion("2.337.0")

	// what code run in a job gets: the job's token, its secrets, what it
	// may write, and the cache it may save to
	jobGains = []lint.Gain{lint.GainRunCode, lint.GainReadSecrets, lint.GainWriteWithToken, lint.GainWriteCache}

	// agentkitIncident is the attack on coinbase/agentkit through
	// tj-actions/changed-files, which permissions and commit-sha cite.
	agentkit2025     = lint.MustIncidentID("agentkit-2025")
	agentkitIncident = lint.Incident{ID: agentkit2025, Date: lint.MustDate("2025-03-14"), CVE: lint.MustCVE("CVE-2025-30066"), Advisory: unit42,
		Compromised: repos("tj-actions/changed-files"),
		Downstream:  repos("coinbase/agentkit"),
		Summary:     "the attacker pointed a tag of tj-actions/changed-files to a malicious commit made in a fork and aimed at coinbase/agentkit; its pull_request workflow, which named tj-actions/changed-files@v39 and wrote no permissions, ran it and leaked a GITHUB_TOKEN that could write (15:10 UTC), before the attacker moved every tag of tj-actions/changed-files (16:57 UTC); Coinbase found no damage"}

	// the incidents of the uses of another repository, which commit-sha,
	// impostor-commit and known-vulnerable-actions cite
	reviewdog2025Incident = lint.Incident{ID: reviewdog2025, Date: lint.MustDate("2025-03-11"), CVE: lint.MustCVE("CVE-2025-30154"), Advisory: reviewdog,
		Compromised: repos("reviewdog/action-setup"),
		Downstream:  repos("reviewdog/action-shellcheck", "reviewdog/action-composite-template", "reviewdog/action-staticcheck", "reviewdog/action-ast-grep", "reviewdog/action-typos"),
		Summary:     "the tag v1 was moved to code that prints secrets to the log; the reviewdog actions that use it @v1 were hit whatever their own pin"}
	tjActions2025Incident = lint.Incident{ID: tjActions2025, Date: lint.MustDate("2025-03-14"), CVE: lint.MustCVE("CVE-2025-30066"), Advisory: tjActions,
		Compromised: repos("tj-actions/changed-files"),
		Summary:     "the tags v1 to v45.0.7 were moved to a commit that prints secrets to the log"}
	trivy2026Incident = lint.Incident{ID: trivy2026, Date: lint.MustDate("2026-03-19"), CVE: lint.MustCVE("CVE-2026-33634"), Advisory: trivy,
		Compromised: repos("aquasecurity/trivy", "aquasecurity/trivy-action", "aquasecurity/setup-trivy"),
		Summary:     "with stolen credentials, a commit swapped the actions/checkout of a workflow for an impostor commit (70379aad) that fetched malicious code, and was tagged v0.69.4 to run the release; 76 of the 77 version tags of aquasecurity/trivy-action and all 7 of aquasecurity/setup-trivy were force-pushed to credential-stealing commits"}

	secureUse = lint.MustCitation("https://docs.github.com/en/actions/reference/security/secure-use#using-third-party-actions")
	cvss      = lint.MustCitation("https://www.first.org/cvss/v4.0/specification-document")
)

// startedBy is who starts the run of each of evs: the attacker, by an act
// of their own, but others (a maintainer or a schedule, which what the
// attacker wrote reaches) for those of others.
func startedBy(evs []workflow.EventName, others ...workflow.EventName) map[workflow.EventName]lint.RunStarter {
	m := map[workflow.EventName]lint.RunStarter{}
	for _, e := range evs {
		m[e] = lint.RunStarterAttacker
		if slices.Contains(others, e) {
			m[e] = lint.RunStarterOther
		}
	}
	return m
}

// splitEnvNameLimit is a key of env with = in it, which the runner makes
// the variable named by the part before the first =, whose value is the
// rest of the key, = and the value: the rules that
// read the variables of env (actions/taint) do not read it. It is
// declared by the rules whose harm the B= at the head of the value leaves.
var splitEnvNameLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("split-env-name"),
	Text:        "a variable named by the part of a key of env before the first =, such as A for the key A=B, which the runner sets to the rest of the key, =, and the value (in a step in a job's container, to the rest of the key alone): the rule reads a variable of env by a key equal to the name of the variable",
	Disposition: lint.Todo(lint.NeedSameFile)}

// secretInputLimit is a secret that a step of an action receives as an
// input: a composite action cannot read the secrets context, so the
// caller gives the secret under with. It is declared by the rules that
// read a secret from the secrets context and github.token only.
var secretInputLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("secret-input"),
	Text:        "a secret that a step of an action reads by inputs.<name>, either because a caller among the files that the linter reads gives the secret under with:, or because the default of inputs.<name> is ${{ github.token }}: the rule does not follow the value under with: into inputs.<name> and does not read the default of inputs.<name>; when no caller of the action is among the files that the linter reads, whether inputs.<name> holds a secret is not known",
	Disposition: lint.Todo(lint.NeedRepoFile)}
