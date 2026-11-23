package boundary

import "github.com/sisaku-security/sisakulint/actions/lint"

// The observations of 2026-10-30, in a public repository with a harmless
// secret, of what the runs of acts by accounts of no role in the
// repository, of the role read and of the role triage held, against the
// same acts by the owner of the repository. Each run asked for contents:
// write, printed the length of the secret and tried to create a ref with
// its token.
var (
	observedAccounts = lint.MustDate("2026-10-30")
	runner2338       = lint.MustVersion("2.338.0")

	sawWikiNone        = lint.Observation{Date: observedAccounts, Runner: runner2338, What: "in a public repository whose settings let anyone with an account edit the wiki, an account with no role in the repository created a wiki page on the web interface of GitHub and edited the page; the creation and the edit each started a run of gollum, and each run had the repository's secret, and a step of each run created a ref with the token of the run, which the workflow asked for with contents: write"}
	sawWikiOffNone     = lint.Observation{Date: observedAccounts, Runner: runner2338, What: "in a public repository whose wiki was turned off, an account with no role in the repository could not open the page /wiki/_new, which creates a wiki page (the web interface of GitHub redirected to the repository), and GitHub refused a push by git to the wiki (403); no run of gollum started"}
	sawWikiRestricted  = lint.Observation{Date: observedAccounts, Runner: runner2338, What: "in a public repository whose wiki had the setting Restrict editing to collaborators only turned on (as the owner of the repository reported), an account with the role read could not create a wiki page on the web interface of GitHub (You do not have permission to update this wiki.), and, as the owner of the repository reported, an account with the role triage could not either; no run of gollum started"}
	sawReviewNone      = lint.Observation{Date: observedAccounts, Runner: runner2338, What: "in a public repository, an account with no role in the repository submitted a review in the COMMENT state, and a separate comment on a line of the diff, on a pull request from a branch of the repository; the runs of pull_request_review and pull_request_review_comment started without approval, and each run had the repository's secret, and a step of each run created a ref with the token of the run, which the workflow asked for with contents: write"}
	sawPRTargetNone    = lint.Observation{Date: observedAccounts, Runner: runner2338, What: "in a public repository, the run of pull_request_target of a pull request from a fork by an account with no role in the repository started without approval, had the repository's secret, and a step of the run created a ref with the token of the run, which the workflow asked for with contents: write; so did the runs of pull_request_target after an account with the role read, and the same account later with the role triage, pushed a commit to the branch of the same pull request, and the run of pull_request_target with the activity type labeled that started when the account with the role triage added a label"}
	sawWorkflowRunNone = lint.Observation{Date: observedAccounts, Runner: runner2338, What: "in a public repository, the run of pull_request of a pull request from a fork by an account with no role in the repository waited for approval, and, after the owner approved the run, had no secret; the run of workflow_run that followed had the repository's secret, and a step of the run of workflow_run created a ref with the token of the run, which the workflow asked for with contents: write"}
	sawCommentNone     = lint.Observation{Date: observedAccounts, Runner: runner2338, What: "in a public repository, comments by an account with no role in the repository, on an issue, on a pull request from a branch of the repository and on a pull request from a fork, each started a run of issue_comment; each run had the repository's secret, and a step of each run created a ref with the token of the run, which the workflow asked for with contents: write; so did the runs of issue_comment of comments by an account with the role read, and the same account later with the role triage"}
	sawIssuesReaders   = lint.Observation{Date: observedAccounts, Runner: runner2338, What: "in a public repository, issues opened by an account with the role read, and the same account later with the role triage, each started a run of issues; each run had the repository's secret, and a step of each run created a ref with the token of the run, which the workflow asked for with contents: write"}
	sawForkPRPublic    = lint.Observation{Date: observedAccounts, Runner: runner2338, What: "in a public repository, the run of pull_request of a pull request from a fork by an account with no role in the repository waited for approval, and, after the owner approved the run, had no secret and a read token (creating a ref: 403); the runs of pull_request after an account with the role read, and the same account later with the role triage, pushed a commit to the branch of the same pull request did not wait (the repository asked for approval of the runs of first-time contributors only), and had no secret and a read token"}
	sawForkReviewPub   = lint.Observation{Date: observedAccounts, Runner: runner2338, What: "in a public repository, the run of pull_request_review of a review by the owner on a pull request from a fork waited for approval, and, after the owner approved the run, had no secret and a read token (creating a ref: 403)"}
	sawNoneActs        = lint.Observation{Date: observedAccounts, Runner: runner2338, What: "in a public repository, an account with no role in the repository opened an issue, commented on the issue and on pull requests, submitted a review, forked the repository and opened a pull request from the fork"}
	sawArtifactLogNone = lint.Observation{Date: observedAccounts, Runner: runner2338, What: "in a public repository, an account with no role in the repository, signed in, viewed the log of a run and downloaded an artifact of the run; without signing in, the API refused the log (403) and the artifact (401)"}
	sawArtifactLogRole = lint.Observation{Date: observedAccounts, Runner: runner2338, What: "in a public repository, an account with the role read, and the same account later with the role triage, viewed the log of a run and downloaded an artifact of the run"}
)

// sawReaderActs is what an account of the role r (read or triage) was seen
// to do and not to do in the public repository.
func sawReaderActs(r Role) lint.Observation {
	what := "in a public repository, an account with the role " + r.String() + " was refused a push to a branch (403) and the dispatch of a workflow (403), opened an issue, commented, submitted a review, and pushed a commit to the branch of a pull request from a fork, whose run of pull_request had no secret and a read token"
	if r == RoleTriage {
		what += "; the account added a label to a pull request from a fork, which started a run of pull_request_target with the activity type labeled, with the account as the actor"
	}
	return lint.Observation{Date: observedAccounts, Runner: runner2338, What: what}
}

// unknownWikiOff is the uncertainty of the rows of wiki-editor of the
// roles read and triage in a public repository.
const unknownWikiOff = "with the setting Restrict editing to collaborators only turned on, an account with the role read could not edit the wiki (seen), and the owner of the repository reported that an account with the role triage could not either; with the wiki turned off, the owner of the repository could still push to the wiki by git (seen), and whether an account with the role read or triage can is not seen. repo.wiki-open is false in both cases and cannot tell the two cases apart. So that the linter does not miss a wiki that the account can edit, the row assumes the worst case: the account can edit the wiki"
