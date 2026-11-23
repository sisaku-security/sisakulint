package boundary

import (
	"errors"
	"fmt"
	"slices"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// BarrierPass is whether an attacker that a run adds (AddedAttacker) gets
// past Barrier, with its grounds. An unverified row lets no attacker past:
// the analysis does not add on a premise no one checked.
type BarrierPass struct {
	AddedAttacker lint.AddedAttacker
	Barrier       analysis.Barrier
	Passes        bool
	Basis         Basis
	Quotes        []Quote
	Observed      []lint.Observation
	Uncertainty   string
}

func (b BarrierPass) check() error {
	switch {
	case b.AddedAttacker == lint.AddedAttackerUnset:
		return errors.New("no added attacker")
	case b.Barrier == analysis.BarrierUnset:
		return fmt.Errorf("%s: no barrier", b.AddedAttacker)
	case b.Basis == BasisUnverified && b.Passes:
		return fmt.Errorf("%s %s: unverified, but it passes", b.AddedAttacker, b.Barrier)
	}
	if err := checkGrounds(b.Basis, b.Quotes, b.Observed, b.Uncertainty); err != nil {
		return fmt.Errorf("%s %s: %w", b.AddedAttacker, b.Barrier, err)
	}
	return nil
}

// retrievedBarriers is when the quotes of the barrier passes were
// retrieved.
var retrievedBarriers = lint.MustDate("2026-11-03")

const (
	schemaDoc      = "src/graphql/data/fpt/schema.docs.graphql"
	claudeAction   = "anthropics/claude-code-action"
	claudeCommit   = "6fed3ca145920b639991cb756090506e1bcaf515"
	patPermissions = "src/github-apps/data/fpt-2026-03-10/fine-grained-pat-permissions.json"
	appPermissions = "src/github-apps/data/fpt-2026-03-10/server-to-server-permissions.json"
	appAuthDocs    = "content/apps/creating-github-apps/authenticating-with-a-github-app/"
	appsList       = "src/github-apps/components/PermissionsList.tsx"
	// permissionsCommit is the commit of github/docs of the quotes of the
	// tables of the permissions of fine-grained tokens and of GitHub Apps,
	// of the component that shows the table of GitHub Apps, and of the
	// documents of the tokens of a GitHub App.
	permissionsCommit = "285a28f284a1ec002904a394349a688a27f40f8f"
)

// retrievedPermissions is when the quotes at permissionsCommit were
// retrieved, each within the JSON value it points to.
var retrievedPermissions = lint.MustDate("2026-11-16")

// doc16 is the text of path of github/docs at permissionsCommit, word for
// word, within the value that pointer points to; the empty pointer is the
// whole file.
func doc16(path, pointer, text string) Quote {
	q := source("github/docs", permissionsCommit, path, text, retrievedPermissions)
	q.JSONPointer = MustJSONPointer(pointer)
	return q
}

// doc03 is the text of path of github/docs at docsCommit, word for word,
// retrieved on retrievedBarriers.
func doc03(path, text string) Quote {
	return source("github/docs", docsCommit, path, text, retrievedBarriers)
}

// The quotes of the barrier passes: the values of author_association, who
// may add a label, who may review a deployment, how the gate of
// claude-code-action checks the actor, what a fine-grained token of one
// permission may write, and which tokens start runs.
var (
	assocOwner        = doc03(schemaDoc, "  \"\"\"\n  Author is the owner of the repository.\n  \"\"\"\n  OWNER")
	assocMember       = doc03(schemaDoc, "  \"\"\"\n  Author is a member of the organization that owns the repository.\n  \"\"\"\n  MEMBER")
	assocCollaborator = doc03(schemaDoc, "  \"\"\"\n  Author has been invited to collaborate on the repository.\n  \"\"\"\n  COLLABORATOR")
	rolesLabels       = doc03(rolesDoc, "  - action: 'Apply/dismiss labels'\n    roles: 'triage, write, maintain, admin'")
	reviewersRead     = source("github/docs", "7fa55a0ac28d01b5cb6f9cbebff06fbee1e2408f", "content/actions/reference/workflows-and-actions/deployments-and-environments.md", "The reviewers must have at least read access to the repository.", retrievedBarriers)
	claudeWriteOnly   = source(claudeAction, claudeCommit, "src/github/validation/permissions.ts", "    if (permissionLevel === \"admin\" || permissionLevel === \"write\") {", retrievedBarriers)
	claudeHumanOnly   = source(claudeAction, claudeCommit, "src/github/validation/actor.ts", "  if (actorType !== \"User\") {\n    // GitHub Apps and other bot accounts.", retrievedBarriers)
	triageIsRead      = source("github/rest-api-description", "6348fd455a44a445f9e37a505e981b2c3ed24046", "descriptions/api.github.com/api.github.com.json", "The `permission` attribute provides the legacy base roles of `admin`, `write`, `read`, and `none`, where the\\n`maintain` role is mapped to `write` and the `triage` role is mapped to `read`.", retrievedBarriers)
	installationRuns  = doc03("content/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow.md", "If you do want to trigger a workflow from within a workflow run, you can use a {% data variables.product.prodname_github_app %} installation access token or a {% data variables.product.pat_generic %} instead of `GITHUB_TOKEN` to trigger events that require a token.")
	variablesWrite    = doc16(patPermissions, "/actions_variables/permissions", "        \"slug\": \"create-a-repository-variable\",\n        \"subcategory\": \"variables\",\n        \"verb\": \"post\",\n        \"requestPath\": \"/repos/{owner}/{repo}/actions/variables\",\n        \"additional-permissions\": false,\n        \"access\": \"write\"")
	patVariables      = doc16(patPermissions, "/actions_variables", "\"title\": \"Variables\"")
	patSecrets        = doc16(patPermissions, "/secrets", "\"title\": \"Secrets\"")
	secretsWrite      = doc16(patPermissions, "/secrets/permissions", "        \"slug\": \"create-or-update-a-repository-secret\",\n        \"subcategory\": \"secrets\",\n        \"verb\": \"put\",\n        \"requestPath\": \"/repos/{owner}/{repo}/actions/secrets/{secret_name}\",\n        \"additional-permissions\": false,\n        \"access\": \"write\"")
)

// The observations the barrier passes hold: of 2026-10-23 (labels and the
// review of a deployment), of 2026-10-30 (the collaborators), of
// 2026-11-03 (the tokens of one permission and a GitHub App) and of
// 2026-11-04 (an issue and a review by the tokens of one permission) and of
// 2026-11-17 (an issue and a review by the token of a GitHub App).
var (
	observedCredentials = lint.MustDate("2026-10-23")
	observedTokens      = lint.MustDate("2026-11-03")
	runner23382         = lint.MustVersion("2.338.2")

	sawLabelPermissions   = lint.Observation{Date: observedCredentials, Runner: runner2338, What: "a GITHUB_TOKEN, an installation access token, whose only write permission was pull-requests: write could change the labels of a pull request and was refused (403, FORBIDDEN) the labels of an issue; with issues: write, the token could change the labels of the issue and was refused those of the pull request"}
	sawLabelRun           = lint.Observation{Date: observedCredentials, Runner: runner2338, What: "a label that a fine-grained personal access token with only the Pull requests permission with write access added to a pull request started a run of pull_request_target with the activity type labeled; the actor of the run was the owner of the token, and the job whose if needed the label ran"}
	sawReviewerOnly       = lint.Observation{Date: observedCredentials, Runner: runner2338, What: "a GITHUB_TOKEN with deployments: write could not approve a deployment that waited for the review of an environment whose required reviewer was the owner of the repository; the required reviewer approved the deployment on the web interface of GitHub, and the job of the environment ran"}
	sawCollaborators      = lint.Observation{Date: observedAccounts, Runner: runner2338, What: "in a public repository, the author_association of an account with the role read, and of the same account later with the role triage, as a collaborator of the repository was COLLABORATOR"}
	sawVariablesToken     = lint.Observation{Date: observedTokens, Runner: runner23382, What: "in a private repository, a fine-grained personal access token with only the Variables permission with write access created a variable of the repository, and the token was refused (403) a new branch, a change of a file and the list of the secrets; a job of push whose run had the variable in ${{ }} ran the value of the variable, $(echo PWNED), as a command"}
	sawSecretsToken       = lint.Observation{Date: observedTokens, Runner: runner23382, What: "in a private repository, a fine-grained personal access token with only the Secrets permission with write access created a secret of the repository, and the token was refused (403) a new branch and the list of the variables; a job of push whose run had the secret in ${{ }} ran the value of the secret, $(echo PWNED), as a command"}
	sawIssuesToken        = lint.Observation{Date: observedTokens, Runner: runner23382, What: "in a private repository, a fine-grained personal access token with only the Issues permission with write access, of the owner of the repository (the role admin), commented on an issue and was refused (403) a comment on a pull request; the run of issue_comment had the owner of the token as its actor and as the author of the comment, the author_association of the comment was OWNER, and the endpoint of the permission of a collaborator, which the gate of claude-code-action asks, answered admin for the actor"}
	sawPullRequestsToken  = lint.Observation{Date: observedTokens, Runner: runner23382, What: "in a private repository, a fine-grained personal access token with only the Pull requests permission with write access, of the owner of the repository (the role admin), commented on a pull request and was refused (403) a comment on an issue; the run of issue_comment had the owner of the token as its actor and as the author of the comment, the author_association of the comment was OWNER, and the endpoint of the permission of a collaborator answered admin for the actor"}
	sawIssueOpenAndReview = lint.Observation{Date: lint.MustDate("2026-11-04"), Runner: runner23382, What: "in a private repository, a fine-grained personal access token with only the Pull requests permission with write access was refused (403) a new issue, which a token with only the Issues permission with write access opened; the token with only the Issues permission was refused (403) a review of a pull request and a comment of a review, which the token with only the Pull requests permission wrote"}
	sawAppIssueAndReview  = lint.Observation{Date: lint.MustDate("2026-11-17"), What: "in a private repository, an installation access token of a GitHub App with only the Issues and the Pull requests permissions with write access opened an issue and wrote a review (COMMENT) of a pull request; the author of the issue and of the review was the name of the App followed by [bot], and the author_association of both was NONE"}
	sawAppToken           = lint.Observation{Date: observedTokens, Runner: runner23382, What: "in a private repository, an installation access token of a GitHub App with the Issues and the Pull requests permissions with write access added a label that the repository had to a pull request, which started a run of pull_request_target with the activity type labeled whose actor was the name of the App followed by [bot]; the token commented on an issue and on a pull request, and the runs of issue_comment had the same actor, the author_association of the comments was NONE, and the endpoint of the permission of a collaborator answered none for the actor; the token was refused (403) a new branch"}
)

// passes is a row of v and b that lets the attacker past, on quotes and
// observations.
func passes(v lint.AddedAttacker, b analysis.Barrier, qs []Quote, os ...lint.Observation) BarrierPass {
	return grounded(BarrierPass{AddedAttacker: v, Barrier: b, Passes: true}, qs, os)
}

// stops is a row of v and b that does not let the attacker past, on
// quotes and observations.
func stops(v lint.AddedAttacker, b analysis.Barrier, qs []Quote, os ...lint.Observation) BarrierPass {
	return grounded(BarrierPass{AddedAttacker: v, Barrier: b}, qs, os)
}

func grounded(r BarrierPass, qs []Quote, os []lint.Observation) BarrierPass {
	r.Quotes, r.Observed, r.Basis = qs, os, BasisDocumented
	if len(os) != 0 {
		r.Basis = BasisObserved
	}
	return r
}

// unknownBarrier is the uncertainty of a row that no document and no
// observation decides: the definition of the added attacker does not give
// the credential the means, so the row does not let the attacker past.
const unknownBarrier = "no document and no observation says that the credential of the added attacker gets past the barrier, and the definition of the added attacker does not give the credential the means"

func barrierList() []BarrierPass {
	owner, member, collaborator := analysis.BarrierAssociationOwner, analysis.BarrierAssociationMember, analysis.BarrierAssociationCollaborator
	actor, label, env, gate := analysis.BarrierActorName, analysis.BarrierLabelApproval, analysis.BarrierEnvironmentApproval, analysis.BarrierAgentGate
	q := func(qs ...Quote) []Quote { return qs }
	readMember, triage := lint.AddedAttackerReadMember, lint.AddedAttackerTriageAccount
	prToken, issuesToken := lint.AddedAttackerWriterPullRequestsToken, lint.AddedAttackerWriterIssuesToken
	reviewer, app := lint.AddedAttackerRequiredReviewer, lint.AddedAttackerAppInstallationToken
	rows := []BarrierPass{
		passes(readMember, member, q(assocMember)),
		passes(readMember, collaborator, q(assocCollaborator), sawCollaborators),
		stops(readMember, owner, q(assocOwner)),
		stops(readMember, label, q(rolesLabels)),
		stops(readMember, gate, q(claudeWriteOnly)),

		passes(triage, member, q(assocMember)),
		passes(triage, collaborator, q(assocCollaborator), sawCollaborators),
		stops(triage, owner, q(assocOwner)),
		passes(triage, label, q(rolesLabels), sawReaderActs(RoleTriage)),
		stops(triage, gate, q(claudeWriteOnly, triageIsRead)),

		passes(prToken, owner, q(assocOwner), sawPullRequestsToken),
		passes(prToken, member, q(assocMember), sawPullRequestsToken),
		passes(prToken, collaborator, q(assocCollaborator), sawPullRequestsToken),
		passes(prToken, actor, nil, sawLabelRun, sawPullRequestsToken),
		passes(prToken, label, nil, sawLabelPermissions, sawLabelRun),
		passes(prToken, gate, q(claudeWriteOnly), sawPullRequestsToken),
		stops(prToken, env, nil, sawReviewerOnly),

		passes(issuesToken, owner, q(assocOwner), sawIssuesToken),
		passes(issuesToken, member, q(assocMember), sawIssuesToken),
		passes(issuesToken, collaborator, q(assocCollaborator), sawIssuesToken),
		passes(issuesToken, actor, nil, sawIssuesToken),
		stops(issuesToken, label, nil, sawLabelPermissions),
		passes(issuesToken, gate, q(claudeWriteOnly), sawIssuesToken),
		stops(issuesToken, env, nil, sawReviewerOnly),

		passes(reviewer, env, q(reviewersRead), sawReviewerOnly),
		passes(reviewer, member, q(assocMember)),
		passes(reviewer, collaborator, q(assocCollaborator), sawCollaborators),
		stops(reviewer, owner, q(assocOwner)),
		stops(reviewer, gate, q(claudeWriteOnly, triageIsRead)),

		passes(app, actor, nil, sawAppToken),
		passes(app, label, q(installationRuns), sawLabelPermissions, sawAppToken),
		stops(app, gate, q(claudeHumanOnly), sawAppToken),
		stops(app, owner, nil, sawAppToken),
		stops(app, member, nil, sawAppToken),
		stops(app, collaborator, nil, sawAppToken),

		passes(lint.AddedAttackerVariablesWriter, analysis.BarrierVariableValue, q(variablesWrite, patVariables), sawVariablesToken),
		passes(lint.AddedAttackerSecretsWriter, analysis.BarrierSecretValue, q(secretsWrite, patSecrets), sawSecretsToken),
	}
	// the rows no document and no observation decides
	for _, v := range lint.AddedAttackers() {
		for _, b := range analysis.Barriers() {
			if !slices.ContainsFunc(rows, func(r BarrierPass) bool { return r.AddedAttacker == v && r.Barrier == b }) {
				rows = append(rows, BarrierPass{AddedAttacker: v, Barrier: b, Basis: BasisUnverified, Uncertainty: unknownBarrier})
			}
		}
	}
	return rows
}

// barrierRows are which barriers each added attacker gets past.
var barrierRows = barrierList()

// WriteRow is whether an attacker that a run adds (AddedAttacker) writes
// Object with their credential, with its grounds: a run of an object they
// do not write is not theirs. An account writes every object; a token
// writes those of its permissions.
type WriteRow struct {
	AddedAttacker lint.AddedAttacker
	Object        analysis.WrittenObject
	Writes        bool
	Basis         Basis
	Quotes        []Quote
	Observed      []lint.Observation
	Uncertainty   string
}

func (w WriteRow) check() error {
	switch {
	case w.AddedAttacker == lint.AddedAttackerUnset:
		return errors.New("no added attacker")
	case w.Object == analysis.WrittenUnset:
		return fmt.Errorf("%s: no object", w.AddedAttacker)
	case w.Basis == BasisUnverified && w.Writes:
		return fmt.Errorf("%s %s: unverified, but it writes", w.AddedAttacker, w.Object)
	}
	if err := checkGrounds(w.Basis, w.Quotes, w.Observed, w.Uncertainty); err != nil {
		return fmt.Errorf("%s %s: %w", w.AddedAttacker, w.Object, err)
	}
	return nil
}

// The quotes of what a token of one permission writes: the endpoints of
// the tables of the permissions of fine-grained tokens and of GitHub Apps,
// each within the permission that allows it, with access write and no
// additional permission; the names of those permissions; and what the
// documents of GitHub call the requests of the tokens of a GitHub App, and
// that the table of GitHub Apps links an entry of server-to-server to the
// document of the installation access token.
var (
	issuesCreate        = doc16(patPermissions, "/issues/permissions", "        \"category\": \"issues\",\n        \"slug\": \"create-an-issue\",\n        \"subcategory\": \"issues\",\n        \"verb\": \"post\",\n        \"requestPath\": \"/repos/{owner}/{repo}/issues\",\n        \"additional-permissions\": false,\n        \"access\": \"write\"")
	reviewCreate        = doc16(patPermissions, "/pull_requests/permissions", "        \"slug\": \"create-a-review-for-a-pull-request\",\n        \"subcategory\": \"reviews\",\n        \"verb\": \"post\",\n        \"requestPath\": \"/repos/{owner}/{repo}/pulls/{pull_number}/reviews\",\n        \"additional-permissions\": false,\n        \"access\": \"write\"")
	reviewCommentCreate = doc16(patPermissions, "/pull_requests/permissions", "        \"slug\": \"create-a-review-comment-for-a-pull-request\",\n        \"subcategory\": \"comments\",\n        \"verb\": \"post\",\n        \"requestPath\": \"/repos/{owner}/{repo}/pulls/{pull_number}/comments\",\n        \"additional-permissions\": false,\n        \"access\": \"write\"")
	patIssues           = doc16(patPermissions, "/issues", "\"title\": \"Issues\"")
	patPullRequests     = doc16(patPermissions, "/pull_requests", "\"title\": \"Pull requests\"")

	appIssuesCreate        = doc16(appPermissions, "/issues/permissions", "        \"slug\": \"create-an-issue\",\n        \"subcategory\": \"issues\",\n        \"verb\": \"post\",\n        \"requestPath\": \"/repos/{owner}/{repo}/issues\",\n        \"access\": \"write\",\n        \"user-to-server\": true,\n        \"server-to-server\": true,\n        \"additional-permissions\": false")
	appReviewCreate        = doc16(appPermissions, "/pull_requests/permissions", "        \"slug\": \"create-a-review-for-a-pull-request\",\n        \"subcategory\": \"reviews\",\n        \"verb\": \"post\",\n        \"requestPath\": \"/repos/{owner}/{repo}/pulls/{pull_number}/reviews\",\n        \"access\": \"write\",\n        \"user-to-server\": true,\n        \"server-to-server\": true,\n        \"additional-permissions\": false")
	appReviewCommentCreate = doc16(appPermissions, "/pull_requests/permissions", "        \"slug\": \"create-a-review-comment-for-a-pull-request\",\n        \"subcategory\": \"comments\",\n        \"verb\": \"post\",\n        \"requestPath\": \"/repos/{owner}/{repo}/pulls/{pull_number}/comments\",\n        \"access\": \"write\",\n        \"user-to-server\": true,\n        \"server-to-server\": true,\n        \"additional-permissions\": false")
	appIssues              = doc16(appPermissions, "/issues", "\"title\": \"Issues\"")
	appPullRequests        = doc16(appPermissions, "/pull_requests", "\"title\": \"Pull requests\"")

	installationRequests = doc16(appAuthDocs+"authenticating-as-a-github-app-installation.md", "", "Requests made with an installation access token are sometimes called \"server-to-server\" requests.")
	appTokenLabel        = doc16(appsList, "", "              const iat = operation['server-to-server'] ? (\n                <span className=\"label mt-2\">\n                  <Link href={`${rootPath}${IAT_DOCS_REF}`}>{IAT}</Link>")
	appTokenDocs         = doc16(appsList, "", "const IAT_DOCS_REF =\n  '/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation'")
	userRequests         = doc16(appAuthDocs+"authenticating-with-a-github-app-on-behalf-of-a-user.md", "", "Requests made with a user access token are sometimes called \"user-to-server\" requests.")
)

// unknownPullRequest is why no token of a credential that cannot push
// opens a pull request: a pull request needs a head branch they push.
const unknownPullRequest = "a pull request needs a head branch with the change, which the credential cannot push (it has no Contents permission with write access, and it is limited to the repository, not to a fork of the account); whether the token opens a pull request from a branch that another pushed is not seen, and the row does not let the attacker open one"

// unknownNoComment is why a credential of vars or secrets writes no
// issue, pull request, comment, review or discussion.
const unknownNoComment = "the credential has no permission of issues, pull requests or discussions; whether a credential of the Variables or the Secrets permission alone writes them is not seen, and the row does not let the attacker write them"

// unknownDiscussion is why a token of issues or pull requests writes no
// discussion.
const unknownDiscussion = "the token has no Discussions permission; whether it writes a discussion is not seen, and the row does not let the attacker write one"

func writeList() []WriteRow {
	issue, issueComment, pull := analysis.WrittenIssue, analysis.WrittenIssueComment, analysis.WrittenPullRequest
	pullComment, review, discussion := analysis.WrittenPullRequestComment, analysis.WrittenPullRequestReview, analysis.WrittenDiscussion
	doc := func(v lint.AddedAttacker, o analysis.WrittenObject, writes bool, qs []Quote, os ...lint.Observation) WriteRow {
		r := WriteRow{AddedAttacker: v, Object: o, Writes: writes, Basis: BasisDocumented, Quotes: qs, Observed: os}
		if len(os) != 0 {
			r.Basis = BasisObserved
		}
		return r
	}
	not := func(v lint.AddedAttacker, o analysis.WrittenObject, why string) WriteRow {
		return WriteRow{AddedAttacker: v, Object: o, Basis: BasisUnverified, Uncertainty: why}
	}
	q := func(qs ...Quote) []Quote { return qs }
	var rows []WriteRow
	// the accounts: of the roles read and triage, which may do all of these
	for _, x := range []struct {
		v    lint.AddedAttacker
		role Role
	}{{lint.AddedAttackerReadMember, RoleRead}, {lint.AddedAttackerTriageAccount, RoleTriage}, {lint.AddedAttackerRequiredReviewer, RoleRead}} {
		seen := sawReaderActs(x.role)
		rows = append(rows,
			doc(x.v, issue, true, q(rolesOpenIssue), seen),
			doc(x.v, issueComment, true, q(rolesOpenIssue), seen),
			doc(x.v, pull, true, q(rolesForkPR, readerPR), seen),
			doc(x.v, pullComment, true, q(rolesReview), seen),
			doc(x.v, review, true, q(rolesReview), seen),
			doc(x.v, discussion, true, q(rolesDiscuss)))
	}
	issues, pulls, app := lint.AddedAttackerWriterIssuesToken, lint.AddedAttackerWriterPullRequestsToken, lint.AddedAttackerAppInstallationToken
	// a token of one permission is a fine-grained token or a user access
	// token of a GitHub App; an App's own token is an installation access
	// token
	tokenIssue := q(issuesCreate, patIssues, appIssuesCreate, appIssues, userRequests)
	tokenReview := q(reviewCreate, reviewCommentCreate, patPullRequests, appReviewCreate, appReviewCommentCreate, appPullRequests, userRequests)
	appIssue := q(appIssuesCreate, appIssues, appTokenLabel, appTokenDocs, installationRequests)
	appReview := q(appReviewCreate, appReviewCommentCreate, appPullRequests, appTokenLabel, appTokenDocs, installationRequests)
	rows = append(rows,
		doc(issues, issue, true, tokenIssue, sawIssueOpenAndReview),
		doc(issues, issueComment, true, nil, sawIssuesToken),
		not(issues, pull, unknownPullRequest),
		doc(issues, pullComment, false, nil, sawIssuesToken),
		doc(issues, review, false, tokenReview, sawIssueOpenAndReview),
		not(issues, discussion, unknownDiscussion),

		doc(pulls, issue, false, tokenIssue, sawIssueOpenAndReview),
		doc(pulls, issueComment, false, nil, sawPullRequestsToken),
		not(pulls, pull, unknownPullRequest),
		doc(pulls, pullComment, true, nil, sawPullRequestsToken),
		doc(pulls, review, true, tokenReview, sawIssueOpenAndReview),
		not(pulls, discussion, unknownDiscussion),

		doc(app, issue, true, appIssue, sawAppIssueAndReview),
		doc(app, issueComment, true, nil, sawAppToken),
		not(app, pull, unknownPullRequest),
		doc(app, pullComment, true, nil, sawAppToken),
		doc(app, review, true, appReview, sawAppIssueAndReview),
		not(app, discussion, unknownDiscussion),
	)
	for _, v := range []lint.AddedAttacker{lint.AddedAttackerVariablesWriter, lint.AddedAttackerSecretsWriter} {
		for _, o := range analysis.WrittenObjects() {
			rows = append(rows, not(v, o, unknownNoComment))
		}
	}
	return rows
}

// writeRows are which objects each added attacker writes.
var writeRows = writeList()

// BarrierPassesOf are the barriers that an attacker of any of vs gets
// past, and the objects they write: what a run that adds vs lets its
// attacker past. A run that adds none passes none and writes every object.
func BarrierPassesOf(vs []lint.AddedAttacker) analysis.BarrierPasses {
	var out analysis.BarrierPasses
	for i, v := range vs {
		var p analysis.BarrierPasses
		for _, b := range rows().barriers {
			if b.AddedAttacker == v && b.Passes {
				p = p.With(b.Barrier)
			}
		}
		var writes []analysis.WrittenObject
		limited := false
		for _, w := range rows().writes {
			if w.AddedAttacker != v {
				continue
			}
			if w.Writes {
				writes = append(writes, w.Object)
			} else {
				limited = true
			}
		}
		if limited {
			p = p.Limited(writes...)
		}
		if i == 0 {
			out = p
		} else {
			out = out.Union(p)
		}
	}
	return out
}
