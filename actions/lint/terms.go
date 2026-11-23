package lint

import (
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/job"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// itemName is a name --explain writes before a colon and what the name
// names (most start an item, some are within the text of an item; see
// itemNamesDoc), and what the name means, which Terms writes. Explain
// writes its item names from these only, so that each is in the terms.
type itemName struct{ name, doc string }

// is is the text "name: s".
func (n itemName) is(s string) string { return n.name + ": " + s }

func (n itemName) String() string { return n.name }

// MarshalText is the name, as the paths of an example catalog have it.
func (n itemName) MarshalText() ([]byte, error) { return []byte(n.name), nil }

// itemNamesDoc is what the item names are, which Terms writes before them:
// where --explain writes them, and the other words before a colon that are
// not item names.
const itemNamesDoc = "The item names are the names listed below. Most item names start an item of a list in --explain, followed by a colon and then what the item name names (such as problem: ...). An ID may come between the item name and the colon (such as precondition attacker-writes: ...). Some item names are within the text of an item, in parentheses or after a comma, followed by what they name, with a colon or without one (such as decided by: run-time, from VC, VI and runner 2.337.0). Some item names are also the heading of a group of values under values (such as severity and disposition). Other words before a colon are not item names: an ID (of a finding kind, a fix kind, a form, an inconclusive kind, a precondition or an incident), the name of a CVSS metric (such as AV), the name of an axis of the facets (such as weakness), and a value (such as always in default run: always: ...). When the value of an item name is empty, --explain leaves out the whole item, the item name together with the value: for example, a rule or a kind without fixes has no item fix kinds."

// textTerm is a word in the texts of the rules, what it means, and the
// items that its meaning has under it (the symbols and the formulas of the
// credential premise).
type textTerm struct {
	name, doc string
	items     []string
}

var (
	nCommit              = itemName{"commit", "the commit of git the binary was built from, marked (modified) when the working tree had changes; unknown when it is not known"}
	nTerms               = itemName{"terms", "the command that writes these terms"}
	nProblem             = itemName{"problem", "what the rule detects, and why it is a problem"}
	nExpected            = itemName{"expected", "the state that the rule asks for (the ideal). The rule reports a finding where a workflow departs from the state, and reports nothing where the workflow keeps the state, with three exceptions: where a workflow has an undetected form, the rule reports nothing, even where the workflow departs from the state; on the places of an inconclusive kind, the rule cannot decide whether the workflow departs from the state, or whether the consequence of a finding kind of the rule can occur at the place, and the rule reports a finding whose certainty is inconclusive (an inconclusive finding); where a workflow has a false positive form, the rule reports a finding though the consequence of the finding kind does not occur in the workflow, even where the workflow keeps the state. The declaration of each form and of each inconclusive kind gives the reason: the disposition, or, for a false positive form, the disposition or the fact kinds. Whether a finding is a false positive is decided by the consequence of the finding kind, not by the state: a finding where the workflow departs from the state is a false positive too when the consequence of the finding kind does not occur in the workflow"}
	nSeverity            = itemName{"severity", "how bad a threat is on any repository, not the risk to one organization: the severity of a kind is found from the CVSS metrics of the kind by a table, and the severity of a rule is the worst severity among the kinds of the rule (values: severity)"}
	nTargets             = itemName{"targets", "what the rule reads its inputs as. The rule reads an action.yml (an input of action-metadata) by itself, as the steps of a job that calls the action. When the inputs are the whole repository and hold every caller of the action, the rule reads the action on the events of the callers. Otherwise, such as when the inputs are some files of the repository or a caller is in another repository, the rule reads the action on every event that the rule checks for an attacker, the worst case (values: input-kind)"}
	nFacets              = itemName{"facets", "where the rule sorts on each axis, for people to find rules alike; they change nothing the rule reports (values: the heading of each axis in these terms, which is the name of the axis as --explain writes it)"}
	nFindingKinds        = itemName{"finding kinds", "the kinds of findings the rule reports, each with what it refers to in the rule"}
	nDetected            = itemName{"detected", "what a finding of the kind says it detects; {name} stands for an argument of the finding"}
	nArguments           = itemName{"arguments", "under a kind, the arguments of a finding of the kind, each by the {name} that the text of detected writes and what the argument holds; an argument that the text of detected does not name is marked (not in the text of detected), and the JSON output of a finding still has the argument"}
	nConsequence         = itemName{"consequence", "under a kind, why a finding of it is bad"}
	nImpact              = itemName{"impact", "under CVSS, the highest of the metrics VC, VI, VA, SC, SI and SA (values: CVSS)"}
	nRemedy              = itemName{"remedy", "what a person does about a finding of the kind"}
	nFixKinds            = itemName{"fix kinds", "the kinds of fixes the rule may give; under a kind, those a finding of it may give"}
	nFactKinds           = itemName{"fact kinds", "kinds of facts about what is outside the inputs, such as a setting of a repository or the commit of a tag: under a kind, those the condition of a finding asks about, which holds only as the facts say; under a fix, those it needs; under a false positive form, those whose answer removes it (values: facts)"}
	nSafety              = itemName{"safety", "whether a fix may be applied without a person looking (values: safety)"}
	nPossibleSideEffects = itemName{"possible side effects", "under a fix, what applying it may change besides the finding, and why a person looks first; a fix given has those of them it makes"}
	nAttackers           = itemName{"attackers", "the attackers of the threat of the rule the kind refers to (values: attacker)"}
	nActor               = itemName{"actor", "an attacker (values: attacker), how they go about the attack, the events the attack takes, and what they get"}
	nVia                 = itemName{"via", "how the attacker goes about it"}
	nEvents              = itemName{"events", "the events that run a workflow, when the threat depends on them; what each is: GitHub's documentation, https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows"}
	nRunStarters         = itemName{"run starters", "who starts the run of each of the events: the attacker by an act of the attacker, or another person or a schedule; in both cases, what the attacker wrote reaches the run (values: run-starter). The value is for an event, not for one run: each event of an actor has one value, by the runs that the attack of the actor takes: attacker when the attack can take a run that the attacker starts by an act of the attacker, even when another person (such as a maintainer who adds a label) starts other runs of the same event; other when the attack takes only runs that another person or a schedule starts (such as the run after a maintainer approves)"}
	nGains               = itemName{"gains", "what the attacker gets (values: gain)"}
	nPreconditions       = itemName{"preconditions", "the IDs of the preconditions of the threat of the rule the kind refers to; a finding of the kind does not mean that each of these preconditions holds on the input of the finding (precondition)"}
	nPrecondition        = itemName{"precondition", "a statement that the threat rests on, about GitHub, the runner, an action or a program that a job runs, an AI agent, or the repository, by its ID, and the observations or the documents that back the statement. The rule checks some preconditions on the input (such as the events a job runs on) or by a kind of facts (such as repo.wiki-open), and does not check other preconditions; some preconditions are about one form of input only (such as a reusable workflow, which runs on the events of its callers)"}
	nObserved            = itemName{"observed", "what was seen on GitHub, and the day"}
	nRunner              = itemName{"runner", "the version of the runner that took part in what was seen"}
	nCites               = itemName{"cites", "the documents a statement rests on"}
	nIncidents           = itemName{"incidents", "the IDs of the incidents of the threat of the rule the kind refers to"}
	nIncident            = itemName{"incident", "a reported attack of what the rule detects, by its ID: the day, and its CVE when it has one"}
	nAdvisory            = itemName{"advisory", "the first-hand report of the incident"}
	nCompromised         = itemName{"compromised", "the repositories the attacker changed"}
	nDownstream          = itemName{"downstream", "repositories not changed, but hit through one of those compromised that they use"}
	nUndetectedForms     = itemName{"undetected forms", "the forms on which the rule reports no finding of the finding kinds under the form, each with the finding kinds and why (disposition). When the finding kinds under a form are every finding kind of the rule, the rule reports nothing on the form, not even an inconclusive finding; when the finding kinds under a form are only some of the finding kinds of the rule, the rule reports a finding of another finding kind of the rule on the form (a finding kind whose conditions the form also meets). The disposition is one of these: no-added-gain, where the flaw that the rule detects adds nothing to what the attacker gets (the disposition no-added-gain does not mean that the workflow is safe); other-rule, where another rule reports a finding on the same form, because the threat of the other rule covers the form; or limitation or todo, where whether the rule should report a finding on the form is not decided, and the consequence of a finding kind of the rule may occur"}
	nInconclusive        = itemName{"inconclusive", "the kinds of place that the rule finds and examines, where the rule cannot decide whether the workflow departs from the expected state, or whether the consequence of a finding kind of the rule can occur at the place, because the value or the content that decides the answer is outside what the rule reads, such as a value that an attacker may write, the value of a setting, or the content of a file that the rule does not read (the disposition of an inconclusive kind is limitation or todo: under the disposition limitation, the item with the name decided by gives what decides the answer; under the disposition todo, the item with the name needs gives what the linter would need to decide the answer). On such a place the rule reports a finding whose certainty is inconclusive (an inconclusive finding): the output of a run lists the inconclusive findings among the findings, marked inconclusive, and a count of findings includes the inconclusive findings. The kind of an inconclusive finding is the inconclusive kind, written <rule>.<kind>, in the same form as the ID of a finding kind, and the severity of an inconclusive finding is the severity of the rule (the worst severity of the finding kinds of the rule). An inconclusive finding sets bit 8 of the exit code when the severity of the inconclusive finding is at or above --fail-on, unless an entry of the file of --accept matches the inconclusive finding; an inconclusive finding that an entry matches stays in the output of the run, with the reason of the entry. The disposition of an inconclusive kind is limitation or todo. An inconclusive finding is different from a conditional finding (see confirmed finding, conditional finding): a conditional finding has a condition about facts of a fact kind that the finding kind declares, and the run did not learn the facts; an inconclusive finding has no such condition, and no answer about facts decides an inconclusive finding"}
	nFalsePositiveForms  = itemName{"false positive forms", "the forms on which the rule reports a finding of a kind though the consequence of the kind does not occur in a workflow that has the form, even when the workflow keeps the expected state, as far as the forms are known: under each form, the kinds of findings of the form, and what the rule would need to stop reporting the form (disposition) or the kinds of facts for which an answer other than the assumed value makes the rule report no finding on the workflows that have the form, in the run that has the answer (fact kinds)"}
	nExample             = itemName{"example", "an input that shows the declaration, and the kind of input it is (values: input-kind); a test of the rules checks that the rule gives on the example what the declaration says; the name of the file of an example is the ID of the declaration (for an example of several files, the name of its directory is), not a description of what the example has. For a true positive or a true negative, the ID is the ID of the kind without the ID of the rule. A declaration can have more than one example: the main example has the ID alone, and each other example has a label after a dot, as controlled.caller. A true negative of several kinds whose fixed inputs are the same has the IDs of those kinds joined by +, as private+public"}
	nFindingOn           = itemName{"finding on", "under an example of several files on which the rule reports a finding, the files where the findings of the declaration are; the first file of the example is the file the declaration is about, and the files of the findings may include the first file, other files of the example, or both"}
	nTruePositives       = itemName{"true positives", "under a kind, inputs on which the rule reports a finding of it; the name of the file of an example is the ID of the declaration (for a true positive or a true negative, the ID of the kind without the ID of the rule, and a label after a dot for another example of the kind), not a description of what the file has"}
	nTrueNegatives       = itemName{"true negatives", "under a kind, inputs close to the true positives on which the rule reports nothing and the consequence of the kind does not occur: the input of a true positive, fixed as the remedy says, or an input without a condition that the kind needs. The input of a true negative may also be a form that another rule reports (an undetected form whose disposition is other-rule). An undetected form whose disposition is no-added-gain is a set of inputs on which the rule reports nothing too, declared with the claim why; in the way of no-added-gain where the attacker gets the same without the flaw, unlike on a true negative, the run of such an input can still give the attacker secrets or a token; the name of the file of an example is the ID of the declaration (for a true positive or a true negative, the ID of the kind without the ID of the rule; a label after a dot for another example of the kind, the form or the kind of place, whose main example has no label; for a true negative of several kinds whose fixed inputs are the same, the IDs of those kinds joined by +, as private+public), not a description of what the file has"}
	nProvider            = itemName{"provider", "under a kind of fact, the value that names where the facts of the kind come from, and what the value means (under each kind of facts in these terms, the line after the provider says how --online answers the facts of the kind)"}
	nAssumed             = itemName{"assumed value", "under a kind of fact, the value with which a run answers a fact of the kind when no source answers the fact, unless the run has --no-assumptions, and the reason for the value; none for a kind without an assumed value"}
	nDisposition         = itemName{"disposition", "under an undetected form or an inconclusive kind, why the rule reports no finding on the form or on the kind of place, as the declaration judges now; to decide the disposition is to know whether the rule should report a finding on the form or on the place. Under a false positive form, which the rule does report, the disposition is what the rule would need to stop reporting the form (values: disposition)"}
	nRule                = itemName{"rule", "under a disposition, the rule that reports it"}
	nDecidedBy           = itemName{"decided by", "under a disposition, what decides whether the rule should report a finding on the form or on the place (values: decider)"}
	nNeeds               = itemName{"needs", "under a disposition, what would be added to the linter to decide whether the rule should report a finding on the form or on the place; a user does not add it (values: need)"}
	nAddedAttackers      = itemName{"added attackers", "under an undetected form or a false positive form, the attackers that a run counts only when the user adds the attackers with --add-attacker, such that a run that adds one of the attackers alone reports the findings of the form, and a run that adds none of the attackers does not report the findings. Under an example of a true positive, the attackers such that a run that adds one of the attackers alone reports a finding of the kind on the example, and the run that adds no attacker reports no finding of the rule on the example (values: added-attacker)"}
	nThreat              = itemName{"threat", "what the kinds refer to: the preconditions, the actors and the incidents"}
	nCVSS                = itemName{"CVSS", "the CVSS v4.0 Base metrics of each kind and its Exploit Maturity (E), each with why it has its value (values: CVSS)"}
	nVector              = itemName{"vector", "the CVSS v4.0 vector of the metrics"}
	nCVSSB               = itemName{"CVSS-B", "the score of the kind's CVSS v4.0 Base metrics by the reference calculator of FIRST, and its rating (values: CVSS); for reference, beside the severity, which is found by the table"}
	nCVSSBT              = itemName{"CVSS-BT", "CVSS-B with the kind's Exploit Maturity (E), the one metric the CVSS specification calls the likelihood of being attacked, and its rating (values: CVSS)"}
	nLikelihood          = itemName{"likelihood", "how readily the threat comes about, for the table of severity: the ease of the attack from AV, AT and PR, lowered by AC and UI; not Exploit Maturity (E), which CVSS calls the likelihood of being attacked and only CVSS-BT takes (values: likelihood)"}
	nFrom                = itemName{"from", "the metrics that give the impact, or that give the likelihood by the row of the table they match"}
	nLoweredBy           = itemName{"lowered by", "the metrics that lowered the likelihood one step (the rows: values of likelihood)"}
	nReason              = itemName{"reason", "why the metric has its value"}
	nQuality             = itemName{"quality rule", "a rule whose finding alone gives no attacker a gain (values: gain): an attack needs another flaw. The flaw that a quality rule finds may still let an attack through another flaw give the attacker more, or keep a vulnerability unfixed for longer. The quality rules check reliability and maintainability. A quality rule has no threat, no CVSS and no severity. The findings of a quality rule set no bit of the exit code; the findings of the other rules, of every certainty, and the inputs set the bits as in a run without the quality rules"}
	nDefaultRun          = itemName{"default run", "whether the rule runs in a run without --rule (a run that names no rule, or a run of --skip-rule): always, named, facts or given-facts, then what the value means. The default run of a rule holds in a run when the value lets the rule run in that one run: facts and given-facts hold in one run and not in another. sisakulint leaves out of a run without --rule each rule whose default run does not hold in the run, and the report gives the ID of the rule in skipped_rules"}
	nCitations           = itemName{"citations", "the documents the rule rests on: those of the rule as a whole, then those its text cites"}
)

// itemNames are the item names of --explain, in the order Terms writes
// them.
var itemNames = []itemName{
	nCommit, nTerms, nProblem, nExpected, nSeverity, nTargets, nQuality, nDefaultRun, nFacets,
	nFindingKinds, nDetected, nArguments, nConsequence, nImpact, nRemedy, nFixKinds, nFactKinds, nSafety, nPossibleSideEffects,
	nUndetectedForms, nInconclusive, nFalsePositiveForms, nExample, nFindingOn, nTruePositives, nTrueNegatives, nProvider, nAssumed, nDisposition, nRule, nDecidedBy, nNeeds, nAddedAttackers,
	nThreat, nPreconditions, nPrecondition, nObserved, nRunner, nCites,
	nAttackers, nActor, nVia, nEvents, nRunStarters, nGains,
	nIncidents, nIncident, nAdvisory, nCompromised, nDownstream,
	nCVSS, nVector, nCVSSB, nCVSSBT, nLikelihood, nFrom, nLoweredBy, nReason, nCitations,
}

// textTerms are the words the texts of the rules use that are neither a
// item name nor a value of an enumeration, and what each means, in the order
// Terms writes them. A word that cites a document cites it at a fixed
// commit.
var textTerms = []textTerm{
	{name: "privileged event", doc: privilegedEventDoc()},
	{name: "$/", doc: "a uses that starts with $/, the self repository reference of GitHub: the action at the path after $/, in the repository of the file that has the uses, at the commit of the running workflow or action; a $/ uses has no @ and no ref. GitHub documents the reference in https://github.com/github/docs/blob/5815d11586b0796688963a98c889680e60d72dc4/content/actions/reference/workflows-and-actions/workflow-syntax.md"},
	{name: "tag mode, agent mode", doc: "the two modes of claude-code-action. A step with track_progress true, on pull_request, issues, issue_comment, pull_request_review or pull_request_review_comment, runs in the tag mode, and a step with track_progress true on another event stops with an error. Otherwise, a step with the input prompt runs in the agent mode, which gives the prompt to the agent; and a step without prompt, on an event of an issue, a comment or a review that has the trigger of the step (@claude, or the label or the assignee that the step names), runs in the tag mode; a step without prompt and without the trigger runs in the agent mode, which starts no agent without a prompt. In the tag mode, the action puts the title, the body and the comments of the issue or of the pull request in the prompt. The tools that the agent has by default differ between the two modes. The code of claude-code-action that decides the mode and writes the prompt: https://github.com/anthropics/claude-code-action/blob/6fed3ca145920b639991cb756090506e1bcaf515/src/modes/detector.ts and https://github.com/anthropics/claude-code-action/blob/6fed3ca145920b639991cb756090506e1bcaf515/src/create-prompt/index.ts"},
	{name: "larger runner", doc: "a runner that GitHub manages, with more resources than the standard GitHub-hosted runners; larger runners can be put in runner groups. GitHub documents larger runners in https://github.com/github/docs/blob/5815d11586b0796688963a98c889680e60d72dc4/data/reusables/actions/about-larger-runners.md"},
	{name: "internal repository, enterprise", doc: "an enterprise is an account of GitHub whose administrators manage the policies and the billing of several organizations; an internal repository is a repository that every member of the enterprise can read, owned by an organization of the enterprise. GitHub documents them in https://github.com/github/docs/blob/5815d11586b0796688963a98c889680e60d72dc4/content/repositories/creating-and-managing-repositories/about-repositories.md and https://github.com/github/docs/blob/5815d11586b0796688963a98c889680e60d72dc4/content/get-started/learning-about-github/types-of-github-accounts.md"},
	{name: "input", doc: "the word has two meanings. In the definitions of the item names of these terms, and where a text speaks of the inputs, of an input kind or of what is among the inputs, an input is a file given to the linter: a workflow or an action metadata file (values: input-kind). In the other texts of the rules, an input is an input of GitHub: an input of an action (what a step gives the action under with, such as the input prompt of claude-code-action), an input of a reusable workflow, of workflow_dispatch or of workflow_call, or a value of the inputs context (inputs.<name>)"},
	{name: "confirmed finding, conditional finding", doc: "two of the three certainties of a finding (the field certainty of a finding in the JSON output); the third certainty is inconclusive (see inconclusive). Some finding kinds have a condition about facts (fact kinds), such as whether anyone may edit the wiki of the repository. A run asks the following sources about a fact in this order, and uses the first answer: --fact, a file under --root, the file of --facts, and the GitHub API (--online). Some fact kinds also have an assumed value, the worst case: a value with which the condition of a finding holds. When no source answers a fact of a fact kind with an assumed value, the run answers the fact by the assumed value, unless the run has --no-assumptions. A confirmed finding is a finding without a condition, or a finding whose condition holds by the answers, even when an answer is an assumed value; the text output shows the assumed value beside the finding. A conditional finding is a finding whose condition the run cannot decide, because neither a source nor an assumed value answered a fact of the condition; the output of the run lists a conditional finding among the findings, as a finding that holds if the condition holds. A conditional finding is different from an inconclusive finding (see inconclusive): an inconclusive finding has no condition about facts. When the answers show that the condition does not hold, the rule reports no finding. A confirmed finding sets bit 1 of the exit code, and a conditional finding sets bit 2 of the exit code, when the severity of the finding is at or above --fail-on; a finding of a quality rule has a certainty too, and sets no bit"},
	{name: "credential premise", doc: `The threat model assumes the following about the credentials of every attacker. What a credential can change: a credential can change the repository whose files the linter reads only in the ways that the credential allows. For a token (a fine-grained personal access token, an installation access token or a user access token of a GitHub App, or a GITHUB_TOKEN), the permissions of the token decide the changes; a user access token of a GitHub App has only the permissions that both the user and the GitHub App have. For the web interface, for a personal access token (classic) with the scope repo, and for a personal access token (classic) with the scope public_repo in a public repository, the role of the account in the repository decides the changes. The premise: no attacker has, when the attack starts, a credential of either of the following two kinds. The first kind is a credential that can make at least one change in the repository that is allowed neither by the role read nor by write access to the permission Actions. The second kind is a credential with which a required reviewer of an environment of the repository can approve a deployment to the environment. Examples of credentials of the first kind: a token with write access to the permission Contents, Issues, Pull requests, Discussions or Deployments of the repository, or with write access to any other permission of the repository that allows a change and is not Actions; and a credential of an account with the role triage or above. A change of a workflow file needs write access to both the permission Contents and the permission Workflows; write access to the permission Workflows alone allows no change. What the role read can change: the changes that an account with the role read can make depend on the repository and on the settings of the repository, so the boundary of the premise depends on the repository and on the settings of the repository too. For example, an account with the role read can open an issue when the repository has issues enabled, and can open a pull request from a fork when the repository allows forking. In a public repository, any account, also an account without a role in the repository, can fork the repository, and can open an issue, comment on a pull request and open a pull request unless the repository uses the GitHub feature that limits interactions, which can stop opening issues, commenting and creating pull requests. The examples of the role read and of a public repository are not a complete list of changes. Who has the credential: the premise is the same whether the credential is a token that leaked or a credential of a bot, an app or an account of a third party. Attackers that the threat model includes: every attacker whose credentials are of neither kind, for example an attacker whose credentials can make only the changes that an account with the role read can make, and an attacker who also has a credential whose only write access is to the permission Actions. A credential whose only write access is to the permission Actions can dispatch a workflow with inputs of the choice of the attacker, start a re-run (also with debug logging), approve a workflow run that GitHub holds for approval because a pull request from a fork started the run (this approval is not a review of the pull request), change the template of the OIDC subject claim, and delete a workflow run or the logs of a workflow run, among other changes that write access to the permission Actions allows. A credential whose only write access is to the permission Actions cannot push, add a label or approve a deployment with the credential; a workflow that the credential dispatches or re-runs does what the workflow does with the token of the run. What a rule counts: for each attacker, a rule counts what a flaw of the workflow gives the attacker beyond what the credentials of the attacker give the attacker without the flaw. Credentials that a flaw gives: a flaw can give an attacker a credential of the first kind, such as a token that a run leaves in an artifact, or can give the attacker the use of such a credential, such as a workflow that adds a label with a personal access token, or sends a repository_dispatch with a token of the repository, from values that the attacker wrote. With such a use, the attacker does not get the token, but the values of the attacker decide what the workflow does with the token. The premise concerns the credentials that an attacker has when the attack starts, so the premise does not stop a rule from reporting such a flaw; the rule artipacked reports a token left in an artifact. A consequence of the premise: some runs start only after a gate, a label or an approval admits the run. When a person or a program admits the run with a credential that the premise excludes, and no flaw that gives the use of the credential causes the act that admits the run, the rules do not take the person or the program as an attacker, and report no finding whose attack needs the gate, the label or the approval to admit a run that an attacker started. Two cases follow from this consequence and are not further exclusions. In the first case, an attacker took over a bot, an app, an account or a required reviewer whose credential admits the run; the rules report no such finding for the run. In the second case, an attacker has a token of an account with the role write, and the only write access of the token is to the permission Issues. The premise excludes the token, because the token can add a label to an issue, which an account with the role read cannot do. A comment written with the token starts a run whose actor is the account, and a gate that checks the role of the account admits the run; the rules report no such finding for the run. GitHub lists the permissions of tokens in the pages "Permissions required for fine-grained personal access tokens" (data: https://github.com/github/docs/blob/5815d11586b0796688963a98c889680e60d72dc4/src/github-apps/data/fpt-2026-03-10/fine-grained-pat-permissions.json) and "Permissions required for GitHub Apps" (data: https://github.com/github/docs/blob/5815d11586b0796688963a98c889680e60d72dc4/src/github-apps/data/fpt-2026-03-10/server-to-server-permissions.json).`, items: []string{
		`R: the repository whose files the linter reads`,
		`Allow(p): the set of changes that the access p to a permission of R allows`,
		`RoleOps(R, r): the set of changes that an account with the role r can make in R; the settings of R change the set`,
		`AnyOps(R): the set of changes that every account can make in R; the set is empty when R is private`,
		`ReadOps(R) = RoleOps(R, read) ∪ AnyOps(R)`,
		`ActionsOps = Allow(write access to Actions)`,
		`Ops(c) for a token c: the union of Allow(p) over the permissions p of c; the permissions of a user access token of a GitHub App are those that both the user and the GitHub App have`,
		`Ops(c) for the web interface or a personal access token (classic) c: RoleOps(R, the role of the account of c)`,
		`Reviewer(c): true when a required reviewer of an environment of R can approve a deployment to the environment with c`,
		`Excluded(c) ⇔ (Ops(c) ∖ (ReadOps(R) ∪ ActionsOps) ≠ ∅) ∨ Reviewer(c)`,
		`A: the set of the credentials that the attacker has when the attack starts`,
		`W: the set of the flaws of the workflow`,
		`Gets(X, F): what an attacker with the set of credentials X gets from a workflow with the set of flaws F`,
		`the premise: ∀ c ∈ A: ¬Excluded(c)`,
		`what a rule counts, for each attacker and each flaw f ∈ W: Gets(A, {f}) ∖ Gets(A, ∅)`,
		`the consequence: when a gate, a label or an approval admits a run by an act with a credential c, Excluded(c), and no flaw of W causes the act, the rules report no finding whose attack needs the gate, the label or the approval to admit a run that an attacker started`,
	}},
	{name: "example notes", doc: exampleNotesDoc()},
	{name: "fix", doc: "a change to a file given to the linter, made of edits of the text of the file, that a rule computes for a finding. For each finding that has a fix, the output of a run shows the fix. --fix writes the safe fixes (see safety) into the files given to the linter, and --fix=review writes every fix, without asking. With --dry-run, no file given to the linter changes. Before the linter writes the fixes, the linter runs the rules again on the fixed text. The linter writes no fix into any file when two fixes overlap, or when the rules on the fixed text still report a finding that a fix was to remove, report a new finding, or change the certainty or the condition of a finding. Without --fix, no file given to the linter changes. A fix is different from the remedy of a finding kind: the remedy is what a person does about a finding"},
}

// noteKeyDocs are what each key of the notes of an example (noteKeys) says.
var noteKeyDocs = map[string]string{
	"situation":           "what the workflow of the example does",
	"reason":              "why the example is what the declaration says: whether harm can occur, why the rule does not detect the example, or why the rule cannot decide",
	"cause":               "for a false positive form or an undetected form, the part of the rule that reads the example otherwise than GitHub runs the example",
	"attack":              "what an attacker does, when the attack is not a string that the attacker writes",
	"attack-value":        "the string that an attacker writes, and the place where the string goes",
	"attack-run-behavior": "what the run of the example does when the attack goes in",
	"advisory":            "the page of an advisory whose workflow the example reproduces steps of: a page of GitHub Security Lab, of the GitHub Advisory Database, or of the security advisories of a repository; one line for each advisory",
	"source":              "the file of a public repository at a commit whose steps the example reproduces, for a form that no advisory reports: a URL of github.com with blob, the commit and the path of the file, not a branch or a tag; one line for each file",
	"added-attacker":      "for a true positive, an added attacker (values: added-attacker) such that a run of the linter that adds the added attacker alone reports a finding of the kind on the example, and the run of the linter that adds no attacker reports no finding of the rule on the example; one line for each added attacker",
}

// exampleNotesDoc is what the notes of an example are, each key in the
// order of noteKeys with what the key says.
func exampleNotesDoc() string {
	var keys []string
	for _, k := range noteKeys {
		keys = append(keys, k+": "+noteKeyDocs[k])
	}
	return "the comments that the file of an example starts with, each in the form # key: text, which are in the text of the example that --explain writes. The keys: " + strings.Join(keys, "; ") + ". The note reason is not the reason of a CVSS metric (the item name reason)"
}

// privilegedEventPreconditionEvents are the privileged events the
// precondition privileged-event of the rules of a checkout of the code of a
// pull request is about.
var privilegedEventPreconditionEvents = []workflow.EventName{workflow.EventNamePullRequestTarget, workflow.EventNameWorkflowRun, workflow.EventNameIssueComment}

// notPrivileged are events a privileged event is not, each group with why.
var notPrivileged = []struct {
	events []workflow.EventName
	why    string
}{
	{[]workflow.EventName{workflow.EventNamePullRequest}, "whose author can change the workflow"},
	{[]workflow.EventName{workflow.EventNamePush, workflow.EventNameMergeGroup}, "which need write access"},
	{[]workflow.EventName{workflow.EventNameWorkflowDispatch}, "which one with write access to the permission Actions dispatches; the credential premise keeps such a one in the threat model. The values of the event that the one who dispatches the workflow writes are only the inputs, which the rules report as the inconclusive kind input-dispatch (the decider dispatcher)"},
	{[]workflow.EventName{workflow.EventNameSchedule}, "which no person triggers"},
	{[]workflow.EventName{workflow.EventNameWatch}, "whose payload has no text that an attacker wrote, only the account that starred the repository"},
	{[]workflow.EventName{workflow.EventNameGollum}, "which one without write access triggers only where anyone may edit the wiki (a rule that reads gollum declares gollum: a kind of finding on repo.wiki-open, or an undetected form)"},
}

// privilegedEventDoc is what a privileged event is: the events of
// job.Privileged, and those of notPrivileged with why.
func privilegedEventDoc() string {
	names := func(evs []workflow.EventName) string {
		var ns []string
		for _, e := range evs {
			ns = append(ns, e.String())
		}
		if len(ns) > 1 {
			return strings.Join(ns[:len(ns)-1], ", ") + " and " + ns[len(ns)-1]
		}
		return ns[0]
	}
	var not []string
	for _, n := range notPrivileged {
		not = append(not, names(n.events)+", "+n.why)
	}
	return "an event that one without write access to the repository triggers, whose payload has what an attacker wrote, and whose run can have the secrets of the repository and a GITHUB_TOKEN that writes: " + names(job.Privileged()) + ". Among the events that are not privileged events: " + strings.Join(not, "; ") + ". The precondition privileged-event is about three of the privileged events: " + names(privilegedEventPreconditionEvents) +
		". The Actions policies of a repository can block the runs of any event. GitHub adds to a public repository without an applicable event policy a default policy that blocks pull_request_target. The rules assume that the runs of a privileged event start. For status, check_suite and check_run, the rules assume one more thing: an app outside GitHub Actions, such as an outside CI, makes a commit status or a check run for a commit whose message an attacker writes (a commit of a pull request from a fork, or a commit that merges a pull request), and the commit status or the check run starts a run of status, check_suite or check_run, which runs the workflow of the default branch, whatever branch the commit is on. The payload of a run of any of the three events has the SHA of the commit, and the payload of a run of status or check_suite also has the message, the author name and the committer name of the commit. The rules ask whether an app outside GitHub Actions makes a commit status or a check run for a commit of a pull request from a fork by the fact kind repo.fork-pr-app-checks, and for a commit that the merge of a pull request puts in a branch of the repository or that a merge queue of the repository makes by the fact kind repo.merge-commit-app-checks (both assumed true), only for a workflow whose on has only events among status, check_suite and check_run (one, two or all three). For pull_request_review and pull_request_review_comment, the rules assume two more things. First, the repository has an open pull request from a branch of the repository, or a branch from which the attacker can open a pull request: anyone with read access to a repository can open a pull request between two branches that the repository already has, without write access. Second, the run of a review that an outside contributor writes on such a pull request does not wait for an approval, whatever the repository requires of the runs of outside contributors; the runs that the authors of the linter saw were in a repository that requires an approval only for first-time contributors. That a run of a review of a pull request that one without write access opened between two branches that others pushed to the repository has the secrets and the token that the workflow asks for is inferred: the runs that the authors of the linter saw were of reviews of a pull request that the owner of the repository opened. Only for pull_request_target do the rules ask whether the runs start, by the fact kind repo.pull-request-target-allowed (assumed true), and only for a workflow whose on has pull_request_target and no other event (no workflow_call event either)"
}

// dispositionValues are the values of a Disposition as --explain writes them, and what
// each means (the enum of $defs/disposition of schema/registry-v0.json, which
// is not an enumeration of consts).
var dispositionValues = []struct{ name, doc string }{
	{"no-added-gain", "on a form of this value, the flaw that the rule detects (the problem of the rule) adds nothing to what the attacker of the threat of the rule gets from the repository of the input. A form has this value in one of two ways. In the first way, the form does not have the flaw, or the flaw on the form gives the attacker nothing. In the second way, the attacker gets the same without the flaw, such as the author of a pull request, who can change the workflow of a pull_request run when only the pull requests of the repository run the workflow; in the second way, the run can give the attacker secrets or a token that writes, and the workflow can be dangerous while the rule reports nothing. A quality rule has no threat, so no form of a quality rule has this value. The value says nothing of the threats of other rules: another rule may report a form of this value, and the value does not mean that a workflow with the form is safe. The gain that the rule counts is what the attacker gets in the step with the flaw and after that step: in the later steps of the job with the flaw, through the environment files that the step writes, the files that the step leaves on the runner and the processes that the step leaves running; in the other jobs of the run, through the outputs of the job with the flaw and the artifacts that the job with the flaw uploads; and in later runs, through a cache that the run with the flaw saves and a later run restores, and an artifact that the run with the flaw uploads and a later run downloads. What the attacker gets from the repository without the flaw depends on the credentials of the attacker, which the credential premise bounds"},
	{"other-rule", "another rule reports the same form, as a form of the threat of that rule (rule)"},
	{"limitation", "nothing that can be added is expected to decide it now; the decider that decided by names decides it"},
	{"todo", "adding what needs names is expected to decide it for some of its places"},
}

// Terms is what the item names of --explain mean, and each value of the
// enumerations it writes with what it means, as Markdown for people;
// commit is the commit of the binary. The values and what they mean are
// those of the schemas (schema/registry-v0.json, and the kinds of facts
// but those for tests), so that a value added there is here.
func Terms(commit string) []byte {
	d := Definitions()
	var w mdWriter
	w.heading(1, "sisakulint terms")
	w.list([]mdItem{{text: nCommit.is(md(commit))}})
	w.heading(2, "item names")
	w.paragraph(md(d.ItemNamesDescription))
	w.list(definitionItems(d.ItemNames, false))
	w.heading(2, "words in the texts")
	w.list(definitionItems(d.TextTerms, false))
	w.heading(2, "values")
	cvss := false
	for _, g := range d.ValueGroups {
		items := definitionItems(g.Values, true)
		switch {
		case g.CVSS:
			// the metrics of CVSS, each a heading of the fourth level under CVSS
			if !cvss {
				w.heading(3, "CVSS")
				cvss = true
			}
			w.heading(4, g.Heading+": "+md(g.Description))
			w.list(items)
		case g.Description != "":
			w.heading(3, g.Heading)
			w.paragraph(md(g.Description))
			w.list(items)
		default:
			w.group(g.Heading, items)
		}
	}
	return []byte(w.b.String())
}

// definitionItems are the items "name: text" of ds, the name escaped for
// Markdown when escape is set (a value; an item name and a word in the
// texts are written as they are).
func definitionItems(ds []Definition, escape bool) []mdItem {
	var items []mdItem
	for _, x := range ds {
		name := x.Name
		if escape {
			name = md(name)
		}
		it := mdItem{text: name + ": " + md(x.Text)}
		for _, sub := range x.Items {
			it.sub = append(it.sub, mdItem{text: md(sub)})
		}
		items = append(items, it)
	}
	return items
}

// described is a value of an enumeration of the schemas (enum_gen.go).
type described interface {
	fmt.Stringer
	description() string
}
