package boundary

import (
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

const rolesDoc = "data/tables/repository-roles.yml"

// The quotes of the roles: rows of the table of repository roles, an
// action and the roles that may do it, and sentences of who may fork,
// open an issue or a pull request, and comment.
var (
	rolesFork      = doc(rolesDoc, "  - action: \"Fork the person or team's assigned repositories\"\n    roles: 'read, triage, write, maintain, admin'")
	rolesOpenIssue = doc(rolesDoc, "  - action: 'Open issues'\n    roles: 'read, triage, write, maintain, admin'")
	rolesForkPR    = doc(rolesDoc, "  - action: \"Send pull requests from forks of the team's assigned repositories\"\n    roles: 'read, triage, write, maintain, admin'")
	rolesReview    = doc(rolesDoc, "  - action: '[Submit reviews on pull requests](/pull-requests/how-tos/review-pull-requests/reviewing-proposed-changes-in-a-pull-request)'\n    roles: 'read, triage, write, maintain, admin'")
	rolesDiscuss   = doc(rolesDoc, "  - action: '[Create new discussions and comment on existing discussions](/discussions/collaborating-with-your-community-using-discussions/participating-in-a-discussion)'\n    roles: 'read, triage, write, maintain, admin'")
	rolesWikiPub   = doc(rolesDoc, "  - action: 'Edit wikis in public repositories'\n    roles: 'read, triage, write, maintain, admin'")
	rolesWikiPriv  = doc(rolesDoc, "  - action: 'Edit wikis in private repositories'\n    roles: 'write, maintain, admin'")
	rolesPush      = doc(rolesDoc, "  - action: \"Push to (write) the person or team's assigned repositories\"\n    roles: 'write, maintain, admin'")
	rolesWorkflows = doc(rolesDoc, "  - action: 'Create, edit, run, re-run, and cancel [{% data variables.product.prodname_actions %} workflows](/actions)'\n    versions: '{% ifversion fpt or ghec %}show{% endif %}'\n    roles: 'write, maintain, admin'")

	forkPublic    = doc("data/reusables/repositories/you-can-fork.md", "You can fork any public repository:")
	forkPrivate   = doc("data/reusables/repositories/you-can-fork.md", "If you have access to a private repository and the owner permits forking, you can fork the repository:")
	anyonePR      = doc("content/actions/reference/security/secure-use.md", "any user can open pull requests against the repository and compromise the environment")
	readerPR      = doc("content/pull-requests/how-tos/create-pull-requests/creating-a-pull-request.md", "Anyone with read access to a repository can create a pull request.")
	forkerRunner  = doc("content/actions/reference/security/secure-use.md", "anyone who can fork the repository and open a pull request (generally those with read access to the repository) are able to compromise the self-hosted runner environment")
	anyoneIssue   = doc("content/desktop/working-with-your-remote-repository-on-github-or-github-enterprise/creating-an-issue-or-pull-request-from-github-desktop.md", "Anyone can create an issue in a public repository that has issues enabled.")
	readerIssue   = doc("content/issues/tracking-your-work-with-issues/using-issues/creating-an-issue.md", "People with read access can create an issue in a repository where issues are enabled.")
	anyoneComment = doc("content/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/managing-pull-request-reviews-in-your-repository.md", "anyone can comment on pull requests in your public repository")
	privateOnly   = doc("content/repositories/creating-and-managing-repositories/about-repositories.md", "* Private repositories are only accessible to you, people you explicitly share access with, and, for organization repositories, certain organization members.")
	internalOnly  = doc("content/repositories/creating-and-managing-repositories/about-repositories.md", "Internal repositories are not visible to people {% ifversion fpt or ghec %}outside of the enterprise{% else %}who are not members of any organization{% endif %}, including outside collaborators on organization repositories.")
	anyoneWiki    = doc("content/communities/documenting-your-project-with-wikis/changing-access-permissions-for-wikis.md", "Only repository collaborators can edit a public repository''s wiki by default, but you can allow anyone with an account on")
)

func baselineList() []RoleBaseline {
	public, private := is(facts.RepoPublic{}, true), is(facts.RepoPublic{}, false)
	forkable := lint.Any(public, is(facts.RepoAllowForking{}, true))
	closed := lint.All(private, is(facts.RepoAllowForking{}, false))
	forkPR := RunRef{workflow.EventNamePullRequest, PRHeadFork}
	b := []RoleBaseline{
		{Role: RoleNone, Condition: public, Runs: []RunRef{forkPR}, SelfHostedRunner: expr.TruthTrue, Basis: BasisDocumented, Quotes: []Quote{anyonePR, forkPublic}, Observed: []lint.Observation{sawForkPRPublic}},
		{Role: RoleNone, Condition: private, SelfHostedRunner: expr.TruthFalse, Basis: BasisDocumented, Quotes: []Quote{privateOnly, internalOnly, readerPR}},
	}
	for _, r := range []Role{RoleRead, RoleTriage} {
		b = append(b,
			RoleBaseline{Role: r, Condition: forkable, Runs: []RunRef{forkPR}, SelfHostedRunner: expr.TruthTrue, Basis: BasisDocumented, Quotes: []Quote{rolesFork, rolesForkPR, forkPrivate, forkerRunner}, Observed: []lint.Observation{sawReaderActs(r)}},
			RoleBaseline{Role: r, Condition: closed, SelfHostedRunner: expr.TruthFalse, Basis: BasisDocumented, Quotes: []Quote{forkPrivate, rolesPush}},
		)
	}
	for _, r := range []Role{RoleWrite, RoleMaintain, RoleAdmin} {
		b = append(b, RoleBaseline{Role: r, Runs: []RunRef{{workflow.EventNamePullRequest, PRHeadRepository}, {workflow.EventNamePush, PRHeadNone}},
			SelfHostedRunner: expr.TruthTrue, Basis: BasisDocumented, Quotes: []Quote{rolesPush, rolesWorkflows}})
	}
	return b
}

// channel is a documented row of a and r.
func channel(a lint.Attacker, r Role, c lint.Condition, writable bool, qs ...Quote) Channel {
	return Channel{Attacker: a, Role: r, Condition: c, Writable: writable, Basis: BasisDocumented, Quotes: qs}
}

// seen is c observed by o: o saw what c says.
func seen(c Channel, o lint.Observation) Channel {
	c.Basis, c.Observed = BasisObserved, append(c.Observed, o)
	return c
}

// seenOfReader is c observed by what one of its role was seen to do, when
// the role is read or triage, the roles of the check.
func seenOfReader(c Channel) Channel {
	if c.Role != RoleRead && c.Role != RoleTriage {
		return c
	}
	return seen(c, sawReaderActs(c.Role))
}

func channelList() []Channel {
	public, private := is(facts.RepoPublic{}, true), is(facts.RepoPublic{}, false)
	forkable := lint.Any(public, is(facts.RepoAllowForking{}, true))
	closed := lint.All(private, is(facts.RepoAllowForking{}, false))
	wikiOpen, wikiClosed := is(facts.RepoWikiOpen{}, true), is(facts.RepoWikiOpen{}, false)
	readers := []Role{RoleRead, RoleTriage, RoleWrite, RoleMaintain, RoleAdmin}
	var c []Channel
	// issue-author: an issue or a discussion
	c = append(c, seen(channel(lint.AttackerIssueAuthor, RoleNone, public, true, anyoneIssue), sawNoneActs), channel(lint.AttackerIssueAuthor, RoleNone, private, false, privateOnly, internalOnly, readerIssue))
	for _, r := range readers {
		c = append(c, seenOfReader(channel(lint.AttackerIssueAuthor, r, lint.Condition{}, true, rolesOpenIssue, rolesDiscuss)))
	}
	// commenter: a comment or a review
	c = append(c, seen(channel(lint.AttackerCommenter, RoleNone, public, true, anyoneComment), sawNoneActs), channel(lint.AttackerCommenter, RoleNone, private, false, privateOnly, internalOnly))
	for _, r := range readers {
		c = append(c, seenOfReader(channel(lint.AttackerCommenter, r, lint.Condition{}, true, rolesReview, rolesDiscuss)))
	}
	// fork-pr-author, merged-commit-author and anyone-who-forks: a fork,
	// and a pull request from it, whose commit a maintainer may merge
	for _, a := range []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerMergedCommitAuthor, lint.AttackerAnyoneWhoForks} {
		none := channel(a, RoleNone, public, true, anyonePR, forkPublic)
		if a != lint.AttackerMergedCommitAuthor { // no commit was merged
			none = seen(none, sawNoneActs)
		}
		c = append(c, none, channel(a, RoleNone, private, false, privateOnly, internalOnly, readerPR))
		for _, r := range []Role{RoleRead, RoleTriage} {
			reader := channel(a, r, forkable, true, rolesFork, rolesForkPR, forkPrivate)
			if a == lint.AttackerForkPRAuthor { // not anyone-who-forks: the fork they pushed to was made when they had no role
				reader = seenOfReader(reader)
			}
			c = append(c, reader, channel(a, r, closed, false, forkPrivate))
		}
		for _, r := range []Role{RoleWrite, RoleMaintain, RoleAdmin} {
			c = append(c, channel(a, r, forkable, true, rolesFork, rolesForkPR, forkPrivate))
			if a == lint.AttackerMergedCommitAuthor {
				c = append(c, channel(a, r, closed, true, rolesPush)) // a commit of a branch they push
			} else {
				c = append(c, channel(a, r, closed, false, forkPrivate))
			}
		}
	}
	// wiki-editor
	// repo.wiki-open is true only of a public repository; a private one's
	// wiki is closed to those without access, whatever it says
	closedToNone := channel(lint.AttackerWikiEditor, RoleNone, lint.Any(private, wikiClosed), false, anyoneWiki, privateOnly, internalOnly)
	closedToNone.Observed = []lint.Observation{sawWikiOffNone} // a wiki turned off only: not a private one, nor one that only collaborators may edit
	c = append(c, seen(channel(lint.AttackerWikiEditor, RoleNone, lint.All(public, wikiOpen), true, anyoneWiki), sawWikiNone), closedToNone)
	for _, r := range []Role{RoleRead, RoleTriage} {
		reader := channel(lint.AttackerWikiEditor, r, public, true, rolesWikiPub)
		reader.Basis, reader.Observed, reader.Uncertainty = BasisUnverified, []lint.Observation{sawWikiRestricted}, unknownWikiOff
		c = append(c, reader, channel(lint.AttackerWikiEditor, r, private, false, rolesWikiPriv))
	}
	for _, r := range []Role{RoleWrite, RoleMaintain, RoleAdmin} {
		c = append(c, channel(lint.AttackerWikiEditor, r, lint.Condition{}, true, rolesWikiPub, rolesWikiPriv))
	}
	return c
}

// baselineRows are what one of each role holds before any flaw of a
// workflow.
var baselineRows = baselineList()

// channelRows are which roles can write what each attacker writes.
var channelRows = channelList()

// retrievedPathways is when the quotes of the pathways were retrieved.
var retrievedPathways = lint.MustDate("2026-10-22")

// doc22 is doc, retrieved on retrievedPathways.
func doc22(path, text string) Quote {
	return source("github/docs", docsCommit, path, text, retrievedPathways)
}

const secureUseDoc = "content/actions/reference/security/secure-use.md"

// The quotes of the pathways: who downloads an artifact or views a log of
// a run, and how code or a destination outside the repository gets at a
// job.
var (
	artifactDownload = doc22("content/actions/how-tos/manage-workflow-runs/download-workflow-artifacts.md", "People who are signed into {% data variables.product.github %} and have read access to a repository can download workflow artifacts.")
	publicAll        = doc22("content/repositories/creating-and-managing-repositories/about-repositories.md", "Public repositories are accessible to everyone on the internet.")
	logRead          = doc22("data/reusables/repositories/permissions-statement-read.md", "Read access to the repository is required to perform these steps.")
	logSignIn        = doc22("content/actions/how-tos/monitor-workflows/use-workflow-run-logs.md", "You must be logged in to a {% data variables.product.prodname_dotcom %} account to view workflow run information, including for public repositories.")
	actionCompromise = doc22(secureUseDoc, "This means that a compromise of a single action within a workflow can be very significant, as that compromised action would have access to all secrets configured on your repository, and may be able to use the `GITHUB_TOKEN` to write to the repository.")
	tagMoved         = doc22(secureUseDoc, "Note that there is risk to this approach even if you trust the author, because a tag can be moved or deleted if a bad actor gains access to the repository storing the action.")
	networkCommits   = doc22("content/pull-requests/reference/forks.md", "Commits pushed to any repository in a network can be accessible from other repositories in that network, including the upstream repository.")
	dockerTags       = source("docker/docs", "226023fc89bdeb3f051c4c8c697d04ed5f5bcd2c", "data/cli/engine/docker_image_pull.yaml", "When using tags, you can `docker pull` an\n    image again to make sure you have the most up-to-date version of that image.", retrievedPathways)
	curlHeader       = source("curl/curl", "dc99e1274b2bb368dea509ac6694d34e93c50054", "docs/cmdline-opts/header.md", "Help: Pass custom header(s) to server", retrievedPathways)

	sawForkCommit = lint.Observation{Date: lint.MustDate("2026-09-25"), Runner: runner2337, What: "a step had uses: owner/repo@<SHA of a commit that was only in a fork>, where owner/repo was the repository that the fork was made from. The step ran the commit of the fork. The workflow of the step was in owner/repo, not in another repository"}
)

const unknownAdvisory = "who can exploit the vulnerability differs from one advisory to another: exploiting the vulnerability may need no access to the repository whose files are given to the linter, or may need a role in that repository such as write"

// pathway is a documented row of a and r.
func pathway(a lint.Attacker, r Role, c lint.Condition, usable bool, qs ...Quote) Pathway {
	return Pathway{Attacker: a, Role: r, Condition: c, Usable: truthOf(usable), Basis: BasisDocumented, Quotes: qs}
}

func pathwayList() []Pathway {
	public, private := is(facts.RepoPublic{}, true), is(facts.RepoPublic{}, false)
	readers := []Role{RoleRead, RoleTriage, RoleWrite, RoleMaintain, RoleAdmin}
	var p []Pathway
	// artifact-reader and log-reader: what a run leaves, to those who read
	// the repository; on a public repository, to anyone signed in
	for _, x := range []struct {
		a            lint.Attacker
		open, closed []Quote
		reader       Quote
	}{
		{lint.AttackerArtifactReader, []Quote{artifactDownload, publicAll}, []Quote{privateOnly, internalOnly, artifactDownload}, artifactDownload},
		{lint.AttackerLogReader, []Quote{logRead, logSignIn, publicAll}, []Quote{privateOnly, internalOnly, logRead}, logRead},
	} {
		none := pathway(x.a, RoleNone, public, true, x.open...)
		none.Basis, none.Observed = BasisObserved, []lint.Observation{sawArtifactLogNone}
		p = append(p, none, pathway(x.a, RoleNone, private, false, x.closed...))
		for _, r := range readers {
			row := pathway(x.a, r, lint.Condition{}, true, x.reader)
			if r == RoleRead || r == RoleTriage {
				row.Basis, row.Observed = BasisObserved, []lint.Observation{sawArtifactLogRole}
			}
			p = append(p, row)
		}
	}
	// those outside the repository: what they write is outside it (the
	// repository called, a registry, the server of a destination), so one
	// of any role here can be them. The quotes say that what a job runs or
	// sends is decided outside the repository; that any role can be them is
	// derived from who the attacker is, which no document says
	for _, x := range []struct {
		a  lint.Attacker
		qs []Quote
		os []lint.Observation
	}{
		{lint.AttackerMaintainerOfCalled, []Quote{actionCompromise, tagMoved}, nil},
		{lint.AttackerForkerOfCalled, []Quote{networkCommits}, []lint.Observation{sawForkCommit}},
		{lint.AttackerImagePublisher, []Quote{dockerTags}, nil},
		{lint.AttackerDestinationHolder, []Quote{curlHeader}, nil},
	} {
		for _, r := range Roles() {
			row := pathway(x.a, r, lint.Condition{}, true, x.qs...)
			row.Observed = x.os
			p = append(p, row)
		}
	}
	// advisory-attacker: who it is differs from one advisory to another
	for _, r := range Roles() {
		p = append(p, Pathway{Attacker: lint.AttackerAdvisoryAttacker, Role: r, Usable: expr.TruthUnknown, Basis: BasisUnverified, Uncertainty: unknownAdvisory})
	}
	return p
}

// pathwayRows are which roles get at a run of the workflow the way each
// attacker with no event does.
var pathwayRows = pathwayList()
