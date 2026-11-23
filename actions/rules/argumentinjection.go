package rules

import (
	"context"
	"fmt"
	"slices"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// ArgumentInjection is the rule argument-injection: a value an attacker
// controls begins a word a command of a run of bash or sh gets, where the
// command reads a word that begins with - as an option, and the command has
// an option seen to run a program written in it in the spelling the
// attacker can write.
// It reads the value through ${{ }} and through a variable of env, so that
// code-injection's fix, which moves the first into the second, leaves the
// same finding.
var ArgumentInjection lint.Rule = withExamples(lint.WithView[ir.ArgumentInjectionReader](argumentInjection{}, ir.ArgumentInjectionView))

// ArgumentInjectionID is the ID of argument-injection.
var ArgumentInjectionID = lint.MustRuleID("argument-injection")

type argumentInjection struct{}

func (argumentInjection) Meta() lint.Meta { return argumentInjectionMeta }

func (argumentInjection) Check(_ context.Context, c *lint.RuleContext, v ir.ArgumentInjectionReader) error {
	for _, s := range v.Sinks() {
		seen := map[string]int{}
		for _, a := range s.Arguments() {
			if !a.Known || !a.Runs || !a.OptionPlace {
				continue // other-command, no option that runs a program, or not where the command reads options
			}
			if len(a.Spelled) == 0 && !a.Remote && !a.Unverified {
				continue // every spelling the attacker can write is seen not to run a program (bash "$X")
			}
			key := fmt.Sprintf("%s#%d#%s", a.Command, a.Word, a.Path)
			seen[key]++
			anchor := fmt.Sprintf("%s#%d", key, seen[key])
			at := c.At(a.At)
			note := func(why string) string {
				return fmt.Sprintf("%s gets %s at a place where %s reads a word that starts with - as an option; %s", a.Command, a.Ref.Text, a.Command, why)
			}
			evidence, related := valueEvidence(c, a.Ref, a.Ref.Text)
			switch {
			case a.Ref.Verdict == analysis.Inconclusive:
				c.Inconclusive(lint.InconclusiveDraft{KindID: inconclusiveKind(a.Ref.InconclusiveKind), Location: at,
					Note: note(fmt.Sprintf("whether an attacker controls the value is not analyzed (%s)", a.Ref.InconclusiveKind))})
			case len(a.LeadingDash) == 0 && len(a.DashUndecided) == 0:
				// known not to begin with -, whatever the word before the value
				// is: the title of a wiki page holds no -, and a
				// label or a full name begins with a login (dash-login,
				// written-label)
			case a.Undecided:
				c.Inconclusive(lint.InconclusiveDraft{KindID: undeclaredOptionKind, Location: at, Related: slices.Concat(evidence, related),
					Note: note("the word before the value is an option that the linter's table of commands does not declare, and that option may take the attacker's word as the option's argument")})
			case len(a.LeadingDash) == 0:
				c.Inconclusive(lint.InconclusiveDraft{KindID: valueHeadKind, Location: at, Related: slices.Concat(evidence, related),
					Note: note("whether an attacker can make the value start with - is not known")})
			case len(a.Spelled) > 0:
				f := lint.FindingDraft{Location: at, Anchor: anchor, Evidence: evidence, Related: related,
					Args: ArgumentInjectionOption{Command: a.Command, Options: a.Spelled, ExprRef: a.Path, ControlledOn: eventsOf(a.LeadingDash)}}
				if onlyGollum(a.LeadingDash) {
					f.Args = ArgumentInjectionWiki{Command: a.Command, Options: a.Spelled, ExprRef: a.Path}
					f.Condition = wikiOpenCond(c)
				}
				c.Report(f)
				if onlyGollum(a.LeadingDash) && len(withoutGollum(a.DashUndecided)) > 0 {
					// the finding holds only where the wiki is open; on
					// another event the value may still begin with -
					c.Inconclusive(lint.InconclusiveDraft{KindID: valueHeadKind, Location: at, Related: slices.Concat(evidence, related),
						Note: note("whether an attacker can make the value start with - on an event other than gollum is not known")})
				}
			case a.Remote && a.RemoteSSH:
				c.Inconclusive(lint.InconclusiveDraft{KindID: remoteProgramKind, Location: at, Related: slices.Concat(evidence, related),
					Note: note(fmt.Sprintf("the option --upload-pack of %s runs the program in the value on the remote host of the SSH remote that %s names, not on the runner; the rule does not decide what a program on that host can reach", a.Command, a.Command))})
			case a.Remote:
				c.Inconclusive(lint.InconclusiveDraft{KindID: remoteProgramKind, Location: at, Related: slices.Concat(evidence, related),
					Note: note(fmt.Sprintf("the option --upload-pack of %s runs the program in the value on the machine that holds the repository that %s reads: on the runner for a repository on a local path, on the remote host for an SSH remote, and nowhere for an HTTPS remote; which repository %s reads is decided at run time", a.Command, a.Command, a.Command))})
			case a.Unverified:
				c.Inconclusive(lint.InconclusiveDraft{KindID: unverifiedOptionKind, Location: at, Related: slices.Concat(evidence, related),
					Note: note(fmt.Sprintf("whether an option of %s runs a program from a form of the value that an attacker can write is not known; no test by the authors of the linter has seen the program run or not run", a.Command))})
			}
		}
	}
	return nil
}

// observedRepositoryName is the date on which GitHub was seen to take, by a
// rename, a name of a repository that begins with -.
var observedRepositoryName = lint.MustDate("2026-10-16")

// observedPageName and runnerPageName are of the wiki pages made on the
// web interface whose names (page_name) were seen.
var observedPageName, runnerPageName = lint.MustDate("2026-11-06"), lint.MustVersion("2.338.2")

// argumentKinds are the kinds of argument-injection.
var argumentKinds = []lint.FindingKindID{kindArgumentInjectionOption, kindArgumentInjectionWiki}

var (
	observedArgument = lint.MustDate("2026-10-15")

	getoptManual  = lint.MustCitation("https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man3/getopt.3?h=man-pages-6.9")
	gitCLI        = lint.MustCitation("https://github.com/git/git/blob/c44beea485f0f2feaf460e2ac87fdd5608d63cf0/Documentation/gitcli.adoc")
	gitUploadPack = lint.MustCitation("https://github.com/git/git/blob/c44beea485f0f2feaf460e2ac87fdd5608d63cf0/Documentation/fetch-options.adoc")
	tarManual     = lint.MustCitation("https://github.com/mirror/tar/blob/e545d446dfe6564265cdf4186641ee76f4acc7fa/doc/tar.1")
	sedManual     = lint.MustCitation("https://github.com/mirror/sed/blob/7e2e575a36bc88c0f3f3d6d8083c5f5b0ed44009/doc/sed.texi")
	makeManual    = lint.MustCitation("https://github.com/mirror/make/blob/d66a65ad5a0e31b287f53930b0f09e31801f1613/doc/make.texi")
	githubHeadRef = lint.MustCitation("https://github.com/github/docs/blob/0226a2d78cf2be40ee3d769ec5661638461af0cc/content/actions/reference/workflows-and-actions/contexts.md")

	optionAnywhere    = lint.MustPreconditionID("option-anywhere")
	optionRunsProgram = lint.MustPreconditionID("option-runs-program")
	attackerDash      = lint.MustPreconditionID("attacker-dash")

	remoteProgramKind    = lint.MustInconclusiveKindID("remote-program")
	unverifiedOptionKind = lint.MustInconclusiveKindID("unverified-option")
	undeclaredOptionKind = lint.MustInconclusiveKindID("undeclared-option")
	valueHeadKind        = lint.MustInconclusiveKindID("value-head")
)

// argumentBase is the CVSS of argument-injection.option: code-injection's,
// as the program runs in the step; what it reaches is what the step can.
var argumentBase = lint.CVSS{
	AV: metric(lint.AttackVectorNetwork, "the attacker names a branch, or writes a title or a comment, over the network"),
	AC: metric(lint.AttackComplexityLow, "the attacker needs only to write an option and the name of a program or a command in the value"),
	AT: metric(lint.AttackRequirementsNone, "on a public repository anyone can open a pull request from a fork or write an issue"),
	PR: metric(lint.PrivilegesRequiredNone, "nothing of the repository is needed"),
	UI: metric(lint.UserInteractionNone, "the event runs the workflow with nobody doing anything"),
	VC: metric(lint.ImpactHigh, "the program reads what the step can reach: the secrets and the token in its env, the credentials actions/checkout leaves in .git/config, and with sudo on a GitHub-hosted runner the memory of the job's runner"),
	VI: metric(lint.ImpactHigh, "with the token and the secrets the step reaches the program can push, and write releases, artifacts and caches"),
	VA: metric(lint.ImpactLow, "the program can fail or stop the job"),
	SC: metric(lint.ImpactHigh, "the secrets open what is past the job: clouds, registries, other repositories"),
	SI: metric(lint.ImpactHigh, "what the job publishes reaches those who use it"),
	SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
}

var argumentInjectionMeta = lint.Meta{
	ID:       ArgumentInjectionID,
	Problem:  "an attacker's value is passed to a command so that a word the command gets starts with the attacker's value; the command reads a word that starts with - as an option, and some options make the command run a program or code that is written after the name of the option",
	Expected: "the command never reads the attacker's value as an option: the value is inside double quotes, and either the value comes after the word that ends the command's options (-- for most commands, --end-of-options for git), or, when the value starts with -, the step exits with an error before the step runs the command",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessArgumentInjection}, AttackMeans: []lint.AttackMeans{lint.AttackMeansString}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textArgumentInjectionOption,
			Attackers:       []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerMergedCommitAuthor, lint.AttackerAnyoneWhoForks},
			Preconditions:   []lint.PreconditionID{optionAnywhere, optionRunsProgram, attackerDash, attackerEvent, callersEvents, appStatusCheck},
			CVSS:            argumentBase,
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report was found of an attacker's value read as an option of a command in a workflow's run that ran a program (searched 2026-10-15: GitHub Security Lab's advisories, and the GitHub Advisory Database's actions ecosystem and CWE-88)"),
		},
		{
			FindingText:     textArgumentInjectionWiki,
			Attackers:       []lint.Attacker{lint.AttackerWikiEditor},
			Preconditions:   []lint.PreconditionID{optionAnywhere, optionRunsProgram, attackerDash, attackerEvent, callersEvents, wikiOpen},
			FactKinds:       []facts.Kind{facts.KindRepoWikiOpen},
			CVSS:            wikiOf(argumentBase, "a + and an option with a program"),
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report was found of an attack through the name of a wiki page"),
		},
	},
	Threat: lint.Threat{
		Actors: injectionActors(jobGains),
		Preconditions: []lint.Precondition{
			{
				ID:   optionAnywhere,
				Text: "a command reads a word that begins with - as an option up to --; tar, sed, make and git fetch, clone and pull read one after their operands too, and bash, sh, dash and python stop at the code of -c",
				Observed: []lint.Observation{
					{Date: observedArgument, Runner: runner, What: "sed, tar, make and git fetch, clone and pull read as an option a word after their operands; bash, sh, dash and python3 read none after the code of -c, and gawk none after its program"},
				},
				Cites: []lint.Citation{getoptManual, gitCLI},
			},
			{
				ID:   optionRunsProgram,
				Text: "the option runs the program written in its value, in the spelling the attacker writes: one word with blanks (a value inside quotes), one without (a branch's name, or a value outside quotes), or two words (a value outside quotes split at a blank)",
				Observed: []lint.Observation{
					{Date: observedArgument, Runner: runner, What: "a value passed through env and inside quotes ran a program as --to-command= and --use-compress-program= of tar, --expression= of sed, --eval= of make and --upload-pack= of git ls-remote, fetch, clone and pull with a local repository; a value outside quotes ran one as --to-command= of tar and --expression= of sed in one word, and as -c of bash, sh and dash, -c of python3, -e of node and perl in two words"},
				},
				Cites: []lint.Citation{tarManual, sedManual, makeManual, gitUploadPack},
			},
			{
				ID:   attackerDash,
				Text: "the value is one an attacker writes, the name of a pull request's head branch, the name of a repository an attacker names, or the name of a wiki page (page_name), each of which may begin with -: GitHub took a push of a branch named --upload-pack=... and a pull request from it, and one from a fork's branch named --fork-dash-probe, and github.head_ref had the names; GitHub took the rename of a repository to -dash-probe; for a wiki page made on the web interface, GitHub turns each +, < and > of the title into a - in the name of the page, and each blank of the title into a - after trimming the blanks at the head and the end of the title",
				Observed: []lint.Observation{
					{Date: observedArgument, Runner: runner, What: "a branch named --upload-pack=echo${IFS}ARGPROBE-RAN>&2;false was pushed, a pull request from it opened, and git ls-remote \"$HEAD_REF\" /tmp/r with HEAD_REF from github.head_ref ran the echo; a pull request from a fork's branch --fork-dash-probe gave github.head_ref --fork-dash-probe"},
					{Date: observedRepositoryName, What: "a rename of a fork through the REST API to -dash-probe gave the repository that name; the name cp, a line break and x became cp-x, and the name a$(id)`b`;c became a-id-b-c"},
					{Date: observedPageName, Runner: runnerPageName, What: "a wiki page made on the web interface with a title that began with +ws2<9>r gave github.event.pages[0].page_name that began with -ws2-9-r. For another page, whose title had a blank at the head and a blank at the end, GitHub trimmed the two blanks from the title and the name"},
				},
				Cites: []lint.Citation{githubHeadRef},
			},
			attackerEventPre,
			appStatusCheckPre,
			callersEventsPre,
			wikiOpenPre,
		},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	InconclusiveKinds: withRemoteCalleeUnknown(append([]lint.InconclusiveKind{
		{ID: remoteProgramKind, Text: "an option whose program runs on the machine that holds the repository that git reads (--upload-pack of git fetch, clone, pull and ls-remote), where the command names an SSH remote, or no word written in the script (not a variable) before the attacker's value names the repository: for a repository on a local path the program runs on the runner, for an SSH remote the program runs on the remote host, and for an HTTPS remote no program runs. The rule reports a repository on a local path as a finding and reports nothing for an HTTPS remote. When the command names no repository, the repository comes from the settings of the repository at run time (when git fetch reads \"$X\" as an option, git fetch names no repository and reads the remote origin). When the attacker's value can hold blanks and is outside quotes, the attacker can write the repository too, and the rule reports a finding. The rule does not decide what a program on the remote host can reach", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: unverifiedOptionKind, Text: "a command with an option that the linter's table of commands declares to run code or a program, where no test by the authors of the linter has seen whether the option runs the program when the value has a form that an attacker can write. A value such as github.event.pull_request.head.repo.name, the name of a repository, is of this kind for tar: the name holds only ASCII letters, digits, ., - and _, and can be -I followed by the name of a program (-Ipython3); tar then starts that program with the single argument -d and the archive on the standard input of the program, and the attacker writes only the name of the program, not the arguments of the program. Whether a program started in that way does harm depends on the content of the archive, and no test by the authors of the linter has checked that", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: undeclaredOptionKind, Text: "the value after an option the table of commands does not declare, which may take the value as its own", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: valueHeadKind, Text: "a value an attacker shapes, for which the linter does not know whether the value can begin with -: a URL, an email, the name of a default branch, the head branch of a workflow_run. The title of a wiki page is not of this kind: the title holds no -, so the title cannot begin with -, and the rule reports nothing on the title. The label (owner:branch) of the head of a pull request and the full name (owner/name) of a repository are not of this kind: the label and the full name begin with the login of an account; when the authors of the linter tried on 2026-11-01, GitHub refused a login that begins with - at sign-up and at a rename, so the rule assumes that the label and the full name do not begin with -, and the rule reports nothing on the label or the full name (a label or a full name of an older account whose login begins with - is the undetected form dash-login)", Disposition: lint.Todo(lint.NeedSameFile)},
	}, valueGaps...)),
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		wikiSummaryLimit,
		forkReviewLimit,
		{ID: lint.MustUndetectedFormID("program-argument"), Text: "a value in an argument the command reads as a program of its own: the script of sed (with its e command), the program of awk; what CodeQL's argument injection reports", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("other-option"), Text: "an option not seen to run a program that does other harm: a file it writes (curl -o, git diff --output), files it deletes (find -delete), refs it overwrites (git push --mirror), and --receive-pack of git push and --exec of git archive, which were not seen to run", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("other-command"), Text: "a command the table of commands does not have, or one with no option that runs a program", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("shell-derived"), Text: "a value the script makes: an assignment, $( ), a function's argument ($1), standard input, xargs", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("env-file-variable"), Text: "a variable a step before sets through $GITHUB_ENV: the rule reads the variables of the workflow's env", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("empty-prefix"), Text: "a value after another expansion in the same word that may be empty (\"${P}$X\"), or after a word whose text is not known that may be empty or an option ($OPTS \"$X\")", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("param-operator"), Text: "a variable with an operator that changes its value (${X#prefix}, ${X/a/b})", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("command-word"), Text: "a value that is the command's name ($CMD args), or an argument of a wrapper whose words are not known (env A=\"$X\" tar)", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("unwalked-place"), Text: "a command in a place the rule does not walk: $( ) in the words of case", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("unread-command"), Text: "a command in a part of the script that the parser of the script does not read: the commands of each clause of case, $( ) inside the ( ) of the assignment of an array, and the code that another shell reads from the argument of -c (bash -c '...')", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("rewritten-url"), Text: "an HTTPS URL that git rewrites to a local path or to an SSH remote by the setting url.<base>.insteadOf (git config): the rule takes the URL as written in the script, without the git config commands that run earlier in the script, and reports nothing for an HTTPS remote", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("make-variable"), Text: "a value passed to make in a word of the form NAME=value, where the word need not start with -: make reads such a word as the assignment of a variable even after --, and the value of the variable can change a command that a rule of the makefile runs (CC=...)", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("dash-login"), Text: "the label (owner:branch) of the head of a pull request, or the full name (owner/name) of a repository, where the login of the owner begins with -: when the authors of the linter tried on 2026-11-01, GitHub refused a login that begins with - at sign-up and at a rename, but accounts with such a login remain from earlier, and the rule assumes that the label and the full name do not begin with -. On 2026-11-01 the user search of GitHub found 9 accounts whose login begins with -, all made in 2009: the 36 searches for - followed by a letter or a digit (gh api 'search/users?q=%22-a%22+in:login' for -a, and the same search for -b to -z and for -0 to -9) found 8 accounts in all, and the search gh api 'search/users?q=%22-%22+in:login' for - alone found 1 more account, the account whose login is - (a search word of two or more characters matches the start of a login, and a search word of one character matches the whole login). The 9 accounts are users. When the authors of the linter tried on 2026-11-01 to create an organization whose name begins with - on the web, GitHub removed the leading - from the login of the organization; the creation of an organization through the API was not tried", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustUndetectedFormID("written-label"), Text: "the label (owner:branch) of the head of a pull request written into the script with ${{ }} (tar -xf archive.tar notes.txt ${{ github.event.pull_request.head.label }}): the runner writes the label into the script before the shell reads the script, and the attacker can write ${IFS} in the name of the branch, so, when the label is outside quotes, a word after the first word of the label can begin with -. The rule code-injection of this linter reports the same ${{ }}, and the fix of code-injection, which moves the label to a variable of env inside double quotes, passes the label as one word, owner:branch, which begins with the login. The attacker can also write $( ) in the name of the branch; in the script written with ${{ }}, the shell runs that $( ) even inside double quotes (\"${{ ... }}\"), so the attacker already writes code that the shell runs, and a word that the command reads as an option gives the attacker nothing more. Through a variable of env inside double quotes, the shell does not split the label, so the label stays one word that begins with the login. Through a variable of env outside quotes, the shell splits the label at the characters of IFS, which are blanks by default, and the name of a branch holds no blank, so the label also stays one word (a script that changes IFS is the undetected form changed-ifs). The full name holds no $, no quote and no blank, so the full name written with ${{ }} is also one word that begins with the login", Disposition: lint.OtherRule(CodeInjectionID)},
		{ID: lint.MustUndetectedFormID("changed-ifs"), Text: "a value outside quotes in a script that sets IFS (IFS=:): the shell splits a value outside quotes at the characters of IFS, so a part of the value after the first part can begin with -, such as the name of the branch in the label (owner:branch) of the head of a pull request with IFS=:, or the name of the repository in a full name (owner/name) with IFS=/. The rule assumes that the shell splits a value outside quotes at blanks only, and the rule does not read an assignment to IFS in the script", Disposition: lint.Todo(lint.NeedSameFile)},
		otherShellLimit,
		pullRequestLimit,
		dispatchLimit, repositoryDispatchLimit, appWrittenLimit, deploymentStatusLimit, dispatchRelayLimit, dispatchInputCallLimit,
		outsideCallerLimit,
		notAttackerLimit,
		mergedPusherLimit,
		comparedLimit,
		newActivityTypeLimit,
		insiderAssociationLimit,
	}),
	FalsePositiveForms: withCallee([]lint.FalsePositiveForm{
		forkFlagReview(kindArgumentInjectionOption),
		{ID: lint.MustFalsePositiveFormID("posixly-correct"), Text: "sed in a step whose env sets POSIXLY_CORRECT, with the value after its first operand: sed then reads no option there (tar and make still do)", FindingKinds: argumentKinds, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("tar-old-options"), Text: "tar whose first word does not begin with - (tar xf \"$X\"): the f of the old options takes the next word as the archive", FindingKinds: argumentKinds, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("checked-earlier"), Text: "a script that stops before the command when the value begins with -, and passes the value to the command inside double quotes: the rule does not read the flow of the script", FindingKinds: argumentKinds, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("unknown-word-option"), Text: "a word that the same script decides, such as $1 of a function that the script calls with an option, or a variable to which the script assigns an option, where the option takes the next word, the attacker's, as its value: the command then does not read the attacker's value as an option", FindingKinds: argumentKinds, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("run-time-word-option"), Text: "a word that is an option taking the next word, the attacker's, as its value, when the text of the option is decided at run time, such as the output of $(cmd) that reads the state of the runner: the command then does not read the attacker's value as an option", FindingKinds: argumentKinds, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustFalsePositiveFormID("macos-runner"), Text: "sed or make, or tar with the value after the operands of tar, in a step of a job that runs on a macOS runner (runs-on: macos-latest), when the step runs the commands that the runner has by default: tar is bsdtar, which reads a word after its operands as a name of a file; sed is the sed of BSD, which has no e command; make is GNU make 3.81, which has no --eval. A value at the place of options of bsdtar is not this form: bsdtar has --use-compress-program, which runs a program, and the rule reports that place as a finding. git on the runner reads --upload-pack as on Linux", FindingKinds: argumentKinds, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("busybox-tools"), Text: "tar or sed in a step of a job whose container is the image alpine (container: alpine:3), whose BusyBox is built without the option --to-command of tar: the tar of that BusyBox has no option that runs a program, and the sed of BusyBox has no e command. Other builds of BusyBox, such as the image busybox, have --to-command. When the step installs GNU make in the container, make reads --eval as GNU make does on an Ubuntu runner", FindingKinds: argumentKinds, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("reassigned-variable"), Text: "a variable of env, or a variable that the runner writes (GITHUB_HEAD_REF), that the script sets again before the command (H=main; tar ... \"$H\"): the rule reads the value of env or the value that the runner writes", FindingKinds: argumentKinds, Disposition: lint.Todo(lint.NeedSameFile)},
		writerString(argumentKinds...), ifUnnarrowedFalsePositive(argumentKinds...),
	}, kindArgumentInjectionOption, kindArgumentInjectionWiki),
}
