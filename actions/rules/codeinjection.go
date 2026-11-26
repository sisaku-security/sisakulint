package rules

import (
	"context"
	"fmt"
	"slices"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// CodeInjection is the rule code-injection: a value an attacker controls,
// written into a step's run or the script of actions/github-script by
// ${{ }}. The runner writes the value into the script before the shell or
// JavaScript reads it, so the value is code. Also a variable of env (or one
// the runner writes) whose value an attacker controls and that a run of bash
// reads as code (shell.VariableCodes): eval, the code after -c, the command
// name, the input of a shell, arithmetic. Only the events on which an
// attacker gets what they do not have count (actions/taint).
var CodeInjection lint.Rule = withExamples(lint.WithView[ir.CodeInjectionReader](codeInjection{}, ir.CodeInjectionView))

// CodeInjectionID is the ID of code-injection.
var CodeInjectionID = lint.MustRuleID("code-injection")

type codeInjection struct{}

func (codeInjection) Meta() lint.Meta { return codeInjectionMeta }

func (codeInjection) Check(_ context.Context, c *lint.RuleContext, v ir.CodeInjectionReader) error {
	for _, s := range v.Sinks() {
		reportCallsNotRead(c, s.CallsNotRead())
		seen := anchors{}
		kind := s.Kind()
		for i, r := range s.Refs() {
			if r.Verdict == analysis.Controlled && r.QuotedJSON {
				continue
			}
			o := s.RefFix(i)
			anchor := seen.next(r.Text, o)
			at := c.At(r.At)
			switch r.Verdict {
			case analysis.Controlled:
				evidence, related := valueEvidence(c, r, r.Text)
				f := lint.FindingDraft{
					Location: at,
					Args:     CodeInjectionControlled{ExprRef: r.Text, SinkKind: kind, ControlledOn: eventsOf(r.ControlledOn)},
					Anchor:   anchor, // one scalar can have several: which one, and which of the same text
					Evidence: evidence,
					Related:  related,
				}
				if onlyGollum(r.ControlledOn) {
					f.Args = CodeInjectionWiki{ExprRef: r.Text, SinkKind: kind}
					f.Condition = wikiOpenCond(c)
				}
				withFix(&f, o)
				c.Report(f)
			case analysis.Inconclusive:
				c.Inconclusive(lint.InconclusiveDraft{KindID: inconclusiveKind(r.InconclusiveKind), Location: at,
					Note: fmt.Sprintf("%s is written into %s by ${{ }}; whether an attacker controls it is not analyzed (%s)", r.Text, textSinkKind(kind), r.InconclusiveKind)})
			}
		}
		for _, vc := range s.VariableCodes() {
			checkVariableCode(c, vc, seen)
		}
	}
	return nil
}

// checkVariableCode reports vc, a variable of env whose value a run of bash
// reads as code: as the ${{ }} are, by whether an attacker controls the
// value of env, and on gollum alone with the condition of the wiki. A
// variable's finding has no fix (code-injection.env-variable declares none):
// what eval or the code of -c does with the value is the script's.
func checkVariableCode(c *lint.RuleContext, vc ir.VariableCode, seen anchors) {
	r := vc.Ref
	at := c.At(vc.At)
	anchor := seen.next(vc.Text, ir.FixPlan{})
	switch r.Verdict {
	case analysis.Controlled:
		evidence, related := valueEvidence(c, r, vc.Text)
		f := lint.FindingDraft{
			Location: at,
			Args:     CodeInjectionEnvVariable{Variable: vc.Text, ExprRef: vc.Path, CodeReading: vc.Reading, ControlledOn: eventsOf(r.ControlledOn)},
			Anchor:   anchor,
			Evidence: evidence,
			Related:  related,
		}
		if onlyGollum(r.ControlledOn) {
			f.Args = CodeInjectionEnvVariableWiki{Variable: vc.Text, ExprRef: vc.Path, CodeReading: vc.Reading}
			f.Condition = wikiOpenCond(c)
		}
		c.Report(f)
	case analysis.Inconclusive:
		c.Inconclusive(lint.InconclusiveDraft{KindID: inconclusiveKind(r.InconclusiveKind), Location: at,
			Note: fmt.Sprintf("the script of the step (run:) passes the value of the variable %s to %s; whether an attacker controls the value that env gives the variable is not analyzed (%s)", vc.Text, textCodeReading(vc.Reading), r.InconclusiveKind)})
	}
}

var (
	observedInjection = lint.MustDate("2026-09-25")

	scriptInjections = lint.MustCitation("https://docs.github.com/en/actions/concepts/security/script-injections")
	mitigating       = lint.MustCitation("https://docs.github.com/en/actions/reference/security/secure-use#good-practices-for-mitigating-script-injection-attacks")
	ultralytics      = lint.MustCitation("https://github.com/ultralytics/ultralytics/issues/18027#issuecomment-2521480630")

	// the runs of bash with the value of a variable at each reading
	observedVariableCode = lint.MustDate("2026-10-31")
	bashOperation        = lint.MustCitation("https://www.gnu.org/software/bash/manual/html_node/Shell-Operation.html")
	bashEval             = lint.MustCitation("https://www.gnu.org/software/bash/manual/html_node/Bourne-Shell-Builtins.html")
	radwareCampaign      = lint.MustCitation("https://www.radware.com/blog/inside-a-github-supply-chain-attack-campaign/")
)

var (
	// the preconditions and the incident of code-injection's threat, which
	// its kinds refer to
	runnerWrites    = lint.MustPreconditionID("runner-writes")
	valueReadAsCode = lint.MustPreconditionID("value-read-as-code")
	attackerWrites  = lint.MustPreconditionID("attacker-writes")
	ultralytics2024 = lint.MustIncidentID("ultralytics-2024")
)

// controlledBase is the CVSS of code-injection.controlled.
var controlledBase = lint.CVSS{
	AV: metric(lint.AttackVectorNetwork, "the attacker writes an issue, a comment or a pull request over the network"),
	AC: metric(lint.AttackComplexityLow, "a quote and a command in the text are all it takes"),
	AT: metric(lint.AttackRequirementsNone, "on a public repository anyone can open an issue or a pull request from a fork"),
	PR: metric(lint.PrivilegesRequiredNone, "nothing of the repository is needed"),
	UI: metric(lint.UserInteractionNone, "issues and comments trigger the workflow with nobody doing anything; the worst case of the rule (a commit message needs a merge)"),
	VC: metric(lint.ImpactHigh, "the code reads the job's secrets and GITHUB_TOKEN"),
	VI: metric(lint.ImpactHigh, "with the job's token the code can push, and write releases, artifacts and caches; in the Ultralytics incident it published to PyPI", ultralytics),
	VA: metric(lint.ImpactLow, "the code can fail or stop the job"),
	SC: metric(lint.ImpactHigh, "the secrets open what is past the job: clouds, registries, other repositories"),
	SI: metric(lint.ImpactHigh, "what the job publishes (releases, packages) reaches those who use it"),
	SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
}

// envVariableBase is the CVSS of code-injection.env-variable: what the code
// does in the job is that of controlledBase.
var envVariableBase = func() lint.CVSS {
	b := controlledBase
	b.AC = metric(lint.AttackComplexityLow, "a command substitution or a command in the text, which the run reads as code through the variable, is all it takes")
	b.UI = metric(lint.UserInteractionNone, "issues and comments trigger the workflow with nobody doing anything")
	b.VI = metric(lint.ImpactHigh, "with the job's token the code can push, and write releases, artifacts and caches")
	return b
}()

// wikiBase is the CVSS of code-injection.wiki: the attacker gets there by
// an edit of the wiki; what the code does in the job (VC to SA) is that of
// controlledBase.
var wikiBase = wikiOf(controlledBase, "a quote and a command")

var codeInjectionMeta = lint.Meta{
	ID:       CodeInjectionID,
	Problem:  "a value an attacker controls is written by ${{ }} into a run script or the script of actions/github-script, where it runs as code; or the script of a run of bash passes such a value, through a variable of env, to a command or a place that reads the value as code",
	Expected: "no value an attacker controls is written by ${{ }} into such a script where it runs as code, and no script passes such a value, through a variable of env, to a command or a place that reads the value as code",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessScriptInjection}, AttackMeans: []lint.AttackMeans{lint.AttackMeansString}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textCodeInjectionControlled,
			Attackers:       []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerMergedCommitAuthor, lint.AttackerAnyoneWhoForks},
			Preconditions:   []lint.PreconditionID{runnerWrites, attackerWrites, attackerEvent, callersEvents, appStatusCheck},
			Incidents:       []lint.IncidentID{ultralytics2024},
			Fixes:           []lint.FixKindID{EnvVarID, EnvVarReviewID},
			CVSS:            controlledBase,
			ExploitMaturity: metric(lint.ExploitMaturityAttacked, "in 2024-12 pull requests with commands in their branch names ran in a pull_request_target workflow of Ultralytics, which published malicious versions to PyPI", ultralytics),
		},
		{
			FindingText:     textCodeInjectionEnvVariable,
			Attackers:       []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerMergedCommitAuthor, lint.AttackerAnyoneWhoForks},
			Preconditions:   []lint.PreconditionID{valueReadAsCode, attackerWrites, attackerEvent, callersEvents, appStatusCheck},
			CVSS:            envVariableBase,
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report was found of an attack through a variable of env that a run reads as code; a report by Radware of 2026-10 warns, among its mitigations, that a value moved into env can be passed to eval and become code again", radwareCampaign),
		},
		{
			FindingText:     textCodeInjectionEnvVariableWiki,
			Attackers:       []lint.Attacker{lint.AttackerWikiEditor},
			Preconditions:   []lint.PreconditionID{valueReadAsCode, attackerEvent, callersEvents, wikiOpen},
			FactKinds:       []facts.Kind{facts.KindRepoWikiOpen},
			CVSS:            wikiOf(envVariableBase, "a command substitution and a command"),
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report was found of an attack through the title of a wiki page"),
		},
		{
			FindingText:     textCodeInjectionWiki,
			Attackers:       []lint.Attacker{lint.AttackerWikiEditor},
			Preconditions:   []lint.PreconditionID{runnerWrites, attackerEvent, callersEvents, wikiOpen},
			Fixes:           []lint.FixKindID{EnvVarID, EnvVarReviewID},
			FactKinds:       []facts.Kind{facts.KindRepoWikiOpen},
			CVSS:            wikiBase,
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report was found of an attack through the title of a wiki page"),
		},
	},
	Threat: lint.Threat{
		Actors: injectionActors(jobGains),
		Preconditions: []lint.Precondition{
			{
				ID:   runnerWrites,
				Text: "the runner writes the value of ${{ }} into the script before the shell or JavaScript reads it",
				Observed: []lint.Observation{
					{Date: observedInjection, Runner: runner, What: "a commit message with a quote and a command, written into run by ${{ }}, ran the command; an author name written into the script of actions/github-script ran as JavaScript"},
				},
				Cites: []lint.Citation{scriptInjections},
			},
			{
				ID:   valueReadAsCode,
				Text: "bash expands a variable after bash parses the script, so the value of the variable is not code to the bash that runs the script; the value becomes code where bash, or a program that bash gives the value to, reads the value again: an operand of eval, the code that a shell or an interpreter takes after -c, a program that git runs (git -c core.fsmonitor=...), a variable outside quotes as the command name at the start of a command (bash splits the value into words, and the first word names the program that runs), the input of a command that runs the input as code, and arithmetic (a value such as a[$(...)] holds an array subscript whose command substitution runs)",
				Observed: []lint.Observation{
					{Date: observedVariableCode, What: "a test ran a script for each of those places with GNU bash 5.3.15, with the variable V set to a value that held a command that creates a file, and the file appeared; where the script reads the value as data (echo \"$V\", echo $V, A=$V, the body of a heredoc that cat reads), none of the values created the file"},
				},
				Cites: []lint.Citation{bashOperation, bashEval},
			},
			attackerWritesPre,
			attackerEventPre,
			appStatusCheckPre,
			callersEventsPre,
			wikiOpenPre,
		},
		Incidents: []lint.Incident{
			{ID: ultralytics2024, Date: lint.MustDate("2024-12-04"), Advisory: ultralytics,
				Compromised: repos("ultralytics/ultralytics"),
				Summary:     "pull requests whose branch names held a command ran it in a workflow that wrote the branch name into run; ultralytics 8.3.41 and 8.3.42 on PyPI carried a miner"},
		},
	},
	Citations: []lint.Citation{mitigating, cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	FixKinds:  stepFixKinds,
	UndetectedForms: withRemoteCallee(append([]lint.UndetectedForm{
		wikiSummaryLimit,
		forkReviewLimit,
		ifComparedLimit,
		{ID: lint.MustUndetectedFormID("if"), Text: "an expression in an if: the runner evaluates it, and no shell or JavaScript reads it", Disposition: lint.NoAddedGain()},
		{ID: lint.MustUndetectedFormID("env-value"), Text: "an expression in a value of env, whose variable a run of bash or sh reads only where the value stays data: inside double quotes, or outside quotes, as an argument of a command that reads the argument as data (echo \"$TITLE\"); in an assignment; in the body of a heredoc that a command reads as data; or no script reads the variable. bash expands the variable after bash parses the script, and the command reads the value as text. The rule reports the variable where bash, or a program, reads the value as code (code-injection.env-variable). This undetected form is only for a value that no command writes into a file that a later command or step runs as code; a value written into such a file is the undetected form written-file", Disposition: lint.NoAddedGain()},
		{ID: lint.MustUndetectedFormID("env-variable-command-name"), Text: "a variable of env inside quotes as the command word of a run of bash (\"$TOOL\" --version): the value names the program that runs, with the arguments that the script writes. Whether an attacker can cause harm by naming a program that the runner has was not checked", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("env-variable-source"), Text: "a variable of env as the file name of source or . in a run of bash (source \"$FILE\"): the value names the file whose text runs as code. The rule reads the commands source and . (dot) only where the file name is the literal text /dev/stdin, and the value of the variable comes in as the input (code-input); whether an attacker can name a file that holds code on the runner was not checked", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("env-variable-nested"), Text: "a variable of env at a place of a run of bash that the rule does not follow: the old arithmetic expansion $[ ], the patterns and the commands of each clause of case, a heredoc that starts inside $( ), the line where the script leaves a quote or a heredoc open and the lines after it (bash runs the lines after a heredoc that is not closed); and the script that another shell reads from the body of a heredoc whose delimiter is quoted, or from code after -c that the rule does not read as a script of its own, where that shell expands the variable: code that is not one word in single quotes (bash -c 'eval \"$V\"'\"x\"), the code of sh -c, the arguments after the code that the shell reads as $1 and the like (bash -c 'eval \"$1\"' _ \"$V\"), a -c after an option of the shell the rule does not read (bash -x -o pipefail -c '...'), and a variable the script assigns before the command, whose new value that shell gets (T=\"pre-$T\"; bash -c 'eval \"$T\"')", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("env-variable-runs-argument"), Text: "a variable of env as an argument of a command that runs the argument as a command or as code, or in an assignment to an integer variable, where the rule's table of commands has no record that the value of a variable was seen to run as code with that command or option: xargs, find -exec, ssh, docker run with sh -c, and the code options of interpreters that the table does not list; and an assignment to a variable that declare -i, typeset -i or local -i gives the integer attribute, whose value bash reads as arithmetic; and the input of a shell or an interpreter that the rule does not read as code: after an option that the table does not declare (bash -o pipefail <<EOF), from a group of commands or a function before a pipe ({ echo \"$V\"; } | bash), or of an interpreter that the table does not declare as one that runs its input (node <<EOF)", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("env-variable-coproc"), Text: "a variable of env that a run of bash writes to the input of a coproc whose command runs the input of the coproc as code (coproc bash; echo \"$TITLE\" >&${COPROC[1]}), directly or through a descriptor number that the script copies or stores (exec 4>&${COPROC[1]}; echo \"$TITLE\" >&4, or fd=${COPROC[1]}; echo \"$TITLE\" >&$fd, or exec >&${COPROC[1]}; echo \"$TITLE\"): the rule does not read the input of a coproc as code for the value of a variable. For a ${{ }} written in a command whose redirect target holds an element of the coproc's array as a parameter (>&${COPROC[1]}), the rule gives no fix; for a ${{ }} written in a command that writes through a copied or stored descriptor number, or through arithmetic on the array ($((COPROC[1]))), the fix moves the value to env, and the injection stays after the fix in this form", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("associative-scope"), Text: "a variable of env in a subscript of an indexed array whose name a declare, typeset or local command of the script declares associative with -A where the declaration does not hold at the subscript: a declaration inside a function, a declaration after the subscript, a declaration followed by an unset of the name, or a declaration that bash refuses because the name already holds an indexed array (f() { declare -A m; }; m=(1); echo \"${m[$KEY]}\", or echo \"${m[$KEY]}\"; declare -A m, or declare -A m; unset m; m=(1); echo \"${m[$KEY]}\", or m=(1); declare -A m; echo \"${m[$KEY]}\"): the rule reads every name that such a command declares with -A as associative in the whole script, so the rule does not read the subscript as arithmetic. A ${{ }} written in such a subscript gets no fix", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("env-variable-structured"), Text: "a value of env that an attacker shapes only within a structured form (the name of a branch, a URL that GitHub builds, the name of a repository), read as the command name at the start of a command outside quotes, or in arithmetic: there the value runs as code only when the value has a space or a tab (the command name) or a [ (arithmetic). Git does not allow a space or [ in the name of a branch; the characters of the other values were not checked", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("env-variable-sh"), Text: "a variable of env in a run of sh (shell: sh, or a custom shell of sh such as sh -e {0}), or in a run whose shell the rule does not tell is bash (a shell: value of bash with an option that the rule does not read, such as bash -c 'make' {0}, a shell: value that names bash by a path on a runner that the rule does not know to have the path, a shell: that is an expression, or a runner that runs-on does not name, which can be a Windows runner, whose default shell is pwsh), read where bash reads the value as code: the rule reads the variables of runs of bash only, as the four ways in which bash reads the value of a variable as code (code_reading) were observed with bash only, and the sh of a runner can be another shell, such as dash", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("login-startup-file"), Text: "a value that an attacker controls and that a step writes to a startup file of a login shell (~/.bash_profile, ~/.bash_login, ~/.profile, or a file under /etc/profile.d), where a later step has a shell: value that starts bash as a login shell (-l, +l or --login): bash runs the startup file before the script of the later step, and the rule does not read the write to the startup file as a write of code", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("env-variable-other-language"), Text: "a variable of env that the script of actions/github-script, or a run of pwsh, cmd or python, reads as code of that language (eval(process.env.TITLE), Invoke-Expression $env:TITLE, exec(os.environ['TITLE'])): the rule reads the variables of runs of bash only", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("script-var"), Text: "a shell variable that a run of bash sets, and whose value the run then reads as code (X=$TITLE; eval \"$X\"; a value that read or $( ) gives), the output of a command substitution read as code (eval \"$(echo $TITLE)\"), a file that the script writes with the value and then runs (echo \"$TITLE\" > f.sh; bash f.sh), and a variable that an earlier step writes to the file $GITHUB_ENV, which the runner puts into the environment of the later steps: the rule reads a variable only where a key of env: (of the step, the job or the workflow) gives the value, or where the runner writes the variable in every step, and does not follow the value through the script", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("action-input-local"), Text: "an input of a local composite action (./, in the workspace of the job, which is the repository that the job checks out; $/, the repository of the action), in a run of the linter that does not read the action.yml of the composite action: a run that reads only the files named on the command line (without --read-all) and does not name the action.yml, a run that reads the workflow from standard input (--stdin-name), or a run that leaves out the directory of the action with --exclude. The rule reads what the composite action does with the input from the steps of the action.yml, and the rule reads the steps of the action.yml only when the run reads the action.yml. A local action that runs JavaScript or a Docker image is the undetected form repository-program", Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustUndetectedFormID("action-input-remote"), Text: "an input of an action of another repository, other than the script of actions/github-script: what the action does with it is in its action.yml, which the rule does not read", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("action-input-docker"), Text: "an input of a Docker image (docker://): the image reads it when it runs", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustUndetectedFormID("repository-program"), Text: "an attacker's value that a program of the repository reads and then misuses, for example by installing a package whose name is in the value or by writing a file at a path that is in the value: the program is a local action that runs JavaScript or a Docker image (which reads an input or the event payload), or a program that a run starts (node submit.js, which reads a variable of env). The rule reads the scripts of runs and of actions/github-script, not the code of other programs", Disposition: lint.Limitation(lint.DeciderRunTime)},
		pullRequestLimit,
		dispatchLimit, repositoryDispatchLimit, appWrittenLimit, deploymentStatusLimit, dispatchRelayLimit, dispatchInputCallLimit,
		outsideCallerLimit,
		{ID: lint.MustUndetectedFormID("fixed"), Text: "a context an attacker cannot shape into code: a SHA, a number, a date, the name of an account (github.actor, a login), a URL that GitHub builds from the name of an account or from the name of the repository the workflow runs in (github.event.sender.html_url, github.event.repository.html_url), and other values that GitHub or the repository sets (github.event.action, github.event.repository.default_branch)", Disposition: lint.NoAddedGain()},
		notAttackerLimit,
		mergedPusherLimit,
		comparedLimit,
		newActivityTypeLimit,
		{ID: lint.MustUndetectedFormID("tojson-heredoc"), Text: "toJson(...) as the whole of a ${{ }} in the body of a bash or sh heredoc that no shell or interpreter reads, whose delimiter is quoted and does not start with a space, a tab, {, }, [, ] or \": the body is taken as it is, and toJson writes no line that is the delimiter (as the runner's toJson writes JSON, 2.337.0). This undetected form is only for a heredoc whose file no command runs as code; a heredoc whose file a command runs as code is the undetected form written-file", Disposition: lint.NoAddedGain()},
		{ID: lint.MustUndetectedFormID("written-file"), Text: "a value that a command writes as data into a file, such as echo \"$TITLE\" > notes.sh or the body of a heredoc that cat writes to script.sh, where a later command or a later step runs the file as code (bash script.sh): the rule finds where bash takes a value as code inside the script of each run: step, and does not follow a value through a file", Disposition: lint.Todo(lint.NeedSameFile)},
		insiderAssociationLimit,
		remoteCompositeStepsLimit(codeInjectionInStepText, "A ${{ }} of an input (${{ inputs.<name> }}), whose value the step that uses the composite action gives, is declared as the undetected form action-input-remote (a composite action that a uses names) or action-input-local (a composite action that a path that starts with ./ names)"),
	}, checkedOutLocalLimits(codeInjectionInStepText)...)),
	InconclusiveKinds: withRemoteCalleeUnknown(withCallBodyUnknown(valueGaps)),
	FalsePositiveForms: withCallee(withEnvVariableKinds(append(injectionFalsePositives(kindCodeInjectionControlled, kindCodeInjectionWiki),
		lastpipeFalsePositive(kindCodeInjectionEnvVariable),
		nameNotLiteralFalsePositive(kindCodeInjectionEnvVariable),
		lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("git-config-value"), Text: "a variable inside quotes given to git -c as the value of a configuration key that git keeps as data but that the rule's list of data keys (user.name, user.email and the like) does not name, such as git -c merge.conflictStyle=\"$X\" merge: the rule reads the value of every key outside that list as code, as git runs the value of core.sshCommand, init.templateDir or imap.tunnel. Without the quotes, the shell splits the value of the variable into words, and a word of the value can add another -c with a key that names a program, so that form is not a false positive", FindingKinds: []lint.FindingKindID{kindCodeInjectionEnvVariable}, Disposition: lint.Todo(lint.NeedSameFile)},
		lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("associative-key-not-literal"), Text: "a key of an associative array that a declare, typeset or local command declares with an initial value written as a list in parentheses (declare -A m=([k]=v); echo \"${m[$KEY]}\"), where a variable of env is in the key: the rule reads the subscript as arithmetic, which bash does only for an indexed array, as the rule does not read which names such a command declares associative", FindingKinds: []lint.FindingKindID{kindCodeInjectionEnvVariable}, Disposition: lint.Todo(lint.NeedSameFile)},
		lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("sha-suffix"), Text: "a SHA whose name the table's **.sha does not match, such as merge_commit_sha, read as arbitrary", FindingKinds: []lint.FindingKindID{kindCodeInjectionControlled}, Disposition: lint.Todo(lint.NeedSameFile)},
		lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("repository-name"), Text: "the name of a repository, as the name by itself (github.event.pull_request.head.repo.name), as owner/name (github.event.pull_request.head.repo.full_name) or inside a URL that GitHub builds from owner/name (github.event.pull_request.head.repo.html_url), written inside quotes or as an argument, not as the name of a command. GitHub allows only ASCII letters, digits, ., - and _ in the name of a repository, and no shell or JavaScript reads these characters as code in those positions. The rule reports the value because the rule's table of the contexts an attacker controls puts the name of a repository, and a URL built from the name, in the class named structured, the class that the table also gives the name of a branch. The name of a branch can contain the characters $( ); the name of a repository cannot contain them", FindingKinds: []lint.FindingKindID{kindCodeInjectionControlled}, Disposition: lint.Todo(lint.NeedSameFile)},
	)), kindCodeInjectionControlled, kindCodeInjectionEnvVariable, kindCodeInjectionEnvVariableWiki, kindCodeInjectionWiki),
}

// withEnvVariableKinds is forms, the false positive forms of the kinds of
// ${{ }}, with the kinds of a variable of env too: those kinds read the same
// values (the verdict of the reference in the value of env), so the same
// harmless values give their findings.
func withEnvVariableKinds(forms []lint.FalsePositiveForm) []lint.FalsePositiveForm {
	for i, f := range forms {
		kinds := slices.Clone(f.FindingKinds)
		if slices.Contains(kinds, kindCodeInjectionControlled) {
			kinds = append(kinds, kindCodeInjectionEnvVariable)
		}
		if slices.Contains(kinds, kindCodeInjectionWiki) {
			kinds = append(kinds, kindCodeInjectionEnvVariableWiki)
		}
		forms[i].FindingKinds = kinds
	}
	return forms
}

// attackerWritesPre is that the value is one an attacker writes, a branch
// name among them: code-injection's, and envpath-injection's, which needs
// no line break.
var attackerWritesPre = lint.Precondition{
	ID:   attackerWrites,
	Text: "the value is one an attacker writes: a title, a body, a comment, a commit message, a branch name",
	Observed: []lint.Observation{
		{Date: observedInjection, Runner: runner, What: "GitHub accepted a branch named with $( ) and ${IFS}; written into run as github.head_ref, the command in it ran"},
	},
	Cites: []lint.Citation{scriptInjections},
}

// EnvVarID and EnvVarReviewID are the kinds of the fixes of the injection
// rules: the plan of the step (actions/ir, StepFix).
var (
	EnvVarID       = lint.MustFixKindID(ir.FixEnvVar.String())
	EnvVarReviewID = lint.MustFixKindID(ir.FixEnvVarReview.String())

	stepFixKinds = []lint.FixKind{
		{ID: EnvVarID, Title: "move the expressions into the env of the step, and read the variables where they were, quoted as the shell needs (bash and sh)", Safety: lint.SafetyReview,
			PossibleSideEffects: []ir.SideEffect{ir.SideEffectValueNotReadAsScript}},
		{ID: EnvVarReviewID, Title: "move the expressions into the env of the step and read them as \"${NAME}\" where they were unquoted (bash and sh), as $env:NAME (pwsh) or as process.env.NAME (github-script); take the line breaks out of what is written to $GITHUB_ENV or $GITHUB_OUTPUT, or make the delimiter of name<<DELIM random", Safety: lint.SafetyReview,
			PossibleSideEffects: []ir.SideEffect{ir.SideEffectUnquotedOneWord, ir.SideEffectPatternLiteral, ir.SideEffectPwshUnchecked, ir.SideEffectGitHubScriptUnchecked, ir.SideEffectLineBreaksRemoved, ir.SideEffectRandomDelimiter, ir.SideEffectValueNotReadAsScript}},
	}
)

// codeInjectionInStepText is what the undetected forms of code-injection
// about a step of a composite action that the rule does not read name.
const codeInjectionInStepText = "a ${{ }} whose value an attacker shapes, such as ${{ github.event.issue.title }}, in a run"
