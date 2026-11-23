package rules

import (
	"context"
	"strconv"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// SecretInLog is the rule secret-in-log: a value the shell made from a
// secret (a substring, what jq takes out, a base64 with a line break),
// which the runner does not mask, where a run prints it to its log: the
// output of the step, the job summary, the trace of set -x (or of a
// shell: with -x), $GITHUB_ENV
// (the header of each later step prints it), or an output the header of a
// later step prints.
// Whether the repository is public tells who reads the log, as for
// unmasked-secret-exposure.
// It reads no summary in a job that GitHub skips in every run
// (AlwaysSkipped): nothing of such a job runs.
var SecretInLog lint.Rule = withExamples(lint.WithView[ir.SecretInLogReader](secretInLog{}, ir.SecretInLogView))

// SecretInLogID is the ID of secret-in-log.
var SecretInLogID = lint.MustRuleID("secret-in-log")

type secretInLog struct{}

func (secretInLog) Meta() lint.Meta { return secretInLogMeta }

func (secretInLog) Check(_ context.Context, c *lint.RuleContext, v ir.SecretInLogReader) error {
	report := func(at lint.Location, anchor, secret string, place analysis.LogPlace, transform string, related []lint.Related) {
		c.Report(lint.FindingDraft{Location: at, Anchor: anchor + " public", Args: SecretInLogPublic{Secret: secret, Place: place, Transform: transform}, Condition: isPublic(c), Evidence: related})
		c.Report(lint.FindingDraft{Location: at, Anchor: anchor + " private", Args: SecretInLogPrivate{Secret: secret, Place: place, Transform: transform}, Condition: factCond(facts.RepoPublic{Repo: c.Repo()}, false), Evidence: related})
	}
	for _, s := range v.Sinks() {
		if s.AlwaysSkipped() {
			continue // GitHub skips its job in every run
		}
		reportCallsNotRead(c, s.CallsNotRead())
		seen := map[string]int{}
		for _, l := range s.SecretLeaks() {
			name := leakedSecretName(l.Secret, l.Token)
			key := name + " " + strconv.Itoa(int(l.Place))
			seen[key]++
			report(c.At(l.At), key+" "+strconv.Itoa(seen[key]), name, l.Place, l.Transform,
				[]lint.Related{{Location: c.At(l.Command), Note: "the command that prints " + name + " made into another value"}})
		}
	}
	seen := map[string]int{}
	for _, p := range v.PrintedOutputs() {
		if p.AlwaysSkipped() {
			continue // GitHub skips its job in every run
		}
		name := leakedSecretName(p.Secret(), p.Token())
		seen[name]++
		report(c.At(p.At()), "header "+name+" "+strconv.Itoa(seen[name]), name, analysis.LogPlaceStepHeader, p.Transform(), nil)
	}
	return nil
}

// leakedSecretName is how a finding names a secret: in upper case, as
// GitHub compares the names, and GITHUB_TOKEN for the job's token.
func leakedSecretName(name string, token bool) string {
	if token {
		return "GITHUB_TOKEN"
	}
	if n, err := facts.ParseSecretName(name); err == nil {
		return n.String()
	}
	return strings.ToUpper(name)
}

var (
	observedSecretInLog = lint.MustDate("2026-10-20")
	runnerSecretMasker  = lint.MustCitation("https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Sdk/DTLogging/Logging/SecretMasker.cs")
	runnerValueEncoders = lint.MustCitation("https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Sdk/DTLogging/Logging/ValueEncoders.cs")
	runnerCommands      = lint.MustCitation("https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Runner.Worker/ActionCommandManager.cs")
	runnerFileCommands  = lint.MustCitation("https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Runner.Worker/FileCommandManager.cs")
	runnerStepEnv       = lint.MustCitation("https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Runner.Worker/ActionRunner.cs")
	workflowCommandsDoc = lint.MustCitation("https://github.com/github/docs/blob/666463860bec200da6c8db9cb9334e7335d9b753/content/actions/reference/workflows-and-actions/workflow-commands.md")

	derivedUnmasked = lint.MustPreconditionID("derived-unmasked")
	printedPlaces   = lint.MustPreconditionID("printed-places")
	maskAfter       = lint.MustPreconditionID("mask-after")

	noSecretInLogIncident = metric(lint.ExploitMaturityUnreported, "no report was found of a value a workflow's run made from a secret read in the log of the run; the advisories of the GitHub Advisory Database of the actions ecosystem (searched 2026-10-20) were of actions whose code printed the value: GHSA-26wh-cc3r-w6pj, a part of the GITHUB_TOKEN, and GHSA-4mgv-m5cm-f9h7, the lines of a secret not registered")
)

// secretInLogCVSS is unmaskedCVSS, but for the value the shell made.
func secretInLogCVSS(pr lint.Metric[lint.PrivilegesRequired]) lint.CVSS {
	b := unmaskedCVSS(pr)
	b.AC = metric(lint.AttackComplexityLow, "the value is in the log as the shell made it")
	return b
}

var secretInLogKinds = []lint.FindingKindID{kindSecretInLogPublic, kindSecretInLogPrivate}

var secretInLogMeta = lint.Meta{
	ID:       SecretInLogID,
	Problem:  "a value the shell made from a secret is printed to the log of the run; the runner registers the secret, each line of the secret and encoded forms of the secret such as the base64 of the secret, and masks only those strings",
	Expected: "either no value made from a secret is printed, or each line of a value made from a secret is registered with ::add-mask:: before the value is printed",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessCredentialLeak}, AttackMeans: []lint.AttackMeans{lint.AttackMeansNone}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textSecretInLogPrivate,
			Attackers:       []lint.Attacker{lint.AttackerLogReader},
			Preconditions:   []lint.PreconditionID{derivedUnmasked, printedPlaces, maskAfter, readableLog},
			FactKinds:       []facts.Kind{facts.KindRepoPublic},
			CVSS:            secretInLogCVSS(metric(lint.PrivilegesRequiredLow, "the logs of a private or internal repository are read by those with read access to the repository, every member of the enterprise for an internal one")),
			ExploitMaturity: noSecretInLogIncident,
		},
		{
			FindingText:     textSecretInLogPublic,
			Attackers:       []lint.Attacker{lint.AttackerLogReader},
			Preconditions:   []lint.PreconditionID{derivedUnmasked, printedPlaces, maskAfter, readableLog},
			FactKinds:       []facts.Kind{facts.KindRepoPublic},
			CVSS:            secretInLogCVSS(metric(lint.PrivilegesRequiredNone, "anyone signed in to GitHub reads the logs of a public repository")),
			ExploitMaturity: noSecretInLogIncident,
		},
	},
	Threat: lint.Threat{
		Actors: []lint.Actor{{
			Attacker: lint.AttackerLogReader,
			Via:      "reads the log of a run, or downloads the log",
			Gains:    []lint.Gain{lint.GainReadSecrets},
		}},
		Preconditions: []lint.Precondition{
			{ID: derivedUnmasked, Text: "the runner masks what is registered (the value of each secret the job gets, each line of the value, the forms the encoders of the runner make of the value, and what ::add-mask:: registers) where the registered value is in a line of the log as it is; a value the shell makes from a secret (a substring, a value with a part replaced or the case changed, what jq takes out, a base64 of the value with a line break or folded at 76 characters, a hex dump, the value reversed or folded) is printed as it is; a digest does not give the value, so the rule does not report a digest", Cites: []lint.Citation{runnerSecretMasker, runnerValueEncoders, runnerMasker, secureUseSecrets},
				Observed: []lint.Observation{{Date: observedSecretInLog, Runner: runner, What: "the value of a secret, the value through an assignment or $(echo ...), and the value with more around the value were masked; ${S:0:10}, ${S#probe-}, ${S//-/_}, ${S^^}, jq -r .pass, jq ., rev, xxd -p, fold -w 9, the base64 of a 13-character and a 14-character value with a line break, and the base64 of a 67-character value folded at 76 characters were printed as they are"}}},
			{ID: printedPlaces, Text: "the log has what the script writes to the standard output and error it inherits, the trace on the standard error that set -x or the -x option in the shell: value of the step turns on, and the job summary; the header of each step after a step that writes $GITHUB_ENV prints the variables written in the env of the header, and the header of a step prints the run of the step with each ${{ }} evaluated, the env of the step and the with of the step, outputs of steps and jobs included", Cites: []lint.Citation{runnerScript, runnerFileCommands, runnerStepEnv, workflowCommandsDoc},
				Observed: []lint.Observation{{Date: observedSecretInLog, Runner: runner, What: "set -x printed an assignment of a value made from a secret; a value made from a secret written to $GITHUB_ENV was in the env of the header of the next step, and one written to $GITHUB_OUTPUT was in the header of a later step that read the output in the run and the env of the step, and of a step of another job that read the job's output"}}},
			{ID: maskAfter, Text: "::add-mask:: masks the value from the line after the ::add-mask:: on, in every later step of the job; a value made from the registered value is another value, and a value of more than one line has the lines after the first printed by the echo of ::add-mask:: itself", Cites: []lint.Citation{runnerCommands, workflowCommandsDoc},
				Observed: []lint.Observation{{Date: observedSecretInLog, Runner: runner, What: "a value printed before the ::add-mask:: of the value was printed as it is and masked after the ::add-mask::; a value registered in a step was masked in the env of a later step's header; the second line of a value of two lines was printed by the ::add-mask:: of the value and after the ::add-mask::"}}},
			readableLogPre,
		},
	},
	Citations:         []lint.Citation{cvss},
	Targets:           []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	InconclusiveKinds: withRemoteCalleeUnknown(withCallBodyUnknown(nil)),
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		lastpipeLimit,
		nameNotLiteralLimit,
		recursiveUnsetLocalLimit,
		unsetCallerLocalLimit,
		splitEnvNameLimit,
		secretInputLimit,
		{ID: lint.MustUndetectedFormID("extracted"), Text: "a value fromJSON takes out of a secret in a ${{ }}, and a value the shell makes from that value: the header of the step prints the value first", Disposition: lint.OtherRule(UnmaskedSecretExposureID)},
		{ID: lint.MustUndetectedFormID("other-command"), Text: "a value printed by a command that the table of commands built into this linter does not declare to write a value made from its input, such as awk, a python -c or a command line of a service: the rule does not know whether the command writes what it reads", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("debug-if"), Text: "a value that the shell makes from a secret and writes to an output of a step, which the if of a later step reads: a rerun with debug logging prints, in the log of the run, the values that the if evaluates; a credential with read access to the repository can open the log, and a credential whose only write access is to the permission Actions can start the rerun; on 2026-10-23 a rerun with debug logging printed the values that the if of a step evaluated, in the lines ##[debug]Evaluating and ##[debug]Expanded. In the workflow file, the rule reads the commands of a run script that print to the log, and not the if of a step", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("file"), Text: "a value made from a secret written to a file and printed from the file", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("called-outputs"), Text: "a value made from a secret in an output of a called workflow or a called action, printed by the caller", Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustUndetectedFormID("multi-line-mask"), Text: "a value of more than one line that the script registers with ::add-mask:: and one variable (not a secret of the secrets context): ::add-mask:: registers the first line of the value alone, and the echo of ::add-mask:: prints the lines after the first, which stay unmasked; the rule takes the value as masked, as the rule does not know how many lines the value has", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("whole-context"), Text: "a value made from toJSON(secrets): the value may be a registered secret, a part of one, or the JSON around the secrets, which the rule does not tell apart", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("other-shell"), Text: "a run of a shell that is not bash or sh, of bash or sh with an option that the rule does not read, such as bash -v {0}, or of bash or sh named by a path, such as /bin/bash -x {0}, on a runner where the rule does not know that the path exists or in a step of a composite action", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("shell-form"), Text: "a form of the shell the rule does not read as a change of the value: printf with a precision (%.4s), an expansion of an array (${A[@]:0:4}), what a descriptor that exec points at the log prints (exec 3>&1 and >&3), and a function called twice with an assignment between the calls", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("process-substitution"), Text: "what a step prints after exec sends the output to a process substitution (exec > >(tee -a build.log)), or what a redirect to a process substitution prints: tee in the process substitution writes the output to the log", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("writer-function-output"), Text: "a value made from a secret that the body of a shell function prints, where a call of the function with no arguments is a command of a pipeline whose last command is not a simple command and writes to $GITHUB_STEP_SUMMARY (f | { cat; } >>\"$GITHUB_STEP_SUMMARY\"), or where the body of a function that a call with arguments runs calls the function (g() { f; }; g a >>\"$GITHUB_STEP_SUMMARY\"): the rule reads such a pipeline and such a call by every simple command, without the bodies of the called functions, and reads only the bodies of the function the call with arguments names", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("case-arm"), Text: "a value made from a secret that an assignment in an arm of a case statement of the shell makes, or that a command in an arm of a case statement prints (case \"$GITHUB_EVENT_NAME\" in push) X=\"${KEY:1}\";; esac; echo \"$X\"): the rule finds the case statement and does not read the commands in the arms of the case statement", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("action-output"), Text: "an action whose code prints a value made from a secret, where the code of the action is the own code of the action, a program that the action starts, or the post step of the action, which the runner runs at the end of the job, and where the code of the action reads the secret from an input of the action, from the environment of the step or from a file. Examples of a secret from an input of the action: GHSA-26wh-cc3r-w6pj, GHSA-4mgv-m5cm-f9h7, and the GITHUB_TOKEN that shivammathur/setup-php gives to Composer, a program that setup-php starts, where Composer prints the GITHUB_TOKEN (GHSA-5wxr-w449-57cm). Examples of a secret from a file: the post step of setup-steamcmd prints config/config.vdf, where running steamcmd +login in a step after the main step of setup-steamcmd saved the token of the Steam account (GHSA-c5qx-p38x-qf5w), and a parse error of tmatens/compose-lint up to 0.31.0 quotes the first characters of the value of a secret in a file of credentials outside the checkout, which a symlink of a pull request names in place of .compose-lint.yml (GHSA-88f4-frh5-gmcr)", Disposition: lint.Limitation(lint.DeciderRunTime)},
	}),
	FalsePositiveForms: []lint.FalsePositiveForm{
		branchNotRun(secretInLogKinds...),
		{ID: lint.MustFalsePositiveFormID("writer-body"), Text: "a value made from a secret that the body of a shell function prints after an exec in the body points the standard output elsewhere, after a return in the body, or with a redirect of the print that points the standard output elsewhere, where a call of the function with arguments writes to $GITHUB_STEP_SUMMARY (f() { exec >/dev/null; echo \"${KEY:1}\"; }; f a >>\"$GITHUB_STEP_SUMMARY\"): the job summary gets nothing from the print; the rule reads what such a call writes from every command of the body of the function, and does not read where the commands of the body point the standard output or which commands of the body run", FindingKinds: secretInLogKinds, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("pipeline-descriptor"), Text: "a value made from a secret that a command of a $( ) prints after an exec in the $( ) points the standard output at a file descriptor that an exec before a pipeline opened, where the $( ) is in a word of a command of the pipeline and the last command of the pipeline writes to $GITHUB_STEP_SUMMARY (exec 3>/dev/null; echo \"$(exec >&3; echo \"${KEY:1}\")\" | cat >>\"$GITHUB_STEP_SUMMARY\"): the print goes where the file descriptor points, not to the value of the $( ), so the job summary gets nothing from the print; the rule reads such a pipeline without the file descriptors that the commands before the pipeline opened", FindingKinds: secretInLogKinds, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("pipeline-compound"), Text: "a value made from a secret that a command of a pipeline prints elsewhere than the pipe, by a redirect of the command or after an exec in a $( ) of the command, where the last command of the pipeline is not a simple command and writes to $GITHUB_STEP_SUMMARY (echo \"$(exec >/dev/null; echo \"${KEY:1}\")\" | { cat; } >>\"$GITHUB_STEP_SUMMARY\"): the job summary gets nothing from the print; the rule reads such a pipeline by every simple command, and does not read where the commands point the standard output", FindingKinds: secretInLogKinds, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("failing-pipe-redirect"), Text: "a value made from a secret that a pipeline writes to $GITHUB_STEP_SUMMARY, where a redirect of the last command of the pipeline copies a file descriptor that is not open (echo \"${KEY:1}\" | cat >&3 >>\"$GITHUB_STEP_SUMMARY\"): bash does not run the last command, so the job summary gets nothing; the rule reads the last command of such a pipeline as writing to the job summary, and does not read whether a redirect of the last command fails", FindingKinds: secretInLogKinds, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("background-write"), Text: "a value made from a secret that a command, which the script runs in the background (&) with no wait for the command, writes to $GITHUB_ENV after the shell of the script ends (for example: (sleep 5; echo \"P=${KEY:1}\" >> \"$GITHUB_ENV\") &): a write that the command makes after the shell of the script ends does not reach the steps after the step, so the header of a later step does not print the value; the rule reads the write as a write that reaches $GITHUB_ENV, because whether the command writes before the shell of the script ends depends on how long the commands take when the step runs", FindingKinds: secretInLogKinds, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustFalsePositiveFormID("masked-encoding"), Text: "a value the shell made that is a form the runner registers: the base64 of the value without a line break and not folded (base64 -w0, echo -n), the base64 of a value whose length is a multiple of 3, with the line break base64 writes (the head of the output is the base64 of the value, which the runner masks; the last characters left in the log encode the line break alone), or jq -c . of a secret whose JSON is already in the form jq -c writes", FindingKinds: secretInLogKinds, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("secret-lines"), Text: "whole lines of a secret of the secrets context with more than one line, taken by head, tail, grep or sed -n: for a secret of the secrets context, the runner registers each line of the secret", FindingKinds: secretInLogKinds, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustFalsePositiveFormID("other-mask"), Text: "a value registered by a ::add-mask:: of an expression or of another variable holding the same value, by core.setSecret of actions/github-script, or by an action", FindingKinds: secretInLogKinds, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("unchanged-value"), Text: "a command or an expansion that gives a value of one line as the value was: tr -d '\\n', head -n1, sort or uniq of one line, ${X%$'\\n'}, a sed that does not match; the runner masks the value of the secret", FindingKinds: secretInLogKinds, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("filter-result"), Text: "a command that changes the input, whose program gives a value that holds nothing of the input: jq 'type == \"array\"', jq length and the like; the output does not give the value of the secret", FindingKinds: secretInLogKinds, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("function-calls"), Text: "the body of a function that prints an argument or a variable, where the call that carries the value made from a secret sends the output to a file, or where a ::add-mask:: that comes before the call, but after the body in the text, registers the value: the rule reads the body with the arguments of every call, and compares a ::add-mask:: with the body by the place in the text", FindingKinds: secretInLogKinds, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("private-repository"), Text: "a private or internal repository, where the value is secret-in-log.private: whoever may read the repository reads the value", FindingKinds: []lint.FindingKindID{kindSecretInLogPublic}, FactKinds: []facts.Kind{facts.KindRepoPublic}},
	},
}
