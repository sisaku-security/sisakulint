package rules

import (
	"context"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// UnmaskedSecretExposure is the rule unmasked-secret-exposure: a ${{ }}
// whose value has a value taken out of a secret by fromJSON, which the
// runner does not mask, where the runner prints it in the log. Whether
// the repository is public tells who reads the log, so each gives a
// finding of each kind, on repo.public true and false.
// It reads no summary in a job that GitHub skips in every run
// (AlwaysSkipped): nothing of such a job runs.
var UnmaskedSecretExposure lint.Rule = withExamples(lint.WithView[ir.UnmaskedSecretExposureReader](unmaskedSecretExposure{}, ir.UnmaskedSecretExposureView))

// UnmaskedSecretExposureID is the ID of unmasked-secret-exposure.
var UnmaskedSecretExposureID = lint.MustRuleID("unmasked-secret-exposure")

type unmaskedSecretExposure struct{}

func (unmaskedSecretExposure) Meta() lint.Meta { return unmaskedSecretExposureMeta }

func (unmaskedSecretExposure) Check(_ context.Context, c *lint.RuleContext, v ir.UnmaskedSecretExposureReader) error {
	seen := map[ir.Key]anchors{} // by the value: one value can have several
	for _, p := range v.SecretParts() {
		if p.AlwaysSkipped() {
			continue // GitHub skips its job in every run
		}
		at := c.At(p.At())
		var related []lint.Related
		for _, o := range p.Via() {
			related = append(related, lint.Related{Location: c.At(o.At), Note: "the output " + o.Output + " of the job " + o.Job + " holds the value taken out of a secret"})
		}
		if seen[p.Key()] == nil {
			seen[p.Key()] = anchors{}
		}
		anchor := seen[p.Key()].next(p.Text(), ir.FixPlan{}) // which one, and which of the same text
		c.Report(lint.FindingDraft{Location: at, Anchor: "public " + anchor, Args: UnmaskedSecretExposurePublic{Secrets: p.Secrets()}, Condition: isPublic(c), Related: related})
		c.Report(lint.FindingDraft{Location: at, Anchor: "private " + anchor, Args: UnmaskedSecretExposurePrivate{Secrets: p.Secrets()}, Condition: factCond(facts.RepoPublic{Repo: c.Repo()}, false), Related: related})
	}
	return nil
}

// unmaskedCVSS is what the value opens: past the run, which it does not
// harm as such.
func unmaskedCVSS(pr lint.Metric[lint.PrivilegesRequired]) lint.CVSS {
	return lint.CVSS{
		AV: metric(lint.AttackVectorNetwork, "the attacker reads the log of a run over the network"),
		AC: metric(lint.AttackComplexityLow, "the value is unmasked in the log: in the header of a step, or in the docker create or docker login command at the start of the job"),
		AT: metric(lint.AttackRequirementsNone, "the step runs on its events; nothing else is needed"),
		PR: pr,
		UI: metric(lint.UserInteractionNone, "nobody does anything unusual"),
		VC: metric(lint.ImpactNone, "the workflow's run is not harmed as such"),
		VI: metric(lint.ImpactNone, "the workflow's run is not harmed as such"),
		VA: metric(lint.ImpactNone, "the workflow's run is not harmed as such"),
		SC: metric(lint.ImpactHigh, "the value, a password or a key of the secret, opens what is past the run"),
		SI: metric(lint.ImpactHigh, "they write what it may"),
		SA: metric(lint.ImpactLow, "they can delete what it may"),
	}
}

var (
	partUnmasked   = lint.MustPreconditionID("part-unmasked")
	headerPrinted  = lint.MustPreconditionID("header-printed")
	commandPrinted = lint.MustPreconditionID("command-printed")
	outputKept     = lint.MustPreconditionID("output-kept")
	readableLog    = lint.MustPreconditionID("readable-log")

	runnerMasker        = lint.MustCitation("https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Runner.Worker/Worker.cs")
	runnerHeader        = lint.MustCitation("https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Runner.Worker/Handlers/Handler.cs")
	runnerScript        = lint.MustCitation("https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Runner.Worker/Handlers/ScriptHandler.cs")
	runnerEncoders      = lint.MustCitation("https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Runner.Common/HostContext.cs")
	runnerDocker        = lint.MustCitation("https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Runner.Worker/Container/DockerCommandManager.cs")
	runnerContainerInfo = lint.MustCitation("https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Runner.Worker/Container/ContainerInfo.cs")
	runnerOutputs       = lint.MustCitation("https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Runner.Worker/JobExtension.cs")
	runLogs             = lint.MustCitation("https://github.com/github/docs/blob/ba6f6f9b9b31c4f0a991fbcb1005080526424804/content/actions/how-tos/monitor-workflows/use-workflow-run-logs.md")
	logRetention        = lint.MustCitation("https://github.com/github/docs/blob/ba6f6f9b9b31c4f0a991fbcb1005080526424804/data/reusables/actions/about-artifact-log-retention.md")

	readableLogPre = lint.Precondition{ID: readableLog, Text: "anyone signed in to GitHub reads the logs of a public repository (repo.public, assumed true), those with read access the logs of a private or internal one, where every member of the enterprise has read access to an internal one, for 90 days by default", Cites: []lint.Citation{runLogs, logRetention, internalReaders}}

	noUnmaskedIncident = metric(lint.ExploitMaturityUnreported, "no report was found of a value taken out of a secret by fromJSON read in the log of a run (searched 2026-10-14)")
)

var unmaskedSecretExposureMeta = lint.Meta{
	ID:       UnmaskedSecretExposureID,
	Problem:  "a value taken out of a secret by fromJSON is written where the runner prints it, and the runner masks only whole secrets",
	Expected: "each value is a secret of its own, secrets.NAME",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessCredentialLeak}, AttackMeans: []lint.AttackMeans{lint.AttackMeansNone}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textUnmaskedSecretExposurePrivate,
			Attackers:       []lint.Attacker{lint.AttackerLogReader},
			Preconditions:   []lint.PreconditionID{partUnmasked, headerPrinted, commandPrinted, outputKept, readableLog},
			FactKinds:       []facts.Kind{facts.KindRepoPublic},
			CVSS:            unmaskedCVSS(metric(lint.PrivilegesRequiredLow, "the logs of a private or internal repository are read by those with read access to it, every member of the enterprise for an internal one")),
			ExploitMaturity: noUnmaskedIncident,
		},
		{
			FindingText:     textUnmaskedSecretExposurePublic,
			Attackers:       []lint.Attacker{lint.AttackerLogReader},
			Preconditions:   []lint.PreconditionID{partUnmasked, headerPrinted, commandPrinted, outputKept, readableLog},
			FactKinds:       []facts.Kind{facts.KindRepoPublic},
			CVSS:            unmaskedCVSS(metric(lint.PrivilegesRequiredNone, "anyone signed in to GitHub reads the logs of a public repository")),
			ExploitMaturity: noUnmaskedIncident,
		},
	},
	Threat: lint.Threat{
		Actors: []lint.Actor{{
			Attacker: lint.AttackerLogReader,
			Via:      "reads the log of a run, or downloads it",
			Gains:    []lint.Gain{lint.GainReadSecrets},
		}},
		Preconditions: []lint.Precondition{
			{ID: partUnmasked, Text: "the runner masks the values of the secrets its job gets, each of their lines, and the forms its encoders make of them (Base64, a JSON escape, a value without its quotes), not a part of one: a value fromJSON takes out of a secret, or a JSON fromJSON and toJSON write anew, is printed as it is", Cites: []lint.Citation{runnerMasker, runnerEncoders, secureUseSecrets},
				Observed: []lint.Observation{{Date: observedSecretExposure, Runner: runner, What: "a secret holding a JSON was masked whole; its user and pass taken out by fromJSON were printed as they are in the env of the workflow, the job and the step, a run, a with, a step's name, and in the values of case() and ||"}}},
			{ID: headerPrinted, Text: "the runner prints in the header of a step, before it runs, the env of the step with those of the job and the workflow, the with of an action, and the run with its ${{ }} evaluated; a ::add-mask:: in that run comes after it", Cites: []lint.Citation{runnerHeader, runnerScript},
				Observed: []lint.Observation{{Date: observedSecretExposure, Runner: runner, What: "the header of each step printed its env with the job's and the workflow's, its run with the ${{ }} evaluated, and the with of a local action, before the step's output"}}},
			{ID: commandPrinted, Text: "at the start of the job, the runner prints the docker create command of the job's container and of each service with the values of the env of the container, and, when the credentials of a container have both a username and a password, the docker login command with the username; without both, the runner does not log in and prints no docker login command. The runner passes the password to docker login on its standard input and does not print the password", Cites: []lint.Citation{runnerDocker},
				Observed: []lint.Observation{{Date: observedOtherKeys, Runner: runner, What: "a value taken out of a secret by fromJSON was printed unmasked in the docker create command of the job's container and of a service, where the value was in the env of the container, and in the docker login command, where the value was the username of the credentials of the job's container"}}},
			{ID: outputKept, Text: "the runner prints only the name of each output of a job. The runner keeps an output whose value contains no value that the runner masks (a whole secret, or a value that a step of the job registered with ::add-mask::), and the runner drops an output whose value contains such a value. When a step of a later job reads the kept output with needs in its env, with or run, the runner prints the value in the header of that step, as the runner prints any other value there", Cites: []lint.Citation{runnerOutputs},
				Observed: []lint.Observation{{Date: observedOtherKeys, Runner: runner, What: "an output of a job with the value of the key pass of a JSON secret, taken out by fromJSON, printed only the name of the output in that job; a later job that read the output with needs printed the value of pass unmasked in the env and the run of the headers of its steps; an output with a value that a step of its job registered with ::add-mask:: was dropped, and the later job got an empty value"}}},
			readableLogPre,
		},
	},
	Citations:         []lint.Citation{cvss},
	Targets:           []lint.InputKind{lint.InputKindWorkflow},
	InconclusiveKinds: withRemoteCalleeUnknown(nil),
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("debug-if"), Text: "a value taken out of a secret by fromJSON in an if, through an env that holds the secret, as an if cannot refer to the secrets context (env: CONFIG: ${{ secrets.CONFIG }} and if: fromJSON(env.CONFIG).user != ''): a rerun with debug logging prints, in the log of the run, the values that the if evaluates; a credential with read access to the repository can open the log, and a credential whose only write access is to the permission Actions can start the rerun; on 2026-10-23 a rerun with debug logging printed the value that fromJSON took out of a JSON literal in an if, in the lines ##[debug]Evaluating and ##[debug]Expanded. In the workflow file, the rule reads only the places whose values the header of a step prints in the log (the env, the run, the with and the name of the step), and not the if", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("output-with-secret"), Text: "an output of a job whose value the rule reads as having a value that the runner masks in every run, while the value has no value that the runner masks in some runs: a whole secret that is empty in some runs (a secret that is not set), an operand before && that is false in some runs (github.event_name == 'push' && env), or env[INDEX] whose INDEX names a variable that the env does not have in some runs. The rule assumes that the runner drops the output, and so the rule does not follow the output to the jobs that read the output; in a run where the value has no value that the runner masks, the value taken out of a secret reaches the later job", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("called-output"), Text: "a value taken out of a secret in an output of a reusable workflow (on.workflow_call.outputs), which a job of the caller reads with needs and prints: the rule does not follow the outputs of a called workflow to the caller", Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustUndetectedFormID("needs-other-place"), Text: "a value taken out of a secret in an output of a job, read with needs in a key where GitHub does not allow the secrets context in an expression but where the runner prints the value, such as the image, options, ports or volumes of a container or a service, or defaults.run.shell; or such a value passed to a reusable workflow in the with of a job that calls the reusable workflow, where a step of the called workflow may print the value: the rule inspects only the keys where GitHub allows the secrets context", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("escaped-twice"), Text: "toJSON(secrets), toJSON(secrets.X), or toJSON(env.X) where the variable X of the env holds a whole secret, in the env of the job's container or of a service: the runner prints the docker create command with each value of the JSON escaped a second time, the mask does not match a value escaped twice, and so the runner prints a secret that has a double quote in its value unmasked. Whether unmasked-secret-exposure reports a toJSON in the env of a container or of a service is not decided, because the harm depends on whether a secret has a double quote in its value, which the workflow does not show. secret-exposure reports toJSON(secrets) for a different harm, every secret reaching the job; no rule reports toJSON(secrets.X) or toJSON(env.X) in the env of a container", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("github-env"), Text: "a variable that a step writes to $GITHUB_ENV and that a later step or an output of the job reads with env.NAME: the runner puts the variables that the steps write to $GITHUB_ENV over the variables of the same name in the env of the job and of the workflow, and the rule reads env.NAME only from the env written in the workflow file. So the rule does not report fromJSON(env.NAME).key when a step writes a JSON secret to $GITHUB_ENV under NAME, and the rule reads an output of the job that has env.NAME as an output that the runner drops when the env of the job has a whole secret under NAME, even when a step writes another value to $GITHUB_ENV under NAME", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("env-object-property"), Text: "a property of a value that is the whole env in some runs and another value in other runs, such as fromJSON((github.head_ref || env).DB).pass or case(github.ref == 'refs/heads/main', env, vars).DB: the rule reads the value as a value without the variables of the env, so the rule does not report a value taken out of a secret that a variable of the env holds", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("unknown-os-case"), Text: "env.NAME whose NAME differs only in upper and lower case from the name of a variable of the env (env.db and DB), in a job whose OS the runs-on does not decide, such as a ${{ }} of a matrix or the labels of a self-hosted runner without windows: the runner matches the names of the env context in any case on Windows and only in the same case on Linux and macOS, and the rule matches the names in any case only in a job whose runs-on decides Windows", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("shell-derived"), Text: "a value taken out of a secret in the shell, such as by jq, and printed", Disposition: lint.OtherRule(SecretInLogID)},
		{ID: lint.MustUndetectedFormID("json-scalar"), Text: "a secret whose value is a JSON number, or a JSON string of 8 characters or fewer with its quotes, read whole by fromJSON: the runner masks a value without its quotes only when it is longer than 8 characters, and the rule takes the value as an object it does not print", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("whole-map"), Text: "a whole env, with, container env or container credentials written as one ${{ }} of a secret read by fromJSON, such as env: ${{ fromJSON(secrets.J) }}: the authors of the rule have not checked whether GitHub accepts that form, and whether the runner then prints each value of the secret. In the same way, env.NAME where the whole env of the step or of the job is written as one ${{ }}: the rule skips the env written as one ${{ }} and reads env.NAME from the env of the levels above the env written as one ${{ }} (the env of the job and of the workflow for a step, the env of the workflow for a job), so the rule misses a secret that the env written as one ${{ }} has under NAME", Disposition: lint.Todo(lint.NeedSameFile)},
	}),
	FalsePositiveForms: []lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("registered-earlier"), Text: "a value an earlier step of the job registered with ::add-mask::, in the env, with, run or name of a later step: the runner masks the value there. The runner does not mask, and so this rule reports with no false positive, a value in the env of the job or of the workflow, because the header of the step that registers the value prints that env before the registration, and a value in the env or in the username of the credentials of a container, because the runner prints those at the start of the job, before any step runs", FindingKinds: []lint.FindingKindID{kindUnmaskedSecretExposurePublic, kindUnmaskedSecretExposurePrivate}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("registered-output"), Text: "a value that a step of a job registered with ::add-mask::, in an output of the job, which a later job reads with needs: the runner drops an output whose value contains a value that the runner masks, and the later job gets an empty value", FindingKinds: []lint.FindingKindID{kindUnmaskedSecretExposurePublic, kindUnmaskedSecretExposurePrivate}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("env-object-key"), Text: "a value that fromJSON reads back out of the JSON of the whole env, such as fromJSON(toJSON(env)).TOKEN, where the variable TOKEN of the env holds the whole secret TOKEN or toJSON(secrets): the value is the whole secret TOKEN or the JSON of the secrets context, whose values the runner masks; the rule reads the JSON of the whole env as a JSON secret, and reads each value that fromJSON reads out of the JSON of the whole env as a value taken out of a secret", FindingKinds: []lint.FindingKindID{kindUnmaskedSecretExposurePublic, kindUnmaskedSecretExposurePrivate}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("masked-alternative"), Text: "an output of a job whose value has A || B where A is a whole secret, such as ${{ secrets.TOKEN || '' }}-${{ fromJSON(secrets.DB).pass }}: a secret that is set is not empty, so A || B is the secret in every run, and the runner drops the output; the rule reads A || B as either A or B, and so reads the output as an output that the runner may keep. When the secret is not set, the output has no value that the runner masks, and the finding is right", FindingKinds: []lint.FindingKindID{kindUnmaskedSecretExposurePublic, kindUnmaskedSecretExposurePrivate}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("env-property"), Text: "an output of a job whose value has a property NAME of a value that is the whole env, such as (github.event_name != '' && env).TOKEN, where the variable TOKEN of the env holds a whole secret: the value is the whole secret, and the runner drops the output; the rule reads a property of a value that is not written as env.NAME as any one variable of the env, and so reads the output as an output that the runner may keep", FindingKinds: []lint.FindingKindID{kindUnmaskedSecretExposurePublic, kindUnmaskedSecretExposurePrivate}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("env-index"), Text: "env[INDEX] whose INDEX the workflow file does not write as a name, such as env[matrix.key]: the rule reads env[INDEX] as any one variable of the env. So the rule reports a value taken out of a secret by fromJSON(env[INDEX]).key when a variable of the env holds a secret and INDEX names a variable without a secret in every run, and the rule reports an output of the job that has env[INDEX] and a value taken out of a secret when INDEX names a variable with a whole secret in every run, an output that the runner drops", FindingKinds: []lint.FindingKindID{kindUnmaskedSecretExposurePublic, kindUnmaskedSecretExposurePrivate}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("unknown-os-case"), Text: "env.NAME in a job whose OS the runs-on does not decide, where the env of a nearer level has a variable whose name differs from NAME only in upper and lower case and the env of a farther level holds a secret under NAME (db: plain in the env of the job and DB: ${{ secrets.DB }} in the env of the workflow): on Windows, the variable of the nearer level replaces the variable of the farther level, so env.NAME has no secret; in a job whose OS the runs-on does not decide, the rule matches the names only in the same case and reads the secret of the farther level. In a job whose OS the runs-on does not decide, the rule also reports an output of the job that has env.NAME and a value taken out of a secret, as an output that the runner may keep, when one of the variables whose names differ only in upper and lower case holds a whole secret: the runner drops the output on the OS where env.NAME is the whole secret", FindingKinds: []lint.FindingKindID{kindUnmaskedSecretExposurePublic, kindUnmaskedSecretExposurePrivate}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("whole-map"), Text: "env.NAME where the whole env of the step or of the job is written as one ${{ }} that may have a variable under NAME, and the env of a level above holds a secret under NAME: the variable of the env written as one ${{ }} replaces the variable of the level above, so env.NAME may have no secret; the rule skips the env written as one ${{ }} and reads the secret of the level above. In the same way, the rule reports an output of the job that has env.NAME and a value taken out of a secret, as an output that the runner may keep, when the env of a level above holds a whole secret under NAME; the runner drops the output when the env written as one ${{ }} has no variable under NAME. The authors of the rule have not checked whether GitHub accepts an env written as one ${{ }}", FindingKinds: []lint.FindingKindID{kindUnmaskedSecretExposurePublic, kindUnmaskedSecretExposurePrivate}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("github-env"), Text: "fromJSON(env.NAME).key, where the env of the job or of the workflow has a JSON secret under NAME and a step before writes a value without a secret to $GITHUB_ENV under NAME: the runner puts the value of $GITHUB_ENV over the env of the job and of the workflow, so env.NAME has no secret; the rule reads env.NAME only from the env written in the workflow file", FindingKinds: []lint.FindingKindID{kindUnmaskedSecretExposurePublic, kindUnmaskedSecretExposurePrivate}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("private-repository"), Text: "a private or internal repository, where the value is unmasked-secret-exposure.private: whoever may read the repository reads it", FindingKinds: []lint.FindingKindID{kindUnmaskedSecretExposurePublic}, FactKinds: []facts.Kind{facts.KindRepoPublic}},
	},
}
