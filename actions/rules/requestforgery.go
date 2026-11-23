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

// RequestForgery is the rule request-forgery: a value an attacker controls
// decides the host of a request a run sends (curl, wget, gh api) or of the
// request an action sends where its input says, and the request carries a
// credential there, or comes from a job on a self-hosted runner. It
// reads the value through ${{ }} and through a variable of env, so that
// code-injection's fix, which moves the first into the second, leaves the
// same finding.
var RequestForgery lint.Rule = withExamples(lint.WithView[ir.RequestForgeryReader](requestForgery{}, ir.RequestForgeryView))

// RequestForgeryID is the ID of request-forgery.
var RequestForgeryID = lint.MustRuleID("request-forgery")

type requestForgery struct{}

func (requestForgery) Meta() lint.Meta { return requestForgeryMeta }

// enterpriseTokenName stands for gh api's enterprise token in a finding's
// secrets when no secret is known to be in it.
const enterpriseTokenName = "enterprise-token"

func (requestForgery) Check(_ context.Context, c *lint.RuleContext, v ir.RequestForgeryReader) error {
	var seen map[string]int // per sink and per action site: the Fingerprint's place tells them apart
	anchor := func(key string) string {
		seen[key]++
		return fmt.Sprintf("%s#%d", key, seen[key])
	}
	for _, s := range v.Sinks() {
		reportCallsNotRead(c, s.CallsNotRead())
		seen = map[string]int{}
		for _, r := range s.Requests() {
			secrets := secretNames(r.Secrets)
			if len(secrets) == 0 && r.EnterpriseToken {
				secrets = []string{enterpriseTokenName}
			}
			if len(secrets) == 0 && r.RunnerHosting != analysis.RunnerHostingSelfHosted {
				continue // hosted-no-credential, runner-unknown
			}
			for _, h := range r.HostRefs {
				ref := h.Ref
				at := c.At(h.At)
				var carried []lint.Related
				for _, sec := range r.Secrets {
					carried = append(carried, lint.Related{Location: c.At(sec.At), Note: "the request carries " + secretName(sec) + " here"})
				}
				if forgeryGap(c, ref, at, r.Command, carried) {
					continue
				}
				evidence, related := valueEvidence(c, ref, ref.Text)
				related = append(related, carried...)
				f := lint.FindingDraft{Location: at, Anchor: anchor(fmt.Sprintf("%s#%d#%s", r.Command, r.Occurrence, h.Path)), Evidence: evidence, Related: related}
				if len(secrets) > 0 {
					f.Args = RequestForgeryCredentialHost{Command: r.Command, Secrets: secrets, ExprRef: h.Path, ControlledOn: eventsOf(ref.ControlledOn)}
				} else {
					f.Args = RequestForgeryRunnerNetwork{Command: r.Command, RunnerLabels: r.RunnerLabels, ExprRef: h.Path, ControlledOn: eventsOf(ref.ControlledOn)}
				}
				if onlyGollum(ref.ControlledOn) {
					f.Condition = wikiOpenCond(c)
				}
				c.Report(f)
			}
		}
	}
	for _, a := range v.RequestActionSites() {
		seen = map[string]int{}
		secrets := secretNames(a.Secrets())
		if len(secrets) == 0 && a.RunnerHosting() != analysis.RunnerHostingSelfHosted {
			continue // action-no-credential, runner-unknown
		}
		sender := a.Action() + " " + a.Input()
		for _, ref := range a.HostRefs() {
			at := c.At(ref.At)
			if forgeryGap(c, ref, at, sender, nil) {
				continue
			}
			evidence, related := valueEvidence(c, ref, ref.Text)
			f := lint.FindingDraft{Location: at, Anchor: anchor(fmt.Sprintf("%s#%s#%s", a.Action(), a.Input(), ref.Text)), Evidence: evidence, Related: related}
			if len(secrets) > 0 {
				f.Args = RequestForgeryActionInput{Action: a.Action(), Input: a.Input(), Secrets: secrets, ExprRef: ref.Text, ControlledOn: eventsOf(ref.ControlledOn)}
			} else {
				f.Args = RequestForgeryRunnerNetwork{Command: sender, RunnerLabels: a.RunnerLabels(), ExprRef: ref.Text, ControlledOn: eventsOf(ref.ControlledOn)}
			}
			if onlyGollum(ref.ControlledOn) {
				f.Condition = wikiOpenCond(c)
			}
			c.Report(f)
		}
	}
	return nil
}

// forgeryGap reports ref, at the host of a request sender sends, as
// inconclusive when whether an attacker controls it is not analyzed, and
// is whether ref is not one to report as a finding. related are the places
// that the finding would carry other than at, the secrets of the request.
func forgeryGap(c *lint.RuleContext, ref ir.ExprRef, at lint.Location, sender string, related []lint.Related) bool {
	switch ref.Verdict {
	case analysis.Controlled:
		return false
	case analysis.Inconclusive:
		c.Inconclusive(lint.InconclusiveDraft{KindID: inconclusiveKind(ref.InconclusiveKind), Location: at, Related: related,
			Note: fmt.Sprintf("%s sends a request whose host %s decides; whether an attacker controls %s is not analyzed (%s)", sender, ref.Text, ref.Text, ref.InconclusiveKind)})
	}
	return true
}

// secretName is how a finding names sec.
func secretName(sec ir.CarriedSecret) string {
	switch {
	case sec.Whole:
		return "*"
	case sec.Token:
		return "GITHUB_TOKEN"
	}
	return sec.Name
}

// secretNames are the names of cs, once each, in order.
func secretNames(cs []ir.CarriedSecret) []string {
	var out []string
	for _, sec := range cs {
		if n := secretName(sec); !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

var (
	curlHeader         = lint.MustCitation("https://github.com/curl/curl/blob/dc99e1274b2bb368dea509ac6694d34e93c50054/docs/cmdline-opts/header.md")
	ghAPIHTTP          = lint.MustCitation("https://github.com/cli/cli/blob/fa92838bef95fe4a29c1587693885d5e9bdb6cf1/pkg/cmd/api/http.go")
	goGHAuth           = lint.MustCitation("https://github.com/cli/go-gh/blob/aadf36735579aa6ad2343b2e1b0f5387c22c71f0/pkg/auth/auth.go")
	sonarHTTPClient    = lint.MustCitation("https://github.com/SonarSource/sonar-scanner-java-library/blob/87b5593e4fe3fc9a67402875ecfbfdb7d266f79f/lib/src/main/java/org/sonarsource/scanner/lib/internal/http/ScannerHttpClient.java")
	octokitParse       = lint.MustCitation("https://github.com/octokit/endpoint.js/blob/7f97cd91409be64d2b75af807583a4fe18d33188/src/parse.ts")
	selfHostedSecurity = lint.MustCitation("https://github.com/github/docs/blob/dae83f7d28f3b8e10015bd6b6d8b72267cedceca/content/actions/reference/security/secure-use.md")

	hostCarriesCredential = lint.MustPreconditionID("host-carries-credential")
	selfHostedNetwork     = lint.MustPreconditionID("self-hosted-network")
)

// credentialHostBase is the CVSS of request-forgery.credential-host and
// action-input: the attacker's server receives what the request carries.
var credentialHostBase = lint.CVSS{
	AV: metric(lint.AttackVectorNetwork, "the attacker writes a title, a body, a comment or a branch name over the network"),
	AC: metric(lint.AttackComplexityLow, "the host of a server of the attacker's own in the value is all it takes"),
	AT: metric(lint.AttackRequirementsNone, "on a public repository anyone can open a pull request from a fork or write an issue"),
	PR: metric(lint.PrivilegesRequiredNone, "nothing of the repository is needed"),
	UI: metric(lint.UserInteractionNone, "the event runs the workflow with nobody doing anything"),
	VC: metric(lint.ImpactHigh, "the attacker's server receives the secrets or the token the request carries"),
	VI: metric(lint.ImpactHigh, "with the token, when the job's token can write, the attacker writes to the repository while the job runs; a request that carries only secrets gives what the secrets can write"),
	VA: metric(lint.ImpactNone, "the request going elsewhere makes nothing of the job unavailable as such"),
	SC: metric(lint.ImpactHigh, "the secrets open what is past the job: clouds, registries, other repositories"),
	SI: metric(lint.ImpactHigh, "with the secrets the attacker writes to what they open"),
	SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
}

// runnerNetworkBase is the CVSS of request-forgery.runner-network: the
// request reaches the network of a self-hosted runner.
var runnerNetworkBase = lint.CVSS{
	AV: credentialHostBase.AV,
	AC: metric(lint.AttackComplexityLow, "the address of a service of the runner's network in the value is all it takes"),
	AT: metric(lint.AttackRequirementsPresent, "the network of the runner must have a service the attacker does not reach from outside; the organization that runs the runner decides that network"),
	PR: credentialHostBase.PR,
	UI: credentialHostBase.UI,
	VC: metric(lint.ImpactLow, "the response of the service does not always come back to the attacker"),
	VI: metric(lint.ImpactLow, "the request can make the service act, with the method and the body the command sends"),
	VA: metric(lint.ImpactNone, "the request going elsewhere makes nothing of the job unavailable as such"),
	SC: metric(lint.ImpactHigh, "an internal service or a cloud's metadata service of the runner's network can give credentials or data"),
	SI: metric(lint.ImpactLow, "the request can change what the service keeps"),
	SA: metric(lint.ImpactLow, "the request can stop a service that takes such a request as an order"),
}

// requestForgeryCredentialExploited is the exploit maturity of the kinds
// whose request carries a credential.
var requestForgeryCredentialExploited = metric(lint.ExploitMaturityProofOfConcept, "GitHub Security Lab showed a workflow of kptdev/kpt that runs on workflow_run, in which the file sonar.properties of a pull request from a fork named the host of SonarSource's scanner, and the scanner sent SONAR_TOKEN to the host named in the file (GHSL-2026-208). The host came from a file of the code of the pull request, which this rule does not read (the undetected form workspace-config)", ghsl2026208)

var requestForgeryExploited = metric(lint.ExploitMaturityUnreported, "no report was found of an attacker's value that decided the host of a request of a workflow (searched 2026-10-19: the issues and pull requests of sisakulint that ported CodeQL's queries, and the findings of the upstream rules on 4,974 workflows of public repositories)")

var requestForgeryMeta = lint.Meta{
	ID:       RequestForgeryID,
	Problem:  "an attacker's value decides the host to which a command or an action sends a request. When the request carries a secret or the job's token, the attacker's server receives the secret or the token. When the job runs on a self-hosted runner, the request reaches services of the runner's network, with or without a credential",
	Expected: "the workflow writes the host of every request, and any value an attacker controls appears only after the / that ends the host (https://api.example.com/<the value>)",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessRequestForgery}, AttackMeans: []lint.AttackMeans{lint.AttackMeansString}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textRequestForgeryActionInput,
			Attackers:       injectionAttackers,
			Preconditions:   []lint.PreconditionID{hostCarriesCredential, attackerEvent, callersEvents, wikiOpen, appStatusCheck},
			FactKinds:       []facts.Kind{facts.KindRepoWikiOpen},
			CVSS:            credentialHostBase,
			ExploitMaturity: requestForgeryCredentialExploited,
		},
		{
			FindingText:     textRequestForgeryCredentialHost,
			Attackers:       injectionAttackers,
			Preconditions:   []lint.PreconditionID{hostCarriesCredential, attackerEvent, callersEvents, wikiOpen, appStatusCheck},
			FactKinds:       []facts.Kind{facts.KindRepoWikiOpen},
			CVSS:            credentialHostBase,
			ExploitMaturity: requestForgeryCredentialExploited,
		},
		{
			FindingText:     textRequestForgeryRunnerNetwork,
			Attackers:       injectionAttackers,
			Preconditions:   []lint.PreconditionID{selfHostedNetwork, attackerEvent, callersEvents, wikiOpen, appStatusCheck},
			FactKinds:       []facts.Kind{facts.KindRepoWikiOpen},
			CVSS:            runnerNetworkBase,
			ExploitMaturity: requestForgeryExploited,
		},
	},
	Threat: lint.Threat{
		Actors: injectionActors([]lint.Gain{lint.GainReadSecrets, lint.GainWriteWithToken, lint.GainReachRunnerNetwork}),
		Preconditions: []lint.Precondition{
			{
				ID:    hostCarriesCredential,
				Text:  "the request carries its credentials to the host its URL names: curl sends -H, -u, --oauth2-bearer, cookies and the body there, gh api sends GH_ENTERPRISE_TOKEN to any host not of GitHub and uses a full URL as it is, SonarSource's scanner sends SONAR_TOKEN to the sonar.host.url that args sets, and octokit/request-action sends its token to a full URL in route or to url",
				Cites: []lint.Citation{curlHeader, ghAPIHTTP, goGHAuth, sonarHTTPClient, octokitParse},
			},
			{
				ID:    selfHostedNetwork,
				Text:  "a self-hosted runner reaches services of its network that the attacker does not reach from outside, such as internal services and a cloud's metadata service; the organization that runs the runner decides that network, which is not checked",
				Cites: []lint.Citation{selfHostedSecurity},
			},
			attackerEventPre,
			appStatusCheckPre,
			callersEventsPre,
			wikiOpenPre,
		},
	},
	Citations:         []lint.Citation{cvss},
	Targets:           []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	InconclusiveKinds: withRemoteCalleeUnknown(withCallBodyUnknown(valueGaps)),
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		wikiSummaryLimit,
		forkReviewLimit,
		ifComparedLimit,
		secretInputLimit,
		{ID: lint.MustUndetectedFormID("caller-runner"), Text: "a request from a step of an action, where the runs-on of the job of the caller decides the runner: the rule reads runs-on only in a workflow, an action file has no runs-on, and the rule does not read the runs-on of the job of the caller, so a self-hosted runner of the caller is not seen", Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustUndetectedFormID("other-command"), Text: "a request sent by a command other than curl, wget and gh api: httpie, nc, dig, a script of python or node", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("graphql-variables"), Text: "baseUrl in the variables of octokit/graphql-action, which becomes an option of the request when an attacker's value writes the key", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("path-only"), Text: "an attacker's value only in the path, the query or the fragment of a request whose host the workflow writes, including a full URL to GitHub's API as the endpoint of gh api: what the attacker gains with the credential on the same host depends on the method and the endpoint, which are not checked", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("attacker-header"), Text: "a request without a credential from a GitHub-hosted runner, whose header an attacker's value also writes: the metadata service of the runner's cloud answers a request with the header Metadata: true, which was not tried", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("hosted-no-credential"), Text: "a request without a credential from a GitHub-hosted runner: the attacker's server receives nothing of the repository, and the metadata service of the runner's cloud answered 400 to a request without its header. This undetected form is only for a request whose response no step runs as code; a request whose response a step runs as code is the undetected form response-code", Disposition: lint.NoAddedGain()},
		{ID: lint.MustUndetectedFormID("action-no-credential"), Text: "an input of an action of the table in a step that gives the action no secret, in a job on a GitHub-hosted runner. This undetected form is only for an action whose response no step runs as code; an action whose response a step runs as code is the undetected form response-code", Disposition: lint.NoAddedGain()},
		{ID: lint.MustUndetectedFormID("response-code"), Text: "a request to the host that an attacker's value decides, whose response a step runs as code: in the same step (curl -fsS https://$HOST/x | bash), or in a later step (a file that curl -o writes and a later step runs, or an output of an action that the script of a later run: step contains). The server of the attacker writes the response. The rule reads the request and does not follow the response", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("runner-unknown"), Text: "a request without a credential from a job whose runs-on is neither GitHub-hosted nor self-hosted by its labels: a runner group, labels of its own, a ${{ }}", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("shell-derived"), Text: "an attacker's value the script makes: an assignment, $( ), a function's argument ($1), standard input", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("file"), Text: "a secret that reaches the request through a file", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("redirect"), Text: "a fixed destination that redirects the request to another host, where curl sends the headers of -H but Authorization and Cookie, and wget sends its --header: the holder of the fixed destination decides the redirect", Disposition: lint.OtherRule(SecretExfiltrationID)},
		{ID: lint.MustUndetectedFormID("config-file"), Text: "a credential from a file curl reads: -K, the default .curlrc, --netrc", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustUndetectedFormID("env-file-variable"), Text: "a variable a step before sets through $GITHUB_ENV: the rule reads the variables of the workflow's env", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("param-operator"), Text: "a variable with an operator that changes its value (${X#prefix}, ${X/a/b})", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("unwalked-place"), Text: "a command in a place the rule does not walk: the commands of an arm of case, $( ) in the words of case", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("host-env"), Text: "an attacker's value in the env an action reads its server from, such as SONAR_HOST_URL of SonarSource's scanner: the rule reads the inputs of the table, not the env of the step", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("workspace-config"), Text: "a host named in a file of the working tree, where an action or a command reads the file as the settings of the action or the command (sonar.host.url in a project file of SonarSource's scanner): the rule reads the hosts written in the inputs and the commands of the workflow, not the files that an action or a command reads. A file of an attacker reaches the working tree through a checkout of a pull request's code, which untrusted-checkout reports unless the fact checkout.executed is false for the checkout, or through an artifact, which artifact-poisoning reports", Disposition: lint.OtherRule(UntrustedCheckoutID)},
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
		forkFlagReview(kindRequestForgeryActionInput),
		lastpipeFalsePositive(kindRequestForgeryCredentialHost),
		nameNotLiteralFalsePositive(kindRequestForgeryCredentialHost),
		{ID: lint.MustFalsePositiveFormID("args-word-value"), Text: "a value that cannot hold a blank, such as a branch's name, inside a word of args of SonarSource's scanner after literal text (-Dsonar.pullrequest.branch=<the value>): the scanner splits args at blanks, so the value cannot add an argument -Dsonar.host.url of its own", FindingKinds: []lint.FindingKindID{kindRequestForgeryActionInput}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("curl-next"), Text: "curl with --next, after which the credentials go only to the URLs after it: the rule reads every credential of the command as going to every URL", FindingKinds: []lint.FindingKindID{kindRequestForgeryCredentialHost}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("checked-earlier"), Text: "a script that stops before the request when the value is not a host the workflow expects: the rule does not read the flow of the script", FindingKinds: []lint.FindingKindID{kindRequestForgeryCredentialHost, kindRequestForgeryRunnerNetwork}, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustFalsePositiveFormID("wiki-closed"), Text: "gollum in a repository whose wiki is off or that only collaborators may edit", FindingKinds: []lint.FindingKindID{kindRequestForgeryCredentialHost, kindRequestForgeryActionInput, kindRequestForgeryRunnerNetwork}, FactKinds: []facts.Kind{facts.KindRepoWikiOpen}},
		{ID: lint.MustFalsePositiveFormID("github-url"), Text: "when the whole URL is at the start of the address of the request: a URL that GitHub builds from owner/name of a repository whose name an attacker chooses, such as the attacker's fork (github.event.pull_request.head.repo.url). The host of the URL is a host of GitHub (api.github.com or github.com on GitHub.com), and neither the owner nor the name of the repository can change the host. The rule reports the value because the rule's table of the contexts an attacker controls puts the URL in the class named structured, the class that the table also gives the name of a branch. A value of the class structured is one whose form an attacker may shape in part, and the rule does not tell whether such a value holds the host, so the rule reads the value at the start of the address as one that can change the host", FindingKinds: []lint.FindingKindID{kindRequestForgeryCredentialHost, kindRequestForgeryActionInput, kindRequestForgeryRunnerNetwork}, Disposition: lint.Todo(lint.NeedSameFile)},
		writerString(kindRequestForgeryCredentialHost, kindRequestForgeryActionInput, kindRequestForgeryRunnerNetwork), ifUnnarrowedFalsePositive(kindRequestForgeryCredentialHost, kindRequestForgeryActionInput, kindRequestForgeryRunnerNetwork),
	}, kindRequestForgeryActionInput, kindRequestForgeryCredentialHost, kindRequestForgeryRunnerNetwork),
}

// injectionAttackers are the attackers of injectionActors.
var injectionAttackers = []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerMergedCommitAuthor, lint.AttackerAnyoneWhoForks, lint.AttackerWikiEditor}
