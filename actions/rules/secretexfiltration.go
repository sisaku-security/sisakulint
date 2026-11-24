package rules

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// SecretExfiltration is the rule secret-exfiltration: a request a run
// sends (curl, wget, gh api) carries a secret or the job's token to a
// destination the workflow names, which holds unless a file of facts or
// --fact says to trust the destination with the secret
// (request.destination-trusted).
// It reads no summary in a job that GitHub skips in every run
// (AlwaysSkipped): nothing of such a job runs.
var SecretExfiltration lint.Rule = withExamples(lint.WithView[ir.SecretExfiltrationReader](secretExfiltration{}, ir.SecretExfiltrationView))

// SecretExfiltrationID is the ID of secret-exfiltration.
var SecretExfiltrationID = lint.MustRuleID("secret-exfiltration")

type secretExfiltration struct{}

func (secretExfiltration) Meta() lint.Meta { return secretExfiltrationMeta }

// githubHosts are the hosts of GitHub a request to which gives GitHub
// nothing it does not hold: GitHub holds the secrets.
var githubHosts = []string{"github.com", "api.github.com", "uploads.github.com"}

func (secretExfiltration) Check(_ context.Context, c *lint.RuleContext, v ir.SecretExfiltrationReader) error {
	for _, s := range v.Sinks() {
		if s.AlwaysSkipped() {
			continue // GitHub skips its job in every run
		}
		reportCallsNotRead(c, s.CallsNotRead())
		seen := map[string]int{} // per sink: the Fingerprint's place tells the sinks apart
		for _, r := range s.Requests() {
			if len(r.Secrets) == 0 || attackerDestination(r) || ownDestination(r) {
				continue
			}
			dest, ok := destinationOf(r)
			if !ok {
				// the places of the findings the destination would give
				var carried []lint.Related
				for _, x := range sentSecrets(r) {
					carried = append(carried, lint.Related{Location: c.At(x.secret.At), Note: "the request carries " + x.name.String() + " here"})
				}
				c.Inconclusive(lint.InconclusiveDraft{KindID: destinationUnknownKind, Location: c.At(r.At), Related: carried,
					Note: fmt.Sprintf("%s sends a secret to a destination whose host has no name the file of facts can answer for", r.Command)})
				continue
			}
			for _, x := range sentSecrets(r) {
				sec, name := x.secret, x.name
				key := fmt.Sprintf("%s#%d#%s", r.Command, r.Occurrence, name)
				seen[key]++
				c.Report(lint.FindingDraft{
					Location:  c.At(sec.At),
					Anchor:    fmt.Sprintf("%s#%d", key, seen[key]),
					Related:   []lint.Related{{Location: c.At(r.At), Note: "the request goes to " + dest.String() + " here"}},
					Condition: factCond(facts.RequestDestinationTrusted{Secret: name, Destination: dest}, false),
					Args:      SecretExfiltrationUntrustedDestination{Command: r.Command, Secret: name.String(), Destination: dest.String()},
				})
			}
		}
	}
	return nil
}

// attackerDestination is whether an attacker's value may decide the host
// of r: request-forgery reports it (attacker-destination).
// sentSecret is a secret a request sends, and its name.
type sentSecret struct {
	secret ir.CarriedSecret
	name   facts.SecretName
}

// sentSecrets are the secrets of r that the rule reports, each name once:
// not a whole-secrets (secret-exposure reports it), and of a name a fact
// can hold.
func sentSecrets(r ir.RequestSite) []sentSecret {
	var out []sentSecret
	done := map[string]bool{}
	for _, sec := range r.Secrets {
		if sec.Whole {
			continue
		}
		name, err := facts.ParseSecretName(secretName(sec))
		if err != nil || done[name.String()] {
			continue
		}
		done[name.String()] = true
		out = append(out, sentSecret{sec, name})
	}
	return out
}

func attackerDestination(r ir.RequestSite) bool {
	if len(r.HostRefs) > 0 {
		return true
	}
	return r.Destination == analysis.DestinationNamed && r.DestinationRef.Verdict != analysis.NotControlled
}

// ownDestination is whether r goes where nobody but GitHub and the job
// itself receive it: a host of GitHub, a service of the job, or the
// runner itself when the runner is GitHub's.
func ownDestination(r ir.RequestSite) bool {
	switch r.Destination {
	case analysis.DestinationGitHub:
		return true
	case analysis.DestinationLiteral:
	default:
		return false
	}
	h := r.DestinationHost
	switch {
	case slices.Contains(githubHosts, h):
		return true
	case slices.ContainsFunc(r.ServiceNames, func(n string) bool { return strings.EqualFold(n, h) }):
		return true
	}
	return r.RunnerHosting == analysis.RunnerHostingGitHub && loopback(h)
}

// loopback is whether the host h is the machine itself: localhost,
// 127.0.0.0/8, ::1, or the unspecified address (0.0.0.0, ::), to which a
// connection goes to the machine itself.
func loopback(h string) bool {
	if h == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(strings.Trim(h, "[]"))
	return err == nil && (a.IsLoopback() || a.IsUnspecified())
}

// destinationOf is how the fact names where r goes: the host, or the path
// of the value that names the host; false when it has no name.
func destinationOf(r ir.RequestSite) (facts.RequestDestination, bool) {
	var d facts.RequestDestination
	var err error
	switch r.Destination {
	case analysis.DestinationLiteral:
		d, err = facts.ParseRequestDestination(r.DestinationHost)
	case analysis.DestinationNamed:
		d, err = facts.RequestDestinationOfPath(r.DestinationPath)
	default:
		return d, false
	}
	return d, err == nil
}

var (
	githubSecrets = lint.MustCitation("https://github.com/github/docs/blob/dae83f7d28f3b8e10015bd6b6d8b72267cedceca/content/actions/concepts/security/secrets.md")

	requestCarries     = lint.MustPreconditionID("request-carries")
	githubHoldsSecrets = lint.MustPreconditionID("github-holds-secrets")

	destinationUnknownKind = lint.MustInconclusiveKindID("destination-unknown")
)

// exfiltrationBase is the CVSS of secret-exfiltration.untrusted-destination:
// the attacker is whoever holds the server of the destination.
var exfiltrationBase = lint.CVSS{
	AV: metric(lint.AttackVectorNetwork, "the server of the destination receives the request over the network"),
	AC: metric(lint.AttackComplexityHigh, "to hold the server of the destination, the attacker breaches the vendor or registers a lapsed domain"),
	AT: metric(lint.AttackRequirementsPresent, "the finding holds when the destination is not to be trusted with the secret (request.destination-trusted false; a file of facts or --fact can answer true): the holder of the server is the attacker"),
	PR: metric(lint.PrivilegesRequiredNone, "nothing of the repository is needed"),
	UI: metric(lint.UserInteractionNone, "the workflow sends the request whenever it runs"),
	VC: metric(lint.ImpactHigh, "the server receives the secret or the token the request carries"),
	VI: metric(lint.ImpactHigh, "with the token, when the job's token can write, the holder writes to the repository while the job runs; a secret gives what the secret can write"),
	VA: metric(lint.ImpactNone, "the request makes nothing of the job unavailable as such"),
	SC: metric(lint.ImpactHigh, "the secrets open what is past the job: clouds, registries, other repositories"),
	SI: metric(lint.ImpactHigh, "with the secrets the holder writes to what they open"),
	SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
}

var secretExfiltrationMeta = lint.Meta{
	ID:       SecretExfiltrationID,
	Problem:  "a request of the workflow carries a secret or the job's token to a destination the workflow names; whoever runs the server of the destination, or takes the server over, receives the secret or the token. Whether the destination is to be trusted with the secret is not in the workflow, so the finding holds until a file of facts says that the destination is trusted with the secret",
	Expected: "every destination that receives a secret is the service that the secret is for, and a file of facts says so for each pair of the secret and the destination (request.destination-trusted)",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessCredentialLeak}, AttackMeans: []lint.AttackMeans{lint.AttackMeansNone}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textSecretExfiltrationUntrustedDestination,
			Attackers:       []lint.Attacker{lint.AttackerDestinationHolder},
			Preconditions:   []lint.PreconditionID{requestCarries, githubHoldsSecrets},
			FactKinds:       []facts.Kind{facts.KindRequestDestinationTrusted},
			CVSS:            exfiltrationBase,
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report was found of a secret a workflow sent to a destination that its holder misused (searched 2026-10-19: the 43 findings of the upstream rule on 4,974 workflows of public repositories, none of which looked like a theft, and the issues and pull requests of sisakulint that ported the rule)"),
		},
	},
	Threat: lint.Threat{
		Actors: []lint.Actor{{
			Attacker: lint.AttackerDestinationHolder,
			Via:      "runs the server of a destination the workflow names, or takes the server over",
			Gains:    []lint.Gain{lint.GainReadSecrets, lint.GainWriteWithToken},
		}},
		Preconditions: []lint.Precondition{
			{
				ID:    requestCarries,
				Text:  "the request carries its credentials to the host its URL names: curl sends -H, -u, --oauth2-bearer, cookies and the body there, and gh api sends GH_ENTERPRISE_TOKEN to any host not of GitHub",
				Cites: []lint.Citation{curlHeader, ghAPIHTTP, goGHAuth},
			},
			{
				ID:    githubHoldsSecrets,
				Text:  "GitHub decrypts the secrets to give them to the run, so a request to a host of GitHub gives GitHub nothing GitHub does not hold; the rule leaves out such a request, as it leaves out a service of the job and, on a GitHub-hosted runner, the runner itself (localhost), where only the job listens",
				Cites: []lint.Citation{githubSecrets},
			},
		},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	InconclusiveKinds: withRemoteCalleeUnknown(withCallBodyUnknown([]lint.InconclusiveKind{
		{ID: destinationUnknownKind, Text: "a request that carries a secret to a destination whose host has no name a file of facts can answer for: the output of $( ), a value the script builds, the response of an API", Disposition: lint.Limitation(lint.DeciderRunTime)},
	})),
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		splitEnvNameLimit,
		secretInputLimit,
		{ID: lint.MustUndetectedFormID("attacker-destination"), Text: "a request whose host an attacker's value may decide, or whose control is not analyzed", Disposition: lint.OtherRule(RequestForgeryID)},
		{ID: lint.MustUndetectedFormID("whole-secrets"), Text: "the whole secrets context in a request (toJSON(secrets)): the fact names one secret", Disposition: lint.OtherRule(SecretExposureID)},
		{ID: lint.MustUndetectedFormID("other-command"), Text: "a request sent by a command other than curl, wget and gh api: httpie, nc, dig, a script of python or node", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("action-request"), Text: "a secret an action sends where its with or its code says, such as an upload of a coverage report", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("file"), Text: "a secret that reaches the request through a file", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("config-file"), Text: "a credential from a file curl reads: -K, the default .curlrc, --netrc", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustUndetectedFormID("unwalked-place"), Text: "a command in a place the rule does not walk: the commands of an arm of case, $( ) in the words of case", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("proxy"), Text: "a secret sent to a proxy, such as with -U or --proxy-user of curl: the rule reads the destination of the request, not its proxy", Disposition: lint.Todo(lint.NeedSameFile)},
		otherShellLimit,
		lastpipeLimit,
		nameNotLiteralLimit,
		recursiveUnsetLocalLimit,
		unsetCallerLocalLimit,
		severalDestinationsLimit,
	}),
	FalsePositiveForms: []lint.FalsePositiveForm{
		branchNotRun(kindSecretExfiltrationUntrustedDestination),
		{ID: lint.MustFalsePositiveFormID("trusted-destination"), Text: "a destination that is the service the secret is for, such as an API key sent to the API that issued the key", FindingKinds: []lint.FindingKindID{kindSecretExfiltrationUntrustedDestination}, FactKinds: []facts.Kind{facts.KindRequestDestinationTrusted}},
		{ID: lint.MustFalsePositiveFormID("fork-pull-request"), Text: "a job that runs only for a pull request from a fork (pull_request, pull_request_review or pull_request_review_comment, with an if such as github.event.pull_request.head.repo.fork == true or github.event.pull_request.head.repo.full_name != github.repository), in a base repository that is not a fork: the workflow run for a pull request from a fork has no secret except GITHUB_TOKEN, unless the settings of a private repository send secrets to such workflow runs (the fact repo.fork-pr-secrets), so a request that the job sends to a host (with curl, wget or gh api) carries an empty value in the place of a secret other than GITHUB_TOKEN; the rule does not distinguish a workflow run for a pull request from a fork from a workflow run for a pull request from a branch of the repository", FindingKinds: []lint.FindingKindID{kindSecretExfiltrationUntrustedDestination}, Disposition: lint.Todo(lint.NeedSameFile, lint.NeedFact)},
		{ID: lint.MustFalsePositiveFormID("job-listener"), Text: "a destination on the runner itself or in the job's network that only the job listens on, such as a server the job starts, on a runner that is not known to be GitHub's", FindingKinds: []lint.FindingKindID{kindSecretExfiltrationUntrustedDestination}, FactKinds: []facts.Kind{facts.KindRequestDestinationTrusted}},
	},
}
