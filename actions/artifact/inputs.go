package artifact

import (
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/prcode"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// knownAction is an action the analysis reads: one that leaves a credential in
// a file (credentialsOf), or actions/upload-artifact.
type knownAction uint8

const (
	actionNone knownAction = iota
	actionCheckout
	actionPagesDeploy
	actionAuth
	actionDotnet
	actionUpload
)

// actionRepos are the repositories of the actions, by action.
var actionRepos = [...]facts.Repo{actionCheckout: prcode.CheckoutRepo, actionPagesDeploy: pagesDeployRepo, actionAuth: authRepo, actionDotnet: dotnetRepo, actionUpload: UploadRepo}

// input is an input of an action the analysis reads, other than
// actions/checkout's (analysis.CheckoutInput).
type input uint8

const (
	inputSSHKey                   input = iota // JamesIves/github-pages-deploy-action
	inputToken                                 // JamesIves/github-pages-deploy-action
	inputCreateCredentialsFile                 // google-github-actions/auth
	inputCredentialsJSON                       // google-github-actions/auth
	inputWorkloadIdentityProvider              // google-github-actions/auth
	inputSourceURL                             // actions/setup-dotnet
	inputPath                                  // actions/upload-artifact
	inputIncludeHiddenFiles                    // actions/upload-artifact
)

var inputNames = [...]string{"ssh-key", "token", "create_credentials_file", "credentials_json", "workload_identity_provider", "source-url", "path", "include-hidden-files"}

func (i input) String() string { return inputNames[i] }

// actionOf is the action of the step s's uses of another repository,
// without a path under it (actions/upload-artifact/merge is none), with
// its owner and name compared as GitHub compares them; and its ref.
func actionOf(s workflow.Step) (knownAction, string) {
	if s.Uses.Status != workflow.Present {
		return actionNone, ""
	}
	for _, a := range s.Uses.Value.Actions() {
		if !a.Path.IsZero() {
			continue
		}
		r, err := facts.ParseRepo(a.Owner + "/" + a.Repo)
		if err != nil {
			continue
		}
		for k, kr := range actionRepos {
			if k != int(actionNone) && kr == r {
				return knownAction(k), a.Ref
			}
		}
	}
	return actionNone, ""
}
