package analysis

// DestinationKind is where the host of a request a run sends comes from.
type DestinationKind uint8

const (
	DestinationUnset   DestinationKind = iota
	DestinationLiteral                 // written in the workflow
	DestinationNamed                   // the value of a context's path, such as secrets.UPLOAD_API
	DestinationUnnamed                 // made in the script: $( ), a variable no env nor assignment gives
	DestinationGitHub                  // the API or the server of GitHub: github.api_url, $GITHUB_API_URL, github.server_url, $GITHUB_SERVER_URL, or a path of gh api
)

var destinationKindNames = [...]string{"DestinationUnset", "DestinationLiteral", "DestinationNamed", "DestinationUnnamed", "DestinationGitHub"}

func (k DestinationKind) String() string { return destinationKindNames[k] }

// RunnerHosting is who runs the machine a job runs on, as its runs-on
// tells.
type RunnerHosting uint8

const (
	RunnerHostingUnknown    RunnerHosting = iota // a group, a label of neither, or a ${{ }} the matrix does not give
	RunnerHostingGitHub                          // every label is one of GitHub's hosted runners: a new virtual machine for each job
	RunnerHostingSelfHosted                      // a label is self-hosted, which every self-hosted runner has
)

var runnerHostingNames = [...]string{"RunnerHostingUnknown", "RunnerHostingGitHub", "RunnerHostingSelfHosted"}

func (h RunnerHosting) String() string { return runnerHostingNames[h] }
