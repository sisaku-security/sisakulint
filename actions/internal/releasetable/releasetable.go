// Package releasetable checks a Go table of the releases of an action
// against the releases its repository has published since the table was
// made. It asks GitHub, so it runs only with ACTIONS_UPSTREAM=1.
package releasetable

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// EnvVar turns the check on: it asks the network.
const EnvVar = "ACTIONS_UPSTREAM"

// CheckTable fails t when a release of repo, published on since or a later
// day, points to a commit known does not have: a Go table of releases made
// on since misses it.
func CheckTable(t testing.TB, repo facts.Repo, since time.Time, known func(facts.SHA) bool) {
	t.Helper()
	if os.Getenv(EnvVar) != "1" {
		t.Skip(EnvVar + "=1 asks GitHub for the releases")
	}
	checkTable(t, newClient("https://api.github.com", token()), repo, since, known)
}

func checkTable(t testing.TB, c *client, repo facts.Repo, since time.Time, known func(facts.SHA) bool) {
	t.Helper()
	rs, err := c.releasesSince(context.Background(), repo, tableSince(since))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if !known(r.commit) {
			t.Errorf("the release %s of %s (%s, published %s) is in no table: add it to the table",
				r.tag, repo, r.commit, r.published.Format(time.DateOnly))
		}
	}
}

// tableSince is when to look for releases a table taken on the day since
// may miss: the day before, as a release published early on that day in a
// time zone ahead of UTC is on the day before in UTC. Releases the table
// has pass anyway.
func tableSince(since time.Time) time.Time { return since.AddDate(0, 0, -1) }

// token is the GitHub token of the environment: GH_TOKEN, else
// GITHUB_TOKEN, else none.
func token() string {
	if t := os.Getenv("GH_TOKEN"); t != "" {
		return t
	}
	return os.Getenv("GITHUB_TOKEN")
}

// client asks the GitHub REST API.
type client struct {
	api   *url.URL
	token string
	http  *http.Client
}

func newClient(api, token string) *client {
	a, err := url.Parse(api)
	if err != nil {
		panic(err)
	}
	return &client{api: a, token: token, http: &http.Client{Timeout: 60 * time.Second}}
}

func (c *client) getJSON(ctx context.Context, path string, q url.Values, v any) error {
	u := *c.api
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", u.String(), resp.StatusCode)
	}
	return json.Unmarshal(body, v)
}

// release is a release of a repository: its tag, when it was published,
// and the commit its tag points to.
type release struct {
	tag       string
	published time.Time
	commit    facts.SHA
}

// releasesSince are the releases of repo published on since or a later
// day, drafts left out.
func (c *client) releasesSince(ctx context.Context, repo facts.Repo, since time.Time) ([]release, error) {
	var out []release
	for page := 1; ; page++ {
		var rs []struct {
			TagName     string     `json:"tag_name"`
			Draft       bool       `json:"draft"`
			PublishedAt *time.Time `json:"published_at"`
		}
		q := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		if err := c.getJSON(ctx, "/repos/"+repo.String()+"/releases", q, &rs); err != nil {
			return nil, err
		}
		for _, r := range rs {
			if r.Draft || r.PublishedAt == nil || r.PublishedAt.UTC().Before(since) {
				continue
			}
			var cm struct {
				SHA string `json:"sha"`
			}
			if err := c.getJSON(ctx, "/repos/"+repo.String()+"/commits/refs/tags/"+r.TagName, nil, &cm); err != nil {
				return nil, err
			}
			sha, err := facts.ParseSHA(cm.SHA)
			if err != nil {
				return nil, err
			}
			out = append(out, release{r.TagName, *r.PublishedAt, sha})
		}
		if len(rs) < 100 {
			return out, nil
		}
	}
}
