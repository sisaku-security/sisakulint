package boundary

import (
	"io"
	"net/http"
	"os"
	"regexp"
	"testing"

	"github.com/gh-intel/sisakulint/actions/internal/releasetable"
)

// blobPath is the part of a URL of a file on GitHub before its commit.
var blobPath = regexp.MustCompile("^https://github.com/([^/]+/[^/]+)/blob/")

// TestQuotesInSource fetches the source of every quote at its pinned
// commit and finds its text there, only with ACTIONS_UPSTREAM=1 (it asks
// the network), before a merge.
func TestQuotesInSource(t *testing.T) {
	if os.Getenv(releasetable.EnvVar) != "1" {
		t.Skip(releasetable.EnvVar + "=1 fetches the sources of the quotes")
	}
	tb := rows()
	var qs []Quote
	for _, g := range tb.grants {
		qs = append(qs, g.Quotes...)
	}
	for _, b := range tb.baselines {
		qs = append(qs, b.Quotes...)
	}
	for _, c := range tb.channels {
		qs = append(qs, c.Quotes...)
	}
	for _, p := range tb.pathways {
		qs = append(qs, p.Quotes...)
	}
	for _, b := range tb.barriers {
		qs = append(qs, b.Quotes...)
	}
	for _, w := range tb.writes {
		qs = append(qs, w.Quotes...)
	}
	sources := map[string]string{}
	for _, q := range qs {
		u := blobPath.ReplaceAllString(q.Citation.String(), "https://raw.githubusercontent.com/$1/")
		body, ok := sources[u]
		if !ok {
			resp, err := http.Get(u)
			if err != nil {
				t.Fatalf("%s: %v", u, err)
			}
			b, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("%s: %d %v", u, resp.StatusCode, err)
			}
			body = string(b)
			sources[u] = body
		}
		if !q.FoundIn([]byte(body)) {
			t.Errorf("%s does not have %q within the JSON pointer %q", q.Citation, q.Text, q.JSONPointer)
		}
	}
	t.Logf("%d quotes of %d sources", len(qs), len(sources))
}
