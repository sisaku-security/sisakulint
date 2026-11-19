package releasetable

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// recorder is a testing.TB that keeps what Errorf writes.
type recorder struct {
	testing.TB
	errs []string
}

func (r *recorder) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}
func (r *recorder) Helper() {}

func TestCheckTable(t *testing.T) {
	const old, fresh = "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222"
	routes := map[string]string{
		"/repos/o/r/releases?page=1&per_page=100": `[{"tag_name": "v2", "draft": false, "published_at": "2026-10-10T00:00:00Z"},
			{"tag_name": "v1", "draft": false, "published_at": "2026-10-08T00:00:00Z"},
			{"tag_name": "v0", "draft": false, "published_at": "2026-01-01T00:00:00Z"}]`,
		"/repos/o/r/commits/refs/tags/v2": `{"sha": "` + fresh + `"}`,
		"/repos/o/r/commits/refs/tags/v1": `{"sha": "` + old + `"}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path
		if r.URL.RawQuery != "" {
			key += "?" + r.URL.RawQuery
		}
		body, ok := routes[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(body))
	}))
	defer srv.Close()
	repo, _ := facts.ParseRepo("o/r")
	known := func(s facts.SHA) bool { return s.String() == old }
	rec := &recorder{TB: t}
	checkTable(rec, newClient(srv.URL, ""), repo, time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC), known)
	if len(rec.errs) != 1 || !strings.Contains(rec.errs[0], "v2") || !strings.Contains(rec.errs[0], fresh) {
		t.Errorf("errors %q, want one of v2 (%s)", rec.errs, fresh)
	}
	for _, e := range rec.errs {
		if strings.Contains(e, "docs/") {
			t.Errorf("%q names a path of docs", e)
		}
	}
}

func TestCheckTableNeedsTheVariable(t *testing.T) {
	t.Setenv(EnvVar, "")
	repo, _ := facts.ParseRepo("o/r")
	ok := t.Run("skip", func(t *testing.T) {
		CheckTable(t, repo, time.Now(), func(facts.SHA) bool { return false })
		t.Error("not skipped")
	})
	if !ok {
		t.Error("CheckTable did not skip without " + EnvVar)
	}
}

// TestTableSince: a Go table taken on a day is compared from the day
// before, so that a release published early that day in a time zone ahead
// of UTC is not skipped.
func TestTableSince(t *testing.T) {
	if got := tableSince(time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)); !got.Equal(time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("tableSince = %v", got)
	}
}
