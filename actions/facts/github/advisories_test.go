package github

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// advisoryBody is one advisory as GET /advisories gives it, with a
// vulnerability of the package pkg and one of another ecosystem.
func advisoryBody(id, severity, rng, fixed, withdrawn, pkg string) string {
	fp, wd := `null`, `null`
	if fixed != "" {
		fp = `"` + fixed + `"`
	}
	if withdrawn != "" {
		wd = `"` + withdrawn + `"`
	}
	return `{"ghsa_id":"` + id + `","severity":"` + severity + `","withdrawn_at":` + wd + `,"vulnerabilities":[` +
		`{"package":{"ecosystem":"actions","name":"` + pkg + `"},"vulnerable_version_range":"` + rng + `","first_patched_version":` + fp + `},` +
		`{"package":{"ecosystem":"npm","name":"x"},"vulnerable_version_range":"< 9","first_patched_version":"9"}]}`
}

// TestPackageAdvisories: reviewed and malware advisories of the package
// asked about, the withdrawn left out, the package compared
// without case.
func TestPackageAdvisories(t *testing.T) {
	const q = "/advisories?ecosystem=actions&affects="
	reviewed := `[` + advisoryBody("GHSA-cxww-7g56-2vh6", "high", ">= 4.0.0, < 4.1.3", "4.1.3", "", "actions/download-artifact") + `,` +
		advisoryBody("GHSA-jj69-4grx-fqj5", "critical", "< 0.1.22", "0.1.22", "2026-09-24T20:05:24Z", "actions/download-artifact") + `]`
	malware := `[` + advisoryBody("GHSA-qmg3-hpqr-gqvc", "unknown", "= 1", "", "", "Actions/Download-Artifact") + `]`
	f := &fake{answers: map[string]func(http.ResponseWriter){
		q + "actions%2Fdownload-artifact%40v4.1.2&per_page=100&type=reviewed": body(200, reviewed),
		q + "actions%2Fdownload-artifact%40v4.1.2&per_page=100&type=malware":  body(200, malware),
		q + "actions%2Fcheckout&per_page=100&type=reviewed":                   body(200, `[]`),
		q + "actions%2Fcheckout&per_page=100&type=malware":                    body(200, `[]`),
		q + "o%2Fbad&per_page=100&type=reviewed":                              body(500, `{}`),
		q + "o%2Fodd&per_page=100&type=reviewed":                              body(200, `[`+advisoryBody("GHSA-cxww-7g56-2vh6", "severe", "< 1", "", "", "o/odd")+`]`),
		q + "o%2Fpaged&per_page=100&type=reviewed": func(w http.ResponseWriter) {
			w.Header().Set("Link", `<x>; rel="next"`)
			w.WriteHeader(200)
			w.Write([]byte(`[]`))
		},
		// GHSA-vqf5-2xx6-9wfm has two ranges of github/codeql-action, and
		// GitHub gives both for a version only one of them has
		q + "github%2Fcodeql-action%40v3.28.2&per_page=100&type=reviewed": body(200, `[{"ghsa_id":"GHSA-vqf5-2xx6-9wfm","severity":"high","withdrawn_at":null,"vulnerabilities":[`+
			`{"package":{"ecosystem":"actions","name":"github/codeql-action"},"vulnerable_version_range":">= 3.26.11, <= 3.28.2","first_patched_version":"3.28.3"},`+
			`{"package":{"ecosystem":"actions","name":"github/codeql-action"},"vulnerable_version_range":">= 2.26.11, < 3.0.0","first_patched_version":null}]}]`),
		q + "github%2Fcodeql-action%40v3.28.2&per_page=100&type=malware": body(200, `[{"ghsa_id":"GHSA-vqf5-2xx6-9wfm","severity":"high","withdrawn_at":null,"vulnerabilities":[`+
			`{"package":{"ecosystem":"actions","name":"github/codeql-action"},"vulnerable_version_range":">= 3.26.11, <= 3.28.2","first_patched_version":"3.28.3"}]}]`),
	}}
	r := start(t, f, "")
	ctx := context.Background()
	ask := func(pkg, version string) facts.Answer[[]facts.Advisory] {
		p, err := facts.ParsePackageName(pkg)
		if err != nil {
			t.Fatal(err)
		}
		fq := facts.PackageAdvisories{Package: p}
		if version != "" {
			if fq.Version, err = facts.ParsePackageVersion(version); err != nil {
				t.Fatal(err)
			}
		}
		return fq.Ask(ctx, r)
	}
	got := ask("actions/download-artifact", "v4.1.2")
	var ids []string
	for _, a := range got.Value {
		ids = append(ids, a.GHSAID.String()+":"+a.Severity.String()+":"+a.FirstPatchedVersion.String())
	}
	if got.State != facts.StateFound || strings.Join(ids, " ") != "GHSA-cxww-7g56-2vh6:high:4.1.3 GHSA-qmg3-hpqr-gqvc:unknown:" {
		t.Errorf("download-artifact: %+v %v", got, ids)
	}
	if got := ask("actions/checkout", ""); got.State != facts.StateFound || got.Value == nil || len(got.Value) != 0 {
		t.Errorf("checkout: %+v", got)
	}
	if got := ask("o/bad", ""); got.State != facts.StateUnknown {
		t.Errorf("bad: %+v", got)
	}
	if got := ask("o/odd", ""); got.State != facts.StateUnknown {
		t.Errorf("a severity GitHub does not have: %+v", got)
	}
	if got := ask("o/paged", ""); got.State != facts.StateUnknown {
		t.Errorf("more pages: %+v", got)
	}
	got = ask("github/codeql-action", "v3.28.2")
	var ranges []string
	for _, a := range got.Value {
		ranges = append(ranges, a.VulnerableVersionRange.String())
	}
	if got.State != facts.StateFound || strings.Join(ranges, " | ") != ">= 3.26.11, <= 3.28.2 | >= 2.26.11, < 3.0.0" {
		t.Errorf("every range of the package, once, though in both lists: %v", ranges)
	}
	if got := (facts.PackageAdvisories{}).Ask(ctx, r); got.State != facts.StateUnknown {
		t.Errorf("no package: %+v", got)
	}
	for _, h := range f.headers {
		if h.Get("Authorization") != "" {
			t.Error("a token was sent with no token given")
		}
	}
}
