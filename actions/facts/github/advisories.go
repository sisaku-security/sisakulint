package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// advisoryTypes are the types of advisory package.advisories asks for:
// GET /advisories leaves malware out unless asked.
var advisoryTypes = []string{"reviewed", "malware"}

// packageAdvisories answers package.advisories: GET /advisories of the
// actions ecosystem, affects=<package>[@<version>], which GitHub compares
// without case and, with a version, against the range of each advisory.
// A withdrawn advisory is left out: GitHub gives it, marked withdrawn_at.
func (r *resolver) packageAdvisories(ctx context.Context, q facts.PackageAdvisories) facts.RawAnswer {
	if q.Package.IsZero() {
		return unknown("github: the fact names no package")
	}
	affects := q.Package.String()
	if !q.Version.IsZero() {
		affects += "@" + q.Version.String()
	}
	out := []facts.Advisory{}
	seen := map[facts.Advisory]bool{} // an advisory in both lists of types is one
	for _, typ := range advisoryTypes {
		u := r.base + "/advisories?ecosystem=actions&affects=" + url.QueryEscape(affects) + "&per_page=100&type=" + typ
		resp, why := r.get(ctx, facts.KindPackageAdvisories, u, "application/vnd.github+json", 4<<20)
		if why != "" {
			return unknown(why)
		}
		switch {
		case resp.status != http.StatusOK:
			return unknown("github: HTTP " + strconv.Itoa(resp.status))
		case resp.next:
			return unknown("github: the advisories of the package have more pages")
		}
		var list []struct {
			GHSAID          string  `json:"ghsa_id"`
			Severity        string  `json:"severity"`
			WithdrawnAt     *string `json:"withdrawn_at"`
			Vulnerabilities []struct {
				Package struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				} `json:"package"`
				Range        string  `json:"vulnerable_version_range"`
				FirstPatched *string `json:"first_patched_version"`
			} `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(resp.body, &list); err != nil {
			return unknown("github: the list of advisories is not one")
		}
		for _, a := range list {
			if a.WithdrawnAt != nil {
				continue
			}
			for _, v := range a.Vulnerabilities {
				if v.Package.Ecosystem != "actions" || !strings.EqualFold(v.Package.Name, q.Package.String()) {
					continue
				}
				fields := map[string]string{"ghsa_id": a.GHSAID, "severity": a.Severity, "vulnerable_version_range": v.Range}
				if v.FirstPatched != nil {
					fields["first_patched_version"] = *v.FirstPatched
				}
				raw, _ := json.Marshal(fields)
				var adv facts.Advisory
				if err := json.Unmarshal(raw, &adv); err != nil {
					return unknown("github: the advisory " + a.GHSAID + " is not one: " + err.Error())
				}
				if !seen[adv] {
					seen[adv] = true
					out = append(out, adv)
				}
			}
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return unknown("github: " + err.Error())
	}
	return facts.RawAnswer{State: facts.StateFound, Value: b}
}
