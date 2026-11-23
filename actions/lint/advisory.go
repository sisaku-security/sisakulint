package lint

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// AdvisoryID is the key of an advisory's page: the name of a page of
// GitHub Security Lab (GHSL-YYYY-NNN and what follows, as in the URL), or
// the ID of a GitHub security advisory (GHSA-xxxx-xxxx-xxxx). A page of
// GitHub Security Lab may have several GHSL IDs; the key is the page's.
// The zero AdvisoryID is none.
type AdvisoryID struct{ s string }

func (a AdvisoryID) String() string               { return a.s }
func (a AdvisoryID) IsZero() bool                 { return a.s == "" }
func (a AdvisoryID) MarshalJSON() ([]byte, error) { return marshalID(a.s, "AdvisoryID") }

// AdvisoryPage is the page of an advisory and its key: what an example
// whose form is the advisory's cites (# advisory: <URL>). Only
// ParseAdvisoryPage makes one.
type AdvisoryPage struct {
	id  AdvisoryID
	url Citation
}

func (p AdvisoryPage) ID() AdvisoryID { return p.id }
func (p AdvisoryPage) URL() Citation  { return p.url }

// MarshalJSON writes the URL.
func (p AdvisoryPage) MarshalJSON() ([]byte, error) { return json.Marshal(p.url.s) }

var ghslPage = regexp.MustCompile(`^GHSL-[0-9]{4}-[0-9]{3,}[A-Za-z0-9_.-]*$`)

// ParseAdvisoryPage reads the URL of an advisory's page, in one of three
// forms: https://securitylab.github.com/advisories/<name>/ (a page of
// GitHub Security Lab, whose name starts with GHSL-YYYY-NNN),
// https://github.com/advisories/<GHSA ID> (the GitHub Advisory Database),
// and https://github.com/<owner>/<repository>/security/advisories/<GHSA
// ID> (an advisory of a repository). There is no query or fragment.
func ParseAdvisoryPage(s string) (AdvisoryPage, error) {
	c, err := ParseCitation(s)
	if err != nil {
		return AdvisoryPage{}, err
	}
	u, err := url.Parse(s)
	if err != nil || u.RawQuery != "" || u.Fragment != "" || strings.Contains(s, "#") || strings.Contains(s, "?") {
		return AdvisoryPage{}, fmt.Errorf("%q is not the page of an advisory: it has a query or a fragment", s)
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	ghsa := func(id string) (AdvisoryPage, error) {
		g, err := facts.ParseGHSAID(id)
		if err != nil {
			return AdvisoryPage{}, err
		}
		return AdvisoryPage{AdvisoryID{g.String()}, c}, nil
	}
	switch {
	case u.Host == "securitylab.github.com" && len(parts) == 3 && parts[0] == "advisories" && parts[2] == "" && ghslPage.MatchString(parts[1]):
		return AdvisoryPage{AdvisoryID{parts[1]}, c}, nil
	case u.Host == "github.com" && len(parts) == 2 && parts[0] == "advisories":
		return ghsa(parts[1])
	case u.Host == "github.com" && len(parts) == 5 && parts[0] != "" && parts[1] != "" && parts[2] == "security" && parts[3] == "advisories":
		return ghsa(parts[4])
	}
	return AdvisoryPage{}, fmt.Errorf("%q is not the page of an advisory: https://securitylab.github.com/advisories/<GHSL-…>/, https://github.com/advisories/<GHSA ID> or https://github.com/<owner>/<repository>/security/advisories/<GHSA ID>", s)
}

// MustAdvisoryPage is ParseAdvisoryPage that panics on an error.
func MustAdvisoryPage(s string) AdvisoryPage { return must(ParseAdvisoryPage(s)) }
