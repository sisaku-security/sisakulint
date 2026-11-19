package lint

import (
	"strings"
	"testing"
)

func TestParseAdvisoryPage(t *testing.T) {
	for _, c := range []struct{ url, key string }{
		{"https://securitylab.github.com/advisories/GHSL-2026-229_ipdxco_unified-github-workflows/", "GHSL-2026-229_ipdxco_unified-github-workflows"},
		{"https://securitylab.github.com/advisories/GHSL-2024-150_GHSL-2024-157_Gradio/", "GHSL-2024-150_GHSL-2024-157_Gradio"},
		{"https://securitylab.github.com/advisories/GHSL-2020-191-KanCraft-kanColleWidget-workflow/", "GHSL-2020-191-KanCraft-kanColleWidget-workflow"},
		{"https://github.com/advisories/GHSA-mrrh-fwg8-r2c3", "GHSA-mrrh-fwg8-r2c3"},
		{"https://github.com/MIC-DKFZ/nnUNet/security/advisories/GHSA-63mx-j37w-gh59", "GHSA-63mx-j37w-gh59"},
	} {
		p, err := ParseAdvisoryPage(c.url)
		if err != nil {
			t.Errorf("%s: %v", c.url, err)
			continue
		}
		if p.ID().String() != c.key || p.URL().String() != c.url {
			t.Errorf("%s: key %q, URL %q; want %q", c.url, p.ID(), p.URL(), c.key)
		}
	}
	for _, s := range []string{
		"",
		"https://securitylab.github.com/advisories/GHSL-2026-229_ipdxco_unified-github-workflows",
		"https://securitylab.github.com/research/GHSL-2026-229_x/",
		"https://securitylab.github.com/advisories/KIN-2026-229_x/",
		"https://securitylab.github.com/advisories/ghsl-2026-229_x/",
		"https://securitylab.github.com/advisories/GHSL-2026-229_x/more/",
		"http://securitylab.github.com/advisories/GHSL-2026-229_x/",
		"https://github.com/advisories/GHSA-mrrh-fwg8-r2c3/",
		"https://github.com/advisories/ghsa-mrrh-fwg8-r2c3",
		"https://github.com/advisories/GHSA-mrrh-fwg8-r2c",
		"https://example.com/advisories/GHSA-mrrh-fwg8-r2c3",
		"https://github.com/advisories/GHSA-mrrh-fwg8-r2c3?x=1",
		"https://github.com/advisories/GHSA-mrrh-fwg8-r2c3#a",
		"https://github.com/o/r/security/advisories/GHSA-mrrh-fwg8-r2c3/x",
		"https://github.com/o/security/advisories/GHSA-mrrh-fwg8-r2c3",
	} {
		if p, err := ParseAdvisoryPage(s); err == nil {
			t.Errorf("%q: %v, no error", s, p.ID())
		}
	}
}

func TestExampleNotesAdvisories(t *testing.T) {
	const a = "https://securitylab.github.com/advisories/GHSL-2026-229_ipdxco_unified-github-workflows/"
	const b = "https://github.com/advisories/GHSA-mrrh-fwg8-r2c3"
	n, err := ParseExampleNotes("# situation: s\n# reason: r\n# advisory: " + a + "\n# advisory: " + b + "\non: push\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Advisories) != 2 || n.Advisories[0].URL().String() != a || n.Advisories[1].URL().String() != b {
		t.Errorf("advisories %v", n.Advisories)
	}
	for _, c := range []struct{ text, err string }{
		{"# advisory: " + a + "\n# advisory: " + a + "\non: push\n", "twice"},
		{"# advisory: " + b + "\n# advisory: https://github.com/o/r/security/advisories/GHSA-mrrh-fwg8-r2c3\non: push\n", "twice"},
		{"# advisory: " + a + "\n#   more\non: push\n", "one line"},
		{"# advisory: https://example.com/x\non: push\n", "advisory"},
	} {
		if _, err := ParseExampleNotes(c.text); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%q: error %v; want %q", c.text, err, c.err)
		}
	}
}
