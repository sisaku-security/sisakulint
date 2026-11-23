package facts

import (
	"encoding/json"
	"testing"
)

func TestCleanInputPath(t *testing.T) {
	for in, want := range map[string]string{"./a.yml": "a.yml", "a//b": "a/b", ".github/workflows/x.yml": ".github/workflows/x.yml"} {
		n, err := CleanInputPath(in)
		if err != nil || n.String() != want {
			t.Errorf("CleanInputPath(%q) = %v, %v; want %s", in, n, err, want)
		}
	}
	for _, s := range []string{"", "../a", "a/../b", "/a", "."} {
		if _, err := CleanInputPath(s); err == nil {
			t.Errorf("CleanInputPath(%q): no error", s)
		}
	}
	if _, err := json.Marshal(InputPath{}); err == nil {
		t.Error("Marshal of the zero InputPath: no error")
	}
	a, b := MustCleanInputPath("a.yml"), MustCleanInputPath("b.yml")
	if CompareInputPaths(a, b) >= 0 || CompareInputPaths(b, a) <= 0 || CompareInputPaths(a, a) != 0 {
		t.Error("CompareInputPaths is not the order of the strings")
	}
}

func TestWalkedInputPath(t *testing.T) {
	if p := WalkedInputPath("."); p.String() != "." {
		t.Errorf("WalkedInputPath(.) = %s", p)
	}
	defer func() {
		if recover() == nil {
			t.Error("WalkedInputPath(../a) did not panic")
		}
	}()
	WalkedInputPath("../a")
}

func TestPackageName(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"Tj-Actions/Changed-Files", "tj-actions/changed-files"},
		{"super-linter/super-linter/slim", "super-linter/super-linter/slim"},
		{"github/codeql-action/init", "github/codeql-action/init"},
		{"Owner/Repo/Some/Path", "owner/repo/Some/Path"},
	} {
		p, err := ParsePackageName(c.in)
		if err != nil || p.String() != c.want {
			t.Errorf("ParsePackageName(%q) = %q, %v; want %q", c.in, p, err, c.want)
		}
	}
	for _, bad := range []string{"", "owner", "owner/", "/repo", "o/r/", "o/r@v1", "o/r/a b", "https://github.com/o/r"} {
		if _, err := ParsePackageName(bad); err == nil {
			t.Errorf("ParsePackageName(%q) took it", bad)
		}
	}
}

func TestPackageVersion(t *testing.T) {
	for _, c := range []struct {
		in    string
		parts int
	}{{"v4", 1}, {"4.1.2", 3}, {"v4.1.2-beta", 3}, {"v2.283.4", 3}, {"1.0", 2}} {
		v, err := ParsePackageVersion(c.in)
		if err != nil || v.String() != c.in || v.Parts() != c.parts {
			t.Errorf("ParsePackageVersion(%q) = %q (%d parts), %v", c.in, v, v.Parts(), err)
		}
	}
	for _, bad := range []string{"", "main", "release/v1", "v", "v4.", "4..1", "v4.1+build", "1234567890"} {
		if _, err := ParsePackageVersion(bad); err == nil {
			t.Errorf("ParsePackageVersion(%q) took it", bad)
		}
	}
	for _, l := range [][2]string{{"4.1.2", "4.1.3"}, {"v4.1.2", "4.1.10"}, {"4", "4.0.1"}, {"4.1.3-rc1", "4.1.3"}, {"4.1.3-a", "4.1.3-b"}, {"4.1.3-beta.2", "4.1.3-beta.10"}, {"4.1.3-1", "4.1.3-alpha"}, {"4.1.3-beta", "4.1.3-beta.1"}} {
		a, _ := ParsePackageVersion(l[0])
		b, _ := ParsePackageVersion(l[1])
		if ComparePackageVersions(a, b) >= 0 || ComparePackageVersions(b, a) <= 0 {
			t.Errorf("%s is not less than %s", l[0], l[1])
		}
	}
	a, _ := ParsePackageVersion("v4.1.2")
	b, _ := ParsePackageVersion("4.1.2")
	if ComparePackageVersions(a, b) != 0 {
		t.Error("v4.1.2 and 4.1.2 differ")
	}
	if _, err := json.Marshal(PackageVersion{}); err == nil {
		t.Error("Marshal of the zero PackageVersion: no error")
	}
}

func TestGHSAID(t *testing.T) {
	if _, err := ParseGHSAID("GHSA-mrrh-fwg8-r2c3"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"", "GHSA-mrrh-fwg8", "ghsa-mrrh-fwg8-r2c3", "GHSA-aaaa-bbbb-cccc", "CVE-2025-30066"} {
		if _, err := ParseGHSAID(bad); err == nil {
			t.Errorf("ParseGHSAID(%q) took it", bad)
		}
	}
}

func TestAdvisoryJSON(t *testing.T) {
	in := `{"ghsa_id":"GHSA-cxww-7g56-2vh6","severity":"high","vulnerable_version_range":">= 4.0.0, < 4.1.3","first_patched_version":"4.1.3"}`
	var a Advisory
	if err := json.Unmarshal([]byte(in), &a); err != nil {
		t.Fatal(err)
	}
	if a.Severity != AdvisorySeverityHigh || a.FirstPatchedVersion.String() != "4.1.3" {
		t.Errorf("%+v", a)
	}
	out, _ := json.Marshal(a)
	var back Advisory
	if err := json.Unmarshal(out, &back); err != nil || back != a {
		t.Errorf("round trip: %s", out)
	}
	var none Advisory
	if err := json.Unmarshal([]byte(`{"ghsa_id":"GHSA-qmg3-hpqr-gqvc","severity":"high","vulnerable_version_range":"= 1"}`), &none); err != nil || !none.FirstPatchedVersion.IsZero() {
		t.Errorf("%+v %v", none, err)
	}
	for _, bad := range []string{
		`{"ghsa_id":"GHSA-qmg3-hpqr-gqvc","severity":"high"}`,
		`{"ghsa_id":"GHSA-qmg3-hpqr-gqvc","vulnerable_version_range":"= 1"}`,
		`{"ghsa_id":"GHSA-qmg3-hpqr-gqvc","severity":"severe","vulnerable_version_range":"= 1"}`,
		`{"ghsa_id":"GHSA-qmg3-hpqr-gqvc","severity":"high","vulnerable_version_range":"= 1","cvss":1}`,
	} {
		if err := json.Unmarshal([]byte(bad), &none); err == nil {
			t.Errorf("took %s", bad)
		}
	}
}

func TestParseUsesPath(t *testing.T) {
	for _, s := range []string{"a", "a/b", ".github/actions/x"} {
		p, err := ParseUsesPath(s)
		if err != nil || p.String() != s {
			t.Errorf("ParseUsesPath(%q) = %q, %v", s, p, err)
		}
	}
	for _, bad := range []string{"", "/a", "a/", "a//b", "./a", "a/../b", "..", `a\b`, "a@v1", "a b"} {
		if _, err := ParseUsesPath(bad); err == nil {
			t.Errorf("ParseUsesPath(%q) took it", bad)
		}
	}
}

// TestFactArgument: an InputPath with a backslash, which a file name may
// hold, is no argument of a fact (the schema refuses it).
func TestFactArgument(t *testing.T) {
	for in, want := range map[string]bool{"a/b.yml": true, `a\b.yml`: false, `.github/workflows/a\b.yml`: false} {
		p, ok := MustCleanInputPath(in).FactArgument()
		if ok != want || (ok && p.String() != in) {
			t.Errorf("FactArgument(%q) = %v, %v; want %v", in, p, ok, want)
		}
	}
}
