package rules

import (
	"errors"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// rangeHas is whether the range r of an advisory, as the GitHub
// Advisory Database writes it (comparisons joined by commas, such as
// ">= 4.0.0, < 4.1.3" or "= 1"), has the version v. A version is compared
// by facts.ComparePackageVersions, a missing number read as 0, as GitHub
// reads 4 as 4.0.0. It is used only to choose, of the vulnerabilities of
// an advisory GitHub says affects v, the one whose range has v.
func rangeHas(r facts.VersionRange, v facts.PackageVersion) (bool, error) {
	rng := r.String()
	for _, part := range strings.Split(rng, ",") {
		part = strings.TrimSpace(part)
		op := ""
		for _, o := range []string{">=", "<=", ">", "<", "="} {
			if strings.HasPrefix(part, o) {
				op = o
				break
			}
		}
		if op == "" {
			return false, errors.New("the range " + rng + " has a part with no comparison: " + part)
		}
		bound, err := facts.ParsePackageVersion(strings.TrimSpace(part[len(op):]))
		if err != nil {
			return false, err
		}
		c := facts.ComparePackageVersions(v, bound)
		ok := map[string]bool{">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0, "=": c == 0}[op]
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// rangeBounds are the versions the range r compares with, of those it
// reads.
func rangeBounds(r facts.VersionRange) []facts.PackageVersion {
	var out []facts.PackageVersion
	for _, part := range strings.Split(r.String(), ",") {
		b, err := facts.ParsePackageVersion(strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(part), "<>=")))
		if err == nil {
			out = append(out, b)
		}
	}
	return out
}

// imprecise is whether the version v has too few numbers to place in a
// range of advs: a bound of one has more numbers than v and begins with
// v's (v2 against < 2.7.5). GitHub reads v2 as 2.0.0, which the code the
// tag v2 names need not be.
func imprecise(v facts.PackageVersion, advs []facts.Advisory) bool {
	n := v.Numbers()
	for _, a := range advs {
		for _, b := range rangeBounds(a.VulnerableVersionRange) {
			if bn := b.Numbers(); len(bn) > len(n) && slices.Equal(bn[:len(n)], n) {
				return true
			}
		}
	}
	return false
}
