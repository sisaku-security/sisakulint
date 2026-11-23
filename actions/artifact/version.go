package artifact

import (
	"regexp"
	"strconv"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

var (
	fullSHA = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)
	semver  = regexp.MustCompile(`^v([0-9]+)(?:\.([0-9]+)(?:\.([0-9]+))?)?$`)
)

// version is a tag vM[.m[.p]]: a part not written is -1, which a floating
// tag stands for the newest release of it.
type version struct{ major, minor, patch int }

func parseVersion(ref string) (version, bool) {
	m := semver.FindStringSubmatch(ref)
	if m == nil {
		return version{}, false
	}
	v := version{-1, -1, -1}
	v.major, _ = strconv.Atoi(m[1])
	if m[2] != "" {
		v.minor, _ = strconv.Atoi(m[2])
	}
	if m[3] != "" {
		v.patch, _ = strconv.Atoi(m[3])
	}
	return v, true
}

// checkoutVersion is whether actions/checkout at ref leaves its credential
// in .git/config: v1 to v5 do, v6 on keep it in
// RUNNER_TEMP. A commit in neither table leaves it unless it has the
// commit of v6.0.0 (asks); a branch or another ref is the worst case.
func checkoutVersion(ref string) (leaves bool, asks *facts.SHA) {
	if fullSHA.MatchString(ref) {
		sha := mustSHA(ref)
		switch {
		case checkoutLeaves[sha.String()]:
			return true, nil
		case checkoutKeeps[sha.String()]:
			return false, nil
		}
		return true, &sha
	}
	if v, ok := parseVersion(ref); ok {
		return v.major <= 5, nil
	}
	return true, nil
}

// hiddenRule is whether an upload takes hidden files.
type hiddenRule uint8

const (
	hiddenAlways hiddenRule = iota // whatever the input: before v3.2.0 and v4.4.0, or a branch (the worst case)
	hiddenNever                    // never: v3.2.0, which does not pass the input
	hiddenInput                    // with include-hidden-files true only
	hiddenUnless                   // a commit in no table: as hiddenInput if it has a commit of uploadExcludes, else always
)

// uploadVersion is how actions/upload-artifact at ref takes hidden files,
// and whether its artifact can be downloaded while the run goes on (v4
// on). A floating tag is its newest release (2026-09-30).
func uploadVersion(ref string) (hiddenRule, bool) {
	if fullSHA.MatchString(ref) {
		s := mustSHA(ref).String()
		during := !uploadBefore4[s]
		switch {
		case uploadTakes[s]:
			return hiddenAlways, during
		case uploadNever[s]:
			return hiddenNever, during
		case uploadInput[s]:
			return hiddenInput, during
		}
		return hiddenUnless, true
	}
	v, ok := parseVersion(ref)
	if !ok {
		return hiddenAlways, true
	}
	during := v.major >= 4
	switch {
	case v.major <= 2:
		return hiddenAlways, during
	case v.major == 3 && v.minor >= 0 && v.minor < 2:
		return hiddenAlways, during
	case v.major == 3 && v.minor == 2 && v.patch == 0:
		return hiddenNever, during
	case v.major == 4 && v.minor >= 0 && v.minor < 4:
		return hiddenAlways, during
	}
	return hiddenInput, during
}
