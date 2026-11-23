package labeler

import (
	"slices"
	"strings"
	"time"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// Release is how one release of actions/labeler reads its configuration
// and its inputs, from its src and action.yml at the commit of its tag.
type Release struct {
	Format       Format
	LocalFirst   bool // it reads the configuration from the runner when the file is there, else from the API at the commit of the run
	TokenDefault bool // repo-token defaults to github.token; without it, a step with no repo-token fails
	PRNumber     bool // it has the input pr-number
}

type release struct {
	tags []string // the release tag first, then the major tag that points to it
	sha  facts.SHA
	Release
}

func mustSHA(s string) facts.SHA {
	sha, err := facts.ParseSHA(s)
	if err != nil {
		panic(err)
	}
	return sha
}

var (
	keysLimits = Release{Format: FormatKeysLimits, LocalFirst: true, TokenDefault: true, PRNumber: true}
	keys       = Release{Format: FormatKeys, LocalFirst: true, TokenDefault: true, PRNumber: true}
	anyAllNew  = Release{Format: FormatAnyAll, LocalFirst: true, TokenDefault: true, PRNumber: true}
	anyAllAPI  = Release{Format: FormatAnyAll, TokenDefault: true}
	anyAllOld  = Release{Format: FormatAnyAll}
	globsOld   = Release{Format: FormatGlobs}
)

// releases are the releases of actions/labeler (gh api
// repos/actions/labeler/tags, 2026-10-24) but the pre-releases (v3-preview,
// v5.0.0-alpha.1, v5.0.0-beta.1) and v1.0.0, which are read as any
// release. The limits max-files-changed and changed-files-labels-limit are
// from v6.1.0, the input pr-number and the configuration on the runner
// from v4.3.0, the default token from v4.0.3.
var releases = []release{
	{[]string{"v7.0.0", "v7"}, mustSHA("bf12e9b00b37c5c0ca2b87b79b2daf7891dbda13"), keysLimits},
	{[]string{"v6.2.0", "v6"}, mustSHA("b8dd2d9be0f68b860e7dae5dae7d772984eacd6d"), keysLimits},
	{[]string{"v6.1.0"}, mustSHA("f27b608878404679385c85cfa523b85ccb86e213"), keysLimits},
	{[]string{"v6.0.1"}, mustSHA("634933edcd8ababfe52f92936142cc22ac488b1b"), keys},
	{[]string{"v6.0.0"}, mustSHA("f1a63e87db0c6baf19c5713083f8d00d789ca184"), keys},
	{[]string{"v5.0.0", "v5"}, mustSHA("8558fd74291d67161a8a78ce36a881fa63b766a9"), keys},
	{[]string{"v4.3.0", "v4"}, mustSHA("ac9175f8a1f3625fd0d4fb234536d26811351594"), anyAllNew},
	{[]string{"v4.2.0"}, mustSHA("0967ca812e7fdc8f5f71402a1b486d5bd061fe20"), anyAllAPI},
	{[]string{"v4.1.0"}, mustSHA("9fcb2c2f5584144ca754f8bfe8c6f81e77753375"), anyAllAPI},
	{[]string{"v4.0.4"}, mustSHA("0776a679364a9a16110aac8d0f40f5e11009e327"), anyAllAPI},
	{[]string{"v4.0.3"}, mustSHA("ba790c862c380240c6d5e7427be5ace9a05c754b"), anyAllAPI},
	{[]string{"v4.0.2"}, mustSHA("5c7539237e04b714afd8ad9b4aed733815b9fab4"), anyAllOld},
	{[]string{"v4.0.1"}, mustSHA("e54e5b338fbd6e6cdb5d60f51c22335fc57c401e"), anyAllOld},
	{[]string{"v4.0.0"}, mustSHA("9fd24f1f9d6ceb64ba34d181b329ee72f99978a0"), anyAllOld},
	{[]string{"v3.1.0", "v3"}, mustSHA("3d612d72e6784a1a65365cc6d33b5a001c12bf10"), anyAllOld},
	{[]string{"v3.0.2"}, mustSHA("69da01b8e0929f147b8943611bee75ee4175a49e"), anyAllOld},
	{[]string{"v3.0.1"}, mustSHA("5682b7c5137476cceba78108d82b25ae7897cc7c"), anyAllOld},
	{[]string{"v3.0.0"}, mustSHA("9794b1493b6f1fa7b006c5f8635a19c76c98be95"), anyAllOld},
	{[]string{"2.2.0", "v2"}, mustSHA("5f867a63be70efff62b767459b009290364495eb"), globsOld},
	{[]string{"v2.1.1"}, mustSHA("c5c9bd0f54850043af418b8e6b45324d32027454"), globsOld},
	{[]string{"v2.1.0"}, mustSHA("04aa5dbc72538e0b9194c658a9ad6026b865d039"), globsOld},
	{[]string{"v2.0.0"}, mustSHA("26d986477233e2ffd305d08a335654674e379854"), globsOld},
}

// releasesOn is the day releases were taken: a release of actions/labeler
// published on it or later must be added (releasetable.CheckTable).
var releasesOn = time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)

// ReleaseOf is the release a ref of uses names (a tag, or the commit of a
// tag), and true. For any other ref (a branch, another commit, a
// pre-release, a major the table does not have), it is every reading of
// the table, each once, and false.
func ReleaseOf(ref string) ([]Release, bool) {
	for _, r := range releases {
		if slices.Contains(r.tags, ref) || strings.EqualFold(r.sha.String(), ref) {
			return []Release{r.Release}, true
		}
	}
	var all []Release
	for _, r := range releases {
		if !slices.Contains(all, r.Release) {
			all = append(all, r.Release)
		}
	}
	return all, false
}
