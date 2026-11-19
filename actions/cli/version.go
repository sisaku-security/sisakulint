package cli

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// versionText is what --version writes, of the build debug.ReadBuildInfo
// gives (bi, ok): the version of the module (unknown when there is none,
// or when the build gives (devel), as go run does),
// the commit as --explain writes it, the Go release and the platform, and
// the schemas of the JSON this binary writes and reads.
func versionText(bi *debug.BuildInfo, ok bool) string {
	v := moduleVersion(bi, ok)
	if v == "" {
		v = "unknown"
	}
	schemas := []string{lint.ReportSchema, lint.RegistrySchema, facts.FileSchema, lint.AcceptancesSchema}
	return fmt.Sprintf("sisakulint %s\ncommit %s\ngo %s %s/%s\nschemas %s\n",
		v, commit(bi, ok), runtime.Version(), runtime.GOOS, runtime.GOARCH, strings.Join(schemas, " "))
}

// moduleVersion is the version of the module of the build (bi, ok); empty
// when there is none, or when the build gives (devel), as go run does.
func moduleVersion(bi *debug.BuildInfo, ok bool) string {
	if ok && bi != nil && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return ""
}

// binaryVersion is the version of this binary (moduleVersion); empty when
// it is not known.
func binaryVersion() string { return moduleVersion(debug.ReadBuildInfo()) }
