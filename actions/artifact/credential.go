package artifact

import (
	"fmt"
	"github.com/sisaku-security/sisakulint/actions/prcode"
	"path"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/taint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// InconclusiveUpload is an input the analysis does not evaluate: its value as written,
// and where it is.
type InconclusiveUpload struct {
	Kind analysis.InconclusiveUploadKind
	At   workflow.Base
	Text string
	// Files are the files of the credentials whose leaving, or whose
	// taking by the upload, its value decides: a rule gives the gaps of
	// its own credentials only
	Files []analysis.CredentialFile
	// Credentials are, for a gap of the upload, the steps before it that
	// leave a credential whose taking its value decides: not those that
	// the analysis gives, as a LeftCredential, only when an upload takes
	// them
	Credentials []GapCredential
}

// GapCredential is a step before an upload that leaves a credential in
// File, whose taking a gap of the upload decides.
type GapCredential struct {
	Step *workflow.Step
	File analysis.CredentialFile
}

// credential is a credential a step leaves in a file: the file's path from
// the workspace, cleaned, in parts (.. first for one above it).
type credential struct {
	step     *workflow.Step // an element of the steps uploads reads
	uses     string
	file     []string
	life     analysis.CredentialLifetime
	unless   []prcode.MissingCommit
	checkout bool // actions/checkout: persist-credentials false keeps it out
	// gap is, for a credential that a ${{ }} of the step decides whether
	// the step leaves, the gap to give where an upload takes the file
	gap *InconclusiveUpload
	// gapTold is whether gap was given: once, at the first upload that
	// takes the file
	gapTold bool
	// fileID is the file's number among the files of the credentials of
	// the steps of a job or an action: the same number for the same parts
	// (joined by /, which no part has), for a takeMemo
	fileID int
}

// gcpCreds stands for the name google-github-actions/auth gives its file,
// gha-creds-<16 hex>.json: any name of that form matches
// the same patterns.
const gcpCreds = "gha-creds-0123456789abcdef.json"

// valueOf is the value of the input in of s's with: its String and
// whether it is there. dynamic is whether it, or the whole with, is a
// ${{ }}. in is an analysis.CheckoutInput or an input, whose name its
// String is.
func valueOf(s workflow.Step, in fmt.Stringer) (v workflow.String, present, dynamic bool) {
	name := in.String()
	switch s.With.Status {
	case workflow.Dynamic:
		return workflow.String{}, false, true
	case workflow.Present:
	default:
		return workflow.String{}, false, false
	}
	e, ok := s.With.Value.Lookup(name)
	if !ok {
		return workflow.String{}, false, false
	}
	switch e.Value.Status {
	case workflow.Present:
		return e.Value.Value, true, e.Value.Value.Parts != nil
	case workflow.Dynamic:
		return workflow.String{}, true, true
	}
	return workflow.String{}, false, false
}

// isTrue is whether a literal is true as actions/checkout reads a boolean:
// true in any case, nothing else.
func isTrue(v workflow.String) bool {
	return strings.EqualFold(strings.TrimSpace(v.AsString()), "true")
}

// authTrue is whether google-github-actions/auth reads a literal as true:
// parseBoolean of actions-utils v0.8.10 (src/input.ts, df23fe2a) takes 1,
// t, T, true, True and TRUE as true and 0, f, F, false, False, FALSE and
// the empty value as false, and fails the step on any other value, which
// then writes no file.
func authTrue(v workflow.String) bool {
	switch strings.TrimSpace(v.AsString()) {
	case "1", "t", "T", "true", "True", "TRUE":
		return true
	}
	return false
}

// githubToken is whether a token input is the job's GITHUB_TOKEN: none, an
// empty one, or ${{ github.token }} or ${{ secrets.GITHUB_TOKEN }} alone.
func githubToken(v workflow.String, present bool) bool {
	if !present || v.Parts == nil && strings.TrimSpace(v.AsString()) == "" {
		return true
	}
	if !v.IsExpr() {
		return false
	}
	for _, p := range v.Parts {
		if p.Expr {
			return p.Tree != nil && taint.JobTokenRef(p.Tree)
		}
	}
	return false
}

// gapOf is the gap of the input in of s, which decides whether s leaves a
// credential in file.
func gapOf(s workflow.Step, in fmt.Stringer, file analysis.CredentialFile) InconclusiveUpload {
	name := in.String()
	files := []analysis.CredentialFile{file}
	if v, present, _ := valueOf(s, in); present && v.Parts != nil {
		return InconclusiveUpload{Kind: analysis.InconclusiveCredentialInput, At: v.Base, Text: name + ": " + v.Text(), Files: files}
	}
	if s.With.Status == workflow.Dynamic && s.With.Expr != nil {
		return InconclusiveUpload{Kind: analysis.InconclusiveCredentialInput, At: s.With.Expr.Base, Text: "with: " + s.With.Expr.Text(), Files: files}
	}
	return InconclusiveUpload{Kind: analysis.InconclusiveCredentialInput, At: s.Base, Text: name, Files: files}
}

// runnerTempRoot is the first part of the path of a file in RUNNER_TEMP,
// which no path of the workspace has (a part of a path has no NUL), and
// checkoutTempCreds stands for the name actions/checkout v6 and later gives
// the file of its git credential, git-credentials-<uuid>.config.
const (
	runnerTempRoot    = prcode.RunnerTempMark
	checkoutTempCreds = "git-credentials-01234567-89ab-cdef-0123-456789abcdef.config"
)

// fileOf is the kind of the file at the path file: .git/config, or the
// file of actions/checkout in RUNNER_TEMP, which artipacked reads, or
// another.
func fileOf(file []string) analysis.CredentialFile {
	if len(file) == 2 && file[0] == runnerTempRoot && file[1] == checkoutTempCreds {
		return analysis.CredentialFileGitCredentialsTemp
	}
	if len(file) >= 2 && file[len(file)-2] == ".git" && file[len(file)-1] == "config" {
		return analysis.CredentialFileGitConfig
	}
	return analysis.CredentialFileOther
}

// credentialsOf are the credentials the step s leaves in a file, by the
// table of the actions that leave one; gaps are the inputs that decide
// them and are a ${{ }}.
// place is where s, when a checkout, puts the tree, and placed whether it
// puts it (prcode.CheckoutPlacement).
func credentialsOf(sp *workflow.Step, place prcode.Placement, placed bool) ([]credential, []InconclusiveUpload) {
	s := *sp
	act, ref := actionOf(s)
	if act == actionNone {
		return nil, nil
	}
	uses := s.Uses.Value.AsString()
	one := func(file []string, life analysis.CredentialLifetime) []credential {
		return []credential{{step: sp, uses: uses, file: file, life: life}}
	}
	switch act {
	case actionCheckout:
		if !placed {
			return nil, nil // the checkout fails on its path before it writes a credential
		}
		return checkoutCredentials(sp, uses, ref, place)
	case actionPagesDeploy:
		if k, present, _ := valueOf(s, inputSSHKey); present && (k.Parts != nil || strings.TrimSpace(k.AsString()) != "") {
			return nil, nil
		}
		tok, present, _ := valueOf(s, inputToken)
		life := analysis.CredentialLifetimeLasting
		if githubToken(tok, present) {
			life = analysis.CredentialLifetimeGitHubToken
		}
		return one([]string{".git", "config"}, life), nil
	case actionAuth:
		if s.With.Status == workflow.Dynamic {
			return nil, []InconclusiveUpload{gapOf(s, inputCreateCredentialsFile, analysis.CredentialFileOther)} // what inputs it has is not known
		}
		// with neither input of a credential, the step writes no file
		// whatever create_credentials_file is
		life := analysis.CredentialLifetimeLasting
		if _, ok, _ := valueOf(s, inputCredentialsJSON); !ok {
			if _, ok, _ := valueOf(s, inputWorkloadIdentityProvider); !ok {
				return nil, nil
			}
			life = analysis.CredentialLifetimeJob
		}
		f, present, dyn := valueOf(s, inputCreateCredentialsFile)
		switch {
		case dyn:
			return nil, []InconclusiveUpload{gapOf(s, inputCreateCredentialsFile, analysis.CredentialFileOther)}
		case present && !authTrue(f):
			return nil, nil
		}
		return one([]string{gcpCreds}, life), nil
	case actionDotnet:
		if v, present, _ := valueOf(s, inputSourceURL); present && (v.Parts != nil || strings.TrimSpace(v.AsString()) != "") {
			return one([]string{"..", "nuget.config"}, analysis.CredentialLifetimeLasting), nil
		}
	}
	return nil, nil
}

// parts is the path p from the workspace, cleaned, in parts; nil for the
// workspace itself.
func parts(p string) []string {
	c := path.Clean(p)
	if c == "." {
		return nil
	}
	return strings.Split(c, "/")
}

// checkoutCredentials are the credentials a step of actions/checkout at
// ref leaves: in .git/config of the workspace (v1 to v5), in a file of
// RUNNER_TEMP (v6 on, removed by the post step, after the uploads of the
// job), or both for a branch or a commit in no table, which may be either
// (the worst case).
func checkoutCredentials(sp *workflow.Step, uses, ref string, place prcode.Placement) ([]credential, []InconclusiveUpload) {
	s := *sp
	leaves, asks := checkoutVersion(ref)
	_, versioned := parseVersion(ref)
	var cs []credential
	var gaps []InconclusiveUpload
	if !leaves || asks != nil || !versioned && !fullSHA.MatchString(ref) {
		cs = append(cs, checkoutTempCredential(sp, uses)...)
	}
	if !leaves {
		return cs, nil
	}
	life := checkoutLifetime(s)
	p, present, dyn := valueOf(s, analysis.CheckoutInputPersistCredentials)
	switch {
	case dyn:
		return cs, []InconclusiveUpload{gapOf(s, analysis.CheckoutInputPersistCredentials, analysis.CredentialFileGitConfig)}
	case present && !isTrue(p):
		return cs, nil
	}
	rel, known := place.Dir()
	if !known {
		dir, present, dyn := valueOf(s, analysis.CheckoutInputPath)
		switch {
		case dyn:
			return cs, []InconclusiveUpload{gapOf(s, analysis.CheckoutInputPath, analysis.CredentialFileGitConfig)}
		case present:
			return cs, []InconclusiveUpload{{Kind: analysis.InconclusiveCredentialInput, At: dir.Base, Text: analysis.CheckoutInputPath.String() + ": " + dir.Text(),
				Files: []analysis.CredentialFile{analysis.CredentialFileGitConfig}}}
		}
		rel = "." // a with or a path that does not fit the schema: read as no path, as before
	}
	file := append(parts(rel), ".git", "config")
	c := credential{step: sp, uses: uses, file: file, life: life, checkout: true}
	if asks != nil {
		c.unless = []prcode.MissingCommit{{Repo: prcode.CheckoutRepo, SHA: *asks, Commit: checkoutTemp}}
	}
	return append(cs, c), gaps
}

// checkoutTempCredential is the credential of actions/checkout v6 on in a
// file of RUNNER_TEMP, which an upload of ${{ runner.temp }} takes; none
// with persist-credentials false, and a gap at such an upload when
// persist-credentials is a ${{ }}.
func checkoutTempCredential(sp *workflow.Step, uses string) []credential {
	s := *sp
	p, present, dyn := valueOf(s, analysis.CheckoutInputPersistCredentials)
	if present && !dyn && !isTrue(p) {
		return nil
	}
	c := credential{step: sp, uses: uses, file: []string{runnerTempRoot, checkoutTempCreds}, life: checkoutLifetime(s), checkout: true}
	if dyn {
		g := gapOf(s, analysis.CheckoutInputPersistCredentials, analysis.CredentialFileGitCredentialsTemp)
		c.gap = &g
	}
	return []credential{c}
}

// checkoutLifetime is how long the token of a step of actions/checkout
// works: the job's GITHUB_TOKEN, or a token given as the input token.
func checkoutLifetime(s workflow.Step) analysis.CredentialLifetime {
	tok, present, _ := valueOf(s, analysis.CheckoutInputToken)
	if githubToken(tok, present) {
		return analysis.CredentialLifetimeGitHubToken
	}
	return analysis.CredentialLifetimeLasting
}
