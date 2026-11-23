package facts

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Repo is a repository, owner/name ($defs/repo). GitHub compares both
// without case, so ParseRepo writes them in lower case, and two spellings
// of one repository are ==. The zero Repo is not a repository.
type Repo struct{ owner, name string }

var repoPart = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// ParseRepo reads owner/name.
func ParseRepo(s string) (Repo, error) {
	owner, name, ok := strings.Cut(s, "/")
	if !ok || !repoPart.MatchString(owner) || !repoPart.MatchString(name) {
		return Repo{}, fmt.Errorf("%q is not owner/name", s)
	}
	return Repo{strings.ToLower(owner), strings.ToLower(name)}, nil
}

// IsZero is whether r is the zero Repo, which is none.
func (r Repo) IsZero() bool { return r.owner == "" }

func (r Repo) String() string {
	if r.owner == "" {
		return ""
	}
	return r.owner + "/" + r.name
}

func (r Repo) MarshalJSON() ([]byte, error) {
	if r.owner == "" {
		return nil, errors.New("the zero Repo is not a repository")
	}
	return json.Marshal(r.String())
}

func (r *Repo) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	p, err := ParseRepo(s)
	if err != nil {
		return err
	}
	*r = p
	return nil
}

// SHA is a commit, 40 or 64 hexadecimal digits ($defs/sha). ParseSHA
// writes it in lower case, so two spellings of one commit are ==. The zero
// SHA is not a commit.
type SHA struct{ hex string }

var shaDigits = regexp.MustCompile(`^([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$`)

// ParseSHA reads a commit.
func ParseSHA(s string) (SHA, error) {
	if !shaDigits.MatchString(s) {
		return SHA{}, fmt.Errorf("%q is not 40 or 64 hexadecimal digits", s)
	}
	return SHA{strings.ToLower(s)}, nil
}

func (s SHA) String() string { return s.hex }

func (s SHA) MarshalJSON() ([]byte, error) {
	if s.hex == "" {
		return nil, errors.New("the zero SHA is not a commit")
	}
	return json.Marshal(s.hex)
}

func (s *SHA) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	p, err := ParseSHA(v)
	if err != nil {
		return err
	}
	*s = p
	return nil
}

// RefName is the full name of a branch or a tag, refs/heads/<name> or
// refs/tags/<name> ($defs/ref-name). The zero RefName is none.
type RefName struct{ s string }

// ParseRefName reads the full name of a branch or a tag: refs/heads/ or
// refs/tags/ and a name git check-ref-format allows. A revision such as
// main~1 or v1@{1} is not one.
func ParseRefName(s string) (RefName, error) {
	name, ok := strings.CutPrefix(s, "refs/heads/")
	if !ok {
		name, ok = strings.CutPrefix(s, "refs/tags/")
	}
	if !ok || !refNameOK(name) {
		return RefName{}, fmt.Errorf("%q is not refs/heads/… or refs/tags/… with the name of a ref", s)
	}
	return RefName{s}, nil
}

// refNameOK is whether git check-ref-format allows name, after refs/heads/
// or refs/tags/.
func refNameOK(name string) bool {
	if name == "" || name == "@" || strings.HasSuffix(name, ".") ||
		strings.Contains(name, "..") || strings.Contains(name, "@{") || strings.ContainsAny(name, " ~^:?*[\\\x7f") {
		return false
	}
	for _, c := range name {
		if c < 0x20 {
			return false
		}
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}

func (r RefName) String() string { return r.s }

// IsZero is whether r is none.
func (r RefName) IsZero() bool { return r.s == "" }

func (r RefName) MarshalJSON() ([]byte, error) {
	if r.s == "" {
		return nil, errors.New("the zero RefName is no ref")
	}
	return json.Marshal(r.s)
}

func (r *RefName) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	p, err := ParseRefName(s)
	if err != nil {
		return err
	}
	*r = p
	return nil
}

// InputPath is the path of an input of a run, relative to its root, with
// / between its parts ($defs/input-path): no empty part, no . or .. (and no
// backslash, when ParseInputPath reads it from a file of facts). A
// fingerprint depends on it, so the same file gets the same InputPath each
// time. The zero InputPath is none.
type InputPath struct{ s string }

// ParseInputPath reads the path of an input.
func ParseInputPath(s string) (InputPath, error) {
	if s == "" || strings.Contains(s, `\`) {
		return InputPath{}, fmt.Errorf("%q is not a relative path with / between its parts", s)
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." || part == ".." {
			return InputPath{}, fmt.Errorf("%q has an empty part, . or ..", s)
		}
	}
	return InputPath{s}, nil
}

// CleanInputPath normalizes s (it drops ./ and empty parts) and makes the
// InputPath of an input a person names, as the command line takes it.
// Unlike ParseInputPath it takes a backslash, which a file name may hold.
func CleanInputPath(s string) (InputPath, error) {
	if s == "" || strings.HasPrefix(s, "/") {
		return InputPath{}, fmt.Errorf("%q is not a path relative to the repository", s)
	}
	var parts []string
	for _, e := range strings.Split(s, "/") {
		switch e {
		case "", ".":
		case "..":
			return InputPath{}, fmt.Errorf("%q goes out with ..", s)
		default:
			parts = append(parts, e)
		}
	}
	if len(parts) == 0 {
		return InputPath{}, fmt.Errorf("%q names no file", s)
	}
	return InputPath{strings.Join(parts, "/")}, nil
}

// MustCleanInputPath is CleanInputPath that panics on an error.
func MustCleanInputPath(s string) InputPath {
	p, err := CleanInputPath(s)
	if err != nil {
		panic(err)
	}
	return p
}

// WalkedInputPath is the InputPath of p, a path fs.WalkDir gives: . for
// the root, else a path CleanInputPath keeps as it is. Its name may not be
// UTF-8, which the input that reads it says. It panics on any other p.
func WalkedInputPath(p string) InputPath {
	if p != "." {
		if c, err := CleanInputPath(p); err != nil || c.s != p {
			panic(fmt.Sprintf("%q is not a path fs.WalkDir gives", p))
		}
	}
	return InputPath{p}
}

// FactArgument is p as the argument of a fact (input_path), and whether p
// can be one: a name with a backslash, which CleanInputPath takes, cannot,
// as ParseInputPath and the schema refuse it. A rule asks no fact of such an
// input, so a finding that would hold on the answer of a fact holds as the
// fact's assumed value, and no file of facts can drop it.
func (p InputPath) FactArgument() (InputPath, bool) {
	q, err := ParseInputPath(p.s)
	return q, err == nil
}

// IsZero is whether p is the zero InputPath, which is none.
func (p InputPath) IsZero() bool { return p.s == "" }

// CompareInputPaths orders paths by their bytes.
func CompareInputPaths(a, b InputPath) int { return strings.Compare(a.s, b.s) }

func (p InputPath) String() string { return p.s }

func (p InputPath) MarshalJSON() ([]byte, error) {
	if p.s == "" {
		return nil, errors.New("the zero InputPath is no path")
	}
	return json.Marshal(p.s)
}

func (p *InputPath) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseInputPath(s)
	if err != nil {
		return err
	}
	*p = v
	return nil
}

// UsesPath is the path of an action in its repository, the path of uses:
// {owner}/{repo}/{path}@{ref} ($defs/uses-path): parts with / between them,
// no empty part, no . or .., no backslash, no @ and no white space (of
// ASCII: tab, line feed, form feed, carriage return, space). It is
// not an InputPath, which is relative to the root of the run. The zero
// UsesPath is none: the action at the root of its repository.
type UsesPath struct{ s string }

// ParseUsesPath reads the path of uses.
func ParseUsesPath(s string) (UsesPath, error) {
	// the white space of the schema's pattern: \s of Go's regexp
	if s == "" || strings.ContainsAny(s, "\\@\t\n\f\r ") {
		return UsesPath{}, fmt.Errorf("%q is not a path with / between its parts", s)
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "." || part == ".." {
			return UsesPath{}, fmt.Errorf("%q has an empty part, . or ..", s)
		}
	}
	return UsesPath{s}, nil
}

// IsZero is whether p is the zero UsesPath, which is none.
func (p UsesPath) IsZero() bool { return p.s == "" }

func (p UsesPath) String() string { return p.s }

func (p UsesPath) MarshalJSON() ([]byte, error) {
	if p.s == "" {
		return nil, errors.New("the zero UsesPath is no path")
	}
	return json.Marshal(p.s)
}

func (p *UsesPath) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseUsesPath(s)
	if err != nil {
		return err
	}
	*p = v
	return nil
}

// StepPath is where a step is in its input ($defs/step-path):
// jobs.<id>.steps[<n>] in a workflow, jobs.<id>.steps[<n>].parallel[<m>]
// for a step of the parallel group at n, runs.steps[<n>] in an action.yml,
// n and m from 0. The zero StepPath is none.
type StepPath struct {
	job   string // "" in an action.yml
	index int
	inner int // the index in the parallel group, plus 1; 0 when not in one
	set   bool
}

var stepPath = regexp.MustCompile(`^(?:jobs\.([A-Za-z_][A-Za-z0-9_-]*)|runs)\.steps\[(0|[1-9][0-9]*)\](?:\.parallel\[(0|[1-9][0-9]*)\])?$`)

// WorkflowStep is the step index of the job job of a workflow.
func WorkflowStep(job string, index int) (StepPath, error) {
	if !validJobID(job) || index < 0 {
		return StepPath{}, fmt.Errorf("no step %d of a job %q", index, job)
	}
	return StepPath{job: job, index: index, set: true}, nil
}

// WorkflowGroupStep is the step at index inGroup of the parallel group at
// step index of the job job of a workflow.
func WorkflowGroupStep(job string, index, inGroup int) (StepPath, error) {
	p, err := WorkflowStep(job, index)
	if err != nil || inGroup < 0 {
		return StepPath{}, fmt.Errorf("no step %d of the group at step %d of a job %q", inGroup, index, job)
	}
	p.inner = inGroup + 1
	return p, nil
}

// ActionStep is the step index of the runs.steps of an action.yml.
func ActionStep(index int) (StepPath, error) {
	if index < 0 {
		return StepPath{}, fmt.Errorf("no step %d", index)
	}
	return StepPath{index: index, set: true}, nil
}

// ParseStepPath reads jobs.<id>.steps[<n>], jobs.<id>.steps[<n>].parallel[<m>]
// or runs.steps[<n>].
func ParseStepPath(s string) (StepPath, error) {
	m := stepPath.FindStringSubmatch(s)
	if m == nil || strings.HasPrefix(s, "runs.") && m[3] != "" {
		return StepPath{}, fmt.Errorf("%q is not jobs.<id>.steps[<n>], jobs.<id>.steps[<n>].parallel[<m>] or runs.steps[<n>]", s)
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return StepPath{}, fmt.Errorf("%q: %v", s, err)
	}
	if strings.HasPrefix(s, "runs.") {
		return ActionStep(n)
	}
	if m[3] == "" {
		return WorkflowStep(m[1], n)
	}
	k, err := strconv.Atoi(m[3])
	if err != nil {
		return StepPath{}, fmt.Errorf("%q: %v", s, err)
	}
	return WorkflowGroupStep(m[1], n, k)
}

func (p StepPath) String() string {
	switch {
	case !p.set:
		return ""
	case p.job == "":
		return fmt.Sprintf("runs.steps[%d]", p.index)
	}
	if p.inner > 0 {
		return fmt.Sprintf("jobs.%s.steps[%d].parallel[%d]", p.job, p.index, p.inner-1)
	}
	return fmt.Sprintf("jobs.%s.steps[%d]", p.job, p.index)
}

func (p StepPath) MarshalJSON() ([]byte, error) {
	if !p.set {
		return nil, errors.New("the zero StepPath is no step")
	}
	return json.Marshal(p.String())
}

func (p *StepPath) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseStepPath(s)
	if err != nil {
		return err
	}
	*p = v
	return nil
}

// validJobID is the rule of a job's id as actions/workflow reads it
// (validJobID of its job.go; this package does not import it):
// [A-Za-z_][A-Za-z0-9_-]*, shorter than 100, and __ is reserved.
func validJobID(id string) bool {
	if id == "" || len(id) >= 100 || strings.HasPrefix(id, "__") {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case i > 0 && (c >= '0' && c <= '9' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// EnvironmentName is the name of a deployment environment
// ($defs/environment-name): at most 255 characters, with no control
// character. GitHub compares names without case, so ParseEnvironmentName
// writes it in lower case, and two spellings of one are ==. The zero
// EnvironmentName is none.
type EnvironmentName struct{ s string }

// ParseEnvironmentName reads the name of an environment.
func ParseEnvironmentName(s string) (EnvironmentName, error) {
	if s == "" || utf8.RuneCountInString(s) > 255 || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return EnvironmentName{}, fmt.Errorf("%q is not the name of an environment: 1 to 255 characters, none a control", s)
	}
	return EnvironmentName{strings.ToLower(s)}, nil
}

func (n EnvironmentName) String() string { return n.s }

func (n EnvironmentName) MarshalJSON() ([]byte, error) {
	if n.s == "" {
		return nil, errors.New("the zero EnvironmentName is no environment")
	}
	return json.Marshal(n.s)
}

func (n *EnvironmentName) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseEnvironmentName(s)
	if err != nil {
		return err
	}
	*n = v
	return nil
}

// RefCommit is what the runner runs for a ref ($defs/ref-commit): the
// commit, and the branch or the tag it was found as; the zero Ref when the
// ref is a full SHA found as a commit.
type RefCommit struct {
	SHA SHA
	Ref RefName
}

type refCommitJSON struct {
	SHA SHA      `json:"sha"`
	Ref *RefName `json:"ref,omitempty"`
}

func (c RefCommit) MarshalJSON() ([]byte, error) {
	j := refCommitJSON{SHA: c.SHA}
	if !c.Ref.IsZero() {
		j.Ref = &c.Ref
	}
	return json.Marshal(j)
}

func (c *RefCommit) UnmarshalJSON(b []byte) error {
	var j refCommitJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return err
	}
	if j.SHA.hex == "" {
		return errors.New("a RefCommit has a sha")
	}
	*c = RefCommit{SHA: j.SHA}
	if j.Ref != nil {
		c.Ref = *j.Ref
	}
	return nil
}

// ActionFileName is a file that defines an action, as the runner looks for
// it in the directory of the action: action.yml, else action.yaml, else a
// Dockerfile (or dockerfile).
type ActionFileName uint8

const (
	ActionFileNameUnset ActionFileName = iota
	ActionFileYML
	ActionFileYAML
	ActionFileDockerfile
	ActionFileDockerfileLower
)

var actionFileNames = [...]string{"", "action.yml", "action.yaml", "Dockerfile", "dockerfile"}

func (n ActionFileName) String() string {
	if int(n) < len(actionFileNames) {
		return actionFileNames[n]
	}
	return ""
}

// ParseActionFileName reads one of action.yml, action.yaml, Dockerfile and
// dockerfile.
func ParseActionFileName(s string) (ActionFileName, error) {
	for i, x := range actionFileNames {
		if i > 0 && x == s {
			return ActionFileName(i), nil
		}
	}
	return ActionFileNameUnset, fmt.Errorf("%q is not a file that defines an action", s)
}

func (n ActionFileName) MarshalJSON() ([]byte, error) {
	if n == ActionFileNameUnset || int(n) >= len(actionFileNames) {
		return nil, errors.New("no file that defines an action")
	}
	return json.Marshal(n.String())
}

func (n *ActionFileName) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseActionFileName(s)
	if err != nil {
		return err
	}
	*n = v
	return nil
}

// ActionFile is the file that defines an action, as the archive of its
// commit has it ($defs/action-file): the commit, which file, its text
// (empty for a Dockerfile), and whether the archive's text differs from
// the blob (export-subst: an archive of the same commit can differ later).
type ActionFile struct {
	Commit             SHA            `json:"commit"`
	File               ActionFileName `json:"file"`
	Content            string         `json:"content"`
	ArchiveSubstituted bool           `json:"archive_substituted"`
}

// WorkflowFile is a reusable workflow of another repository, as the
// commit has it ($defs/workflow-file): the commit and the text of the
// file. GitHub runs a reusable workflow of another repository from the
// commit, not from its archive, so export-subst does not touch it.
type WorkflowFile struct {
	Commit  SHA    `json:"commit"`
	Content string `json:"content"`
}

// PackageName is the name of a package of the actions ecosystem of the
// GitHub Advisory Database ($defs/package-name): owner/repo, and the path
// of the action or the reusable workflow in the repository when it is not
// at the root. ParsePackageName writes owner and repo in lower case, as
// GitHub compares them, and the path as written. The zero PackageName is
// none.
type PackageName struct{ s string }

var packagePath = regexp.MustCompile(`^[^@\s]+$`)

// ParsePackageName reads owner/repo or owner/repo/path.
func ParsePackageName(s string) (PackageName, error) {
	owner, rest, ok := strings.Cut(s, "/")
	repo, path, hasPath := strings.Cut(rest, "/")
	if !ok || !repoPart.MatchString(owner) || !repoPart.MatchString(repo) || hasPath && !packagePath.MatchString(path) {
		return PackageName{}, fmt.Errorf("%q is not owner/repo or owner/repo/path", s)
	}
	n := strings.ToLower(owner) + "/" + strings.ToLower(repo)
	if hasPath {
		n += "/" + path
	}
	return PackageName{n}, nil
}

func (p PackageName) String() string { return p.s }

// IsZero is whether p is none.
func (p PackageName) IsZero() bool { return p.s == "" }

func (p PackageName) MarshalJSON() ([]byte, error) {
	if p.s == "" {
		return nil, errors.New("the zero PackageName is no package")
	}
	return json.Marshal(p.s)
}

func (p *PackageName) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParsePackageName(s)
	if err != nil {
		return err
	}
	*p = v
	return nil
}

// PackageVersion is a version as the GitHub Advisory Database compares it
// ($defs/package-version): an optional v, numbers joined by dots, and a
// prerelease after a hyphen. It is a string, so that a Query that has one
// is comparable; its numbers are read again when it is compared. The zero
// PackageVersion is none.
type PackageVersion struct{ s string }

var packageVersion = regexp.MustCompile(`^v?([0-9]{1,9}(?:\.[0-9]{1,9})*)(?:-([0-9A-Za-z.-]+))?$`)

// ParsePackageVersion reads a version, such as v4.1.2, 4 or 2.0.0-beta.1.
func ParsePackageVersion(s string) (PackageVersion, error) {
	if _, _, ok := versionParts(s); !ok {
		return PackageVersion{}, fmt.Errorf("%q is not a version: v, numbers joined by dots, a prerelease after a hyphen", s)
	}
	return PackageVersion{s}, nil
}

// versionParts is the numbers and the prerelease of the version s.
func versionParts(s string) (numbers []int, pre string, ok bool) {
	m := packageVersion.FindStringSubmatch(s)
	if m == nil {
		return nil, "", false
	}
	for _, n := range strings.Split(m[1], ".") {
		i, err := strconv.Atoi(n)
		if err != nil {
			return nil, "", false
		}
		numbers = append(numbers, i)
	}
	return numbers, m[2], true
}

func (v PackageVersion) String() string { return v.s }

// IsZero is whether v is none.
func (v PackageVersion) IsZero() bool { return v.s == "" }

// Parts is how many numbers v has: 1 for v4, 3 for v4.1.2.
func (v PackageVersion) Parts() int {
	n, _, _ := versionParts(v.s)
	return len(n)
}

// Numbers are the numbers of v: [4 1 2] for v4.1.2.
func (v PackageVersion) Numbers() []int {
	n, _, _ := versionParts(v.s)
	return n
}

// ComparePackageVersions orders a and b by their numbers, a missing
// number read as 0, then a prerelease before none, then the prereleases
// as SemVer orders them; the v is not compared.
func ComparePackageVersions(a, b PackageVersion) int {
	an, apre, _ := versionParts(a.s)
	bn, bpre, _ := versionParts(b.s)
	for i := range max(len(an), len(bn)) {
		var x, y int
		if i < len(an) {
			x = an[i]
		}
		if i < len(bn) {
			y = bn[i]
		}
		if c := cmp.Compare(x, y); c != 0 {
			return c
		}
	}
	switch {
	case apre == bpre:
		return 0
	case apre == "":
		return 1
	case bpre == "":
		return -1
	}
	return comparePrereleases(apre, bpre)
}

// comparePrereleases orders two prereleases as SemVer 2.0.0 (11.4): by
// their identifiers between dots, a numeric one by its number and before
// one with a letter, and a shorter list first when the other has it all.
func comparePrereleases(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := range min(len(as), len(bs)) {
		x, xerr := strconv.Atoi(as[i])
		y, yerr := strconv.Atoi(bs[i])
		var c int
		switch {
		case xerr == nil && yerr == nil:
			c = cmp.Compare(x, y)
		case xerr == nil:
			c = -1
		case yerr == nil:
			c = 1
		default:
			c = strings.Compare(as[i], bs[i])
		}
		if c != 0 {
			return c
		}
	}
	return cmp.Compare(len(as), len(bs))
}

func (v PackageVersion) MarshalJSON() ([]byte, error) {
	if v.s == "" {
		return nil, errors.New("the zero PackageVersion is no version")
	}
	return json.Marshal(v.s)
}

func (v *PackageVersion) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	p, err := ParsePackageVersion(s)
	if err != nil {
		return err
	}
	*v = p
	return nil
}

// GHSAID is the ID of an advisory of the GitHub Advisory Database
// ($defs/ghsa-id).
type GHSAID struct{ s string }

var ghsaID = regexp.MustCompile(`^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)

// ParseGHSAID reads GHSA-xxxx-xxxx-xxxx.
func ParseGHSAID(s string) (GHSAID, error) {
	if !ghsaID.MatchString(s) {
		return GHSAID{}, fmt.Errorf("%q is not the ID of an advisory, GHSA-xxxx-xxxx-xxxx", s)
	}
	return GHSAID{s}, nil
}

func (g GHSAID) String() string { return g.s }

func (g GHSAID) MarshalJSON() ([]byte, error) {
	if g.s == "" {
		return nil, errors.New("the zero GHSAID is no advisory")
	}
	return json.Marshal(g.s)
}

func (g *GHSAID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseGHSAID(s)
	if err != nil {
		return err
	}
	*g = v
	return nil
}

// VersionRange is the range of versions a vulnerability of an advisory
// affects, as the GitHub Advisory Database writes it (comparisons joined
// by commas, such as >= 4.0.0, < 4.1.3). It is kept as GitHub writes it;
// a rule reads it. The zero VersionRange is none.
type VersionRange struct{ s string }

// ParseVersionRange takes the range s, which is not empty.
func ParseVersionRange(s string) (VersionRange, error) {
	if s == "" {
		return VersionRange{}, errors.New("a range of versions is not empty")
	}
	return VersionRange{s}, nil
}

func (r VersionRange) String() string { return r.s }

// IsZero is whether r is none.
func (r VersionRange) IsZero() bool { return r.s == "" }

// RunsUsing is a runs.using of the metadata of an action that the runner
// accepts ($defs/runs-using), in lower case: the value of the fact
// action.runs-using. The zero value is none.
type RunsUsing uint8

// PackageEcosystem is a value of package-ecosystem in .github/dependabot.yml
// ($defs/package-ecosystem): an argument of the fact
// dependabot.version-updates. The zero value is none.
type PackageEcosystem uint8

// RenovateManager is the name of a manager of Renovate
// ($defs/renovate-manager): an argument of the fact
// renovate.manager-enabled. The zero value is none.
type RenovateManager uint8

// AdvisorySeverity is the severity GitHub gives an advisory
// ($defs/advisory-severity): GitHub's rating, found by another table than
// the Severity of a kind of finding. The zero value is none.
type AdvisorySeverity uint8

// Advisory is an advisory of the GitHub Advisory Database, of the package
// a fact asks about ($defs/advisory). FirstPatchedVersion is zero when no
// version fixes it.
type Advisory struct {
	GHSAID                 GHSAID
	Severity               AdvisorySeverity
	VulnerableVersionRange VersionRange
	FirstPatchedVersion    PackageVersion
}

type advisoryJSON struct {
	GHSAID                 GHSAID           `json:"ghsa_id"`
	Severity               AdvisorySeverity `json:"severity"`
	VulnerableVersionRange string           `json:"vulnerable_version_range"`
	FirstPatchedVersion    *PackageVersion  `json:"first_patched_version,omitempty"`
}

func (a Advisory) MarshalJSON() ([]byte, error) {
	j := advisoryJSON{GHSAID: a.GHSAID, Severity: a.Severity, VulnerableVersionRange: a.VulnerableVersionRange.s}
	if !a.FirstPatchedVersion.IsZero() {
		j.FirstPatchedVersion = &a.FirstPatchedVersion
	}
	return json.Marshal(j)
}

func (a *Advisory) UnmarshalJSON(b []byte) error {
	var j advisoryJSON
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&j); err != nil {
		return err
	}
	rng, err := ParseVersionRange(j.VulnerableVersionRange)
	if j.GHSAID.s == "" || j.Severity == AdvisorySeverityUnset || err != nil {
		return errors.New("an advisory has a ghsa_id, a severity and a vulnerable_version_range")
	}
	*a = Advisory{GHSAID: j.GHSAID, Severity: j.Severity, VulnerableVersionRange: rng}
	if j.FirstPatchedVersion != nil {
		a.FirstPatchedVersion = *j.FirstPatchedVersion
	}
	return nil
}

// SecretName is the name of a secret ($defs/secret-name): a letter or _,
// then letters, digits and _. GitHub compares names without case, so
// ParseSecretName writes it in upper case, and two spellings of one are
// ==. The job's token is GITHUB_TOKEN. The zero SecretName is none.
type SecretName struct{ s string }

var secretNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ParseSecretName reads the name of a secret.
func ParseSecretName(s string) (SecretName, error) {
	if !secretNamePattern.MatchString(s) {
		return SecretName{}, fmt.Errorf("%q is not the name of a secret: a letter or _, then letters, digits and _", s)
	}
	return SecretName{strings.ToUpper(s)}, nil
}

// MustSecretName is ParseSecretName that panics on an error.
func MustSecretName(s string) SecretName {
	n, err := ParseSecretName(s)
	if err != nil {
		panic(err)
	}
	return n
}

func (n SecretName) String() string { return n.s }

func (n SecretName) MarshalJSON() ([]byte, error) {
	if n.s == "" {
		return nil, errors.New("the zero SecretName is no secret")
	}
	return json.Marshal(n.s)
}

func (n *SecretName) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseSecretName(s)
	if err != nil {
		return err
	}
	*n = v
	return nil
}

// ConfigurationVariableName is the name of a configuration variable
// ($defs/configuration-variable-name), as vars.<name> reads it: ASCII
// letters, digits and _, not starting with a digit, and not starting with
// GITHUB_ in any case. GitHub refuses to create other names, keeps the
// name in upper case and reads vars.<name> without case, so
// ParseConfigurationVariableName writes it in upper case, and two
// spellings of one are ==. The zero ConfigurationVariableName is none.
type ConfigurationVariableName struct{ s string }

// ParseConfigurationVariableName reads the name of a configuration
// variable: an error for a name that no level of GitHub can define.
func ParseConfigurationVariableName(s string) (ConfigurationVariableName, error) {
	if !secretNamePattern.MatchString(s) || strings.HasPrefix(strings.ToUpper(s), "GITHUB_") {
		return ConfigurationVariableName{}, fmt.Errorf("%q is not the name of a configuration variable: a letter or _, then letters, digits and _, not starting with GITHUB_", s)
	}
	return ConfigurationVariableName{strings.ToUpper(s)}, nil
}

// MustConfigurationVariableName is ParseConfigurationVariableName that
// panics on an error.
func MustConfigurationVariableName(s string) ConfigurationVariableName {
	n, err := ParseConfigurationVariableName(s)
	if err != nil {
		panic(err)
	}
	return n
}

func (n ConfigurationVariableName) String() string { return n.s }

func (n ConfigurationVariableName) MarshalJSON() ([]byte, error) {
	if n.s == "" {
		return nil, errors.New("the zero ConfigurationVariableName is no name")
	}
	return json.Marshal(n.s)
}

func (n *ConfigurationVariableName) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseConfigurationVariableName(s)
	if err != nil {
		return err
	}
	*n = v
	return nil
}

// RequestDestination is where a request goes as a workflow writes it
// ($defs/request-destination): a host, in lower case and without its
// port, or ${{ <path> }}, the path of a context whose value is the URL.
// The zero RequestDestination is none.
type RequestDestination struct{ s string }

var (
	destinationHost = regexp.MustCompile(`^([A-Za-z0-9_.-]+|\[[0-9A-Fa-f:]+\])$`)
	destinationPath = regexp.MustCompile(`^\$\{\{ [A-Za-z_][A-Za-z0-9_.*-]* \}\}$`)
)

// ParseRequestDestination reads a destination: a host, or a context's path
// in ${{ }}. It writes either in lower case: GitHub reads the names of
// contexts and their properties in any case.
func ParseRequestDestination(s string) (RequestDestination, error) {
	switch {
	case destinationPath.MatchString(s):
		return RequestDestination{strings.ToLower(s)}, nil
	case destinationHost.MatchString(s):
		return RequestDestination{strings.ToLower(s)}, nil
	}
	return RequestDestination{}, fmt.Errorf("%q is not a destination: a host without a scheme, a port nor a path, or ${{ <path> }}", s)
}

// MustRequestDestination is ParseRequestDestination that panics on an
// error.
func MustRequestDestination(s string) RequestDestination {
	d, err := ParseRequestDestination(s)
	if err != nil {
		panic(err)
	}
	return d
}

// RequestDestinationOfPath is the destination of the context path p, such
// as secrets.UPLOAD_API: ${{ p }}.
func RequestDestinationOfPath(p string) (RequestDestination, error) {
	return ParseRequestDestination("${{ " + p + " }}")
}

func (d RequestDestination) String() string { return d.s }

func (d RequestDestination) MarshalJSON() ([]byte, error) {
	if d.s == "" {
		return nil, errors.New("the zero RequestDestination is no destination")
	}
	return json.Marshal(d.s)
}

func (d *RequestDestination) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseRequestDestination(s)
	if err != nil {
		return err
	}
	*d = v
	return nil
}
