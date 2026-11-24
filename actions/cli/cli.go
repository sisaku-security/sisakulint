package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/gh-intel/sisakulint/actions/facts"
	"io"
	"io/fs"
	"net/url"
	"os"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/internal/githubapi"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/remote"
	"github.com/gh-intel/sisakulint/actions/reportview"
	"github.com/gh-intel/sisakulint/actions/rules"
)

// Env is what Main sees of the process. No field may be nil.
type Env struct {
	Args     []string // without the name of the program
	Getenv   func(string) string
	Stdin    io.Reader
	Stdout   io.Writer
	Stderr   io.Writer
	Terminal bool // Stdout is a terminal: --color auto colors the text
}

// The exit codes that are not a report's (sysexits.h).
const (
	ExitUsage   = 64
	ExitNoInput = 66
	ExitFix     = 70
	ExitIO      = 74
	// ExitTempFail is a pull request whose head is not --pull-request-head:
	// the run judged no commit, and a later run of the head that moved
	// will (EX_TEMPFAIL).
	ExitTempFail = 75
)

type options struct {
	root       string
	paths      []string
	readAll    bool            // --read-all: read the whole repository, report the PATHs
	exclude    []lint.Exclude  // --exclude
	stdinName  facts.InputPath // zero when the input is not stdin
	threshold  lint.Severity
	factsIn    string // --facts; empty when not given
	factsBy    string // where factsIn was given, for an error (givenBy)
	factsFrom  valueOrigin
	factsOut   string // --write-facts; empty when not given
	acceptIn   string // --accept; empty when not given
	acceptBy   string // where acceptIn was given, for an error (givenBy)
	acceptFrom valueOrigin
	// configurationPath is --config; empty when not given.
	configurationPath string
	online            bool                 // --online
	added             []lint.AddedAttacker // --add-attacker
	githubAPI         *url.URL             // --github-api; nil is api.github.com
	remote            *remoteTarget        // --remote; nil reads --root
	snapshotDir       string               // --write-snapshot
	pullRequestHead   facts.SHA            // --pull-request-head; zero is any head
	repo              facts.Repo           // --repo; the zero Repo when not given
	arguments         facts.Resolver       // --fact; nil when none
	given             []facts.Entry        // --fact, as entries
	givenFrom         []valueOrigin        // where each of given was given
	fix               fixFlag
	dryRun            bool         // --dry-run
	registry          registryFlag // --registry
	version           bool         // --version
	template          []byte       // --init: the configuration file it writes; nil without --init, and with --legacy-configuration
	// legacy is the legacy configuration file of --init
	// --legacy-configuration, and templateValues the values of the keys
	// given with --init: Main writes the template after reading --root.
	legacy         *legacyConfiguration
	legacyPath     string // --legacy-configuration
	templateValues []keyValue
	examples       examplesFlag // --examples
	explain        explainFlag  // --explain
	format         outputFormat // --format
	reportOut      string       // --report; empty when not given
	sarifOut       string       // --sarif; empty when not given
	htmlOut        string       // --html; empty when not given
	serve          serveFlag    // --serve
	color          colorMode    // --color
	detail         detail       // --detail, or -v
	only           selectFlag   // --rule
	skip           selectFlag   // --skip-rule
	selection      lint.Selection
	selectBy       string // --rule or --skip-rule; empty when every rule runs
	// selectedInFile: the rules are chosen by rule or skip-rule of the
	// configuration file, so an error of Select is the file's.
	selectedInFile bool
}

// colorMode is --color. The zero colorMode is colorAuto, the default: color
// when Stdout is a terminal and NO_COLOR is empty.
type colorMode uint8

const (
	colorAuto colorMode = iota
	colorAlways
	colorNever
)

func (c colorMode) on(e Env) bool {
	switch c {
	case colorAlways:
		return true
	case colorNever:
		return false
	}
	return e.Terminal && e.Getenv("NO_COLOR") == ""
}

// outputFormat is --format. The zero outputFormat is formatText, the
// default: the text for people.
type outputFormat uint8

const (
	formatText  outputFormat = iota
	formatJSON               // the report (schema/report-v0.json)
	formatLine               // a line for each finding: path:line:column: severity kind: message
	formatSARIF              // SARIF 2.1.0 (sarifLog)
)

// detail is --detail: how much the text shows. The zero detail is
// detailNormal, the default: the findings in folds.
type detail uint8

const (
	detailNormal  detail = iota
	detailSummary        // a line for each fold
	detailFull           // every finding by itself (-v)
)

// usageError is an error in the arguments; inputError, in reading the
// inputs; parseError, one that flag has written already.
type (
	usageError struct{ error }
	inputError struct{ error }
	parseError struct{ error }
)

// Main runs the command and gives its exit code.
func Main(ctx context.Context, e Env) int {
	fail := func(code int, err error) int {
		fmt.Fprintf(e.Stderr, "sisakulint: %v\n", err)
		return code
	}
	o, err := parseArgs(e.Args, e.Stderr)
	if err != nil {
		var p parseError
		if errors.As(err, &p) {
			return ExitUsage // flag has written the error and the usage
		}
		var c configurationError
		if errors.As(err, &c) {
			return fail(ExitNoInput, err)
		}
		return fail(ExitUsage, err)
	}
	reg, err := lint.NewRegistry(rules.All(), rules.Quality()...)
	if err != nil {
		panic(err) // the rules are checked by their tests
	}
	if o.version {
		if _, err := io.WriteString(e.Stdout, versionText(debug.ReadBuildInfo())); err != nil {
			return fail(ExitIO, err)
		}
		return 0
	}
	if o.legacy != nil {
		return initLegacy(ctx, e, reg, o)
	}
	if o.template != nil {
		if _, err := reg.Select(o.selection, lint.FactSources{}); err != nil { // the rules, as a run would check them
			return fail(ExitUsage, fmt.Errorf("%s: %w", o.selectBy, err))
		}
		if _, err := e.Stdout.Write(o.template); err != nil {
			return fail(ExitIO, err)
		}
		return 0
	}
	if o.registry.set {
		marshal := reg.MarshalJSON
		if o.registry.full {
			marshal = reg.MarshalJSONFull
		}
		if err := writeJSON(e.Stdout, "the registry", marshal); err != nil {
			return fail(ExitIO, err)
		}
		return 0
	}
	if o.explain.set {
		b, err := explain(reg, o.explain)
		if err != nil {
			var u usageError
			if errors.As(err, &u) {
				return fail(ExitUsage, err)
			}
			panic(err) // explain gives Explain only the IDs reg has, and package rules' TestExamples checks their examples
		}
		if _, err := e.Stdout.Write(b); err != nil {
			return fail(ExitIO, err)
		}
		return 0
	}
	if o.examples.set {
		return examples(ctx, e, reg, o)
	}
	var root *os.Root // not opened for stdin and --remote, which --fix does not write
	var fsys fs.FS    // the repository: root's files, or the tree of --remote; nil for stdin
	var tree *remote.Tree
	var pull *pullRun     // --pull-request
	var snapshot *os.Root // --write-snapshot
	snapshotWritten := false
	switch {
	case o.remote != nil:
		if o.snapshotDir != "" { // before the run asks GitHub anything
			if snapshot, err = makeSnapshotDir(o.snapshotDir); err != nil {
				var u usageError
				if errors.As(err, &u) {
					return fail(ExitUsage, err)
				}
				return fail(ExitIO, err)
			}
			defer snapshot.Close()
			defer func() { // a run that stops before writing leaves no directory: run it again with the same DIR
				if !snapshotWritten {
					os.Remove(o.snapshotDir) // only when empty
				}
			}()
		}
		token := e.Getenv("GITHUB_TOKEN")
		if token == "" {
			fmt.Fprintln(e.Stderr, "sisakulint: GITHUB_TOKEN is empty: asking GitHub without a token, which sees public repositories only, 60 requests an hour")
		}
		c := githubapi.New(githubapi.Options{Token: token, BaseURL: o.githubAPI})
		if o.remote.pull > 0 {
			tree, pull, err = openPullRequest(ctx, c, *o.remote, o.pullRequestHead, o.exclude)
			if errors.Is(err, remote.ErrHeadMoved) {
				return fail(ExitTempFail, err)
			}
		} else {
			tree, err = openRemote(ctx, c, *o.remote)
		}
		if err != nil {
			return fail(ExitNoInput, err)
		}
		fsys = tree
	case o.stdinName.IsZero():
		if root, err = os.OpenRoot(o.root); err != nil {
			return fail(ExitNoInput, err)
		}
		defer root.Close()
		fsys = root.FS()
	}
	r, src, err := resolver(o, e.Getenv, fsys) // before Select: a DefaultRun of facts reads src
	if err != nil {
		return fail(ExitNoInput, err)
	}
	accepted, err := acceptances(o.acceptIn, reg) // before Select: an entry of a rule the run leaves out is read too
	if err != nil {
		return fail(ExitNoInput, fileError(o.acceptBy, o.acceptFrom, o.acceptIn, err))
	}
	if reg, err = reg.Select(o.selection, src); err != nil {
		if o.selectedInFile {
			return fail(ExitNoInput, fmt.Errorf("%s: %w", o.selectBy, err))
		}
		return fail(ExitUsage, fmt.Errorf("%s: %w", o.selectBy, err))
	}
	if o.online && o.remote == nil && e.Getenv("GITHUB_TOKEN") == "" { // after Select, whose error is the run's one error
		fmt.Fprintln(e.Stderr, "sisakulint: GITHUB_TOKEN is empty: asking GitHub without a token, which sees public repositories only, 60 requests an hour")
	}
	in, err := readInputs(fsys, o, e.Stdin)
	if err != nil {
		var u usageError
		if errors.As(err, &u) {
			return fail(ExitUsage, err)
		}
		return fail(ExitNoInput, err)
	}
	in.Repo = o.repo
	if tree != nil {
		in.Submodules = tree.Submodules()
	}
	rep, unmatched := lint.Accept(lint.RunAdded(ctx, in, reg, r, o.added), accepted)
	for _, a := range unmatched {
		fmt.Fprintf(e.Stderr, "sisakulint: %v\n", fileError(o.acceptBy, o.acceptFrom, o.acceptIn, errors.New(unmatchedText(a))))
	}
	if pull != nil {
		if err := pull.apply(&rep, in, tree, o.paths); err != nil {
			return fail(ExitUsage, err)
		}
	}
	whole := rep       // every place: a fix is checked against a run again of all
	rep = rep.Narrow() // after Accept: an entry that matches a place not reported is matched
	if tree != nil {
		if err := unreadOther(tree, in); err != nil {
			return fail(ExitNoInput, err)
		}
		rep.Remote = remoteRevision(*o.remote, tree)
		if pull != nil {
			rep.Remote.PullRequest = pull.revision(rep, tree)
		}
	}
	snapshotFailed := false
	if snapshot != nil {
		snapshotWritten = true
		if err := writeSnapshot(snapshot, tree); err != nil {
			fmt.Fprintf(e.Stderr, "sisakulint: --write-snapshot: %v\n", err)
			snapshotFailed = true
		}
	}
	fixFailed := false
	var diff []byte
	switch {
	case o.dryRun:
		var unchecked []lint.Unchecked
		var files fixFiles = root
		if tree != nil {
			files = tree // a symlink of the tree is one to Lstat: refused as --root refuses it
		}
		diff, unchecked, err = dryRun(ctx, files, in, reg, r, whole, o.fix.safety, nil)
		if err != nil {
			fmt.Fprintf(e.Stderr, "sisakulint: --dry-run: %v\n", err)
			fixFailed = true
		}
		for _, u := range unchecked {
			fmt.Fprintf(e.Stderr, "sisakulint: %s\n", uncheckedText(u))
		}
	case o.fix.safety != lint.SafetyUnset && snapshot != nil:
		if !snapshotFailed {
			rep.Fix = applyFix(ctx, snapshot, in, reg, r, whole, o.fix.safety, treeSymlink(tree))
			fixFailed = rep.Fix.Error != ""
		}
	case o.fix.safety != lint.SafetyUnset:
		rep.Fix = applyFix(ctx, root, in, reg, r, whole, o.fix.safety, nil)
		fixFailed = rep.Fix.Error != ""
	}
	writeFailed := snapshotFailed
	if o.factsOut != "" {
		if err := writeFacts(o.factsOut, rep.Facts); err != nil {
			fmt.Fprintf(e.Stderr, "sisakulint: --write-facts: %v\n", err)
			writeFailed = true
		}
	}
	if o.reportOut != "" {
		if err := writeReportFile(o.reportOut, rep); err != nil {
			fmt.Fprintf(e.Stderr, "sisakulint: --report: %v\n", err)
			writeFailed = true
		}
	}
	var sarif []byte // built once for --sarif and --format sarif
	if o.sarifOut != "" || o.format == formatSARIF && !o.dryRun {
		if sarif, err = sarifLog(rep, in, reg, binaryVersion()); err != nil {
			return fail(ExitIO, fmt.Errorf("the SARIF: %w", err))
		}
	}
	if o.sarifOut != "" {
		if err := writeFileAtomic(o.sarifOut, sarif); err != nil {
			fmt.Fprintf(e.Stderr, "sisakulint: --sarif: %v\n", err)
			writeFailed = true
		}
	}
	var page []byte
	if o.htmlOut != "" || o.serve.set {
		if page, err = reportPage(rep, in, reg); err != nil {
			fmt.Fprintf(e.Stderr, "sisakulint: the report view: %v\n", err)
			writeFailed = true
		} else if o.htmlOut != "" {
			if err := writeFileAtomic(o.htmlOut, page); err != nil {
				fmt.Fprintf(e.Stderr, "sisakulint: --html: %v\n", err)
				writeFailed = true
			}
		}
	}
	switch {
	case o.dryRun:
		_, err = e.Stdout.Write(diff) // only the diff, for git apply
	case o.format == formatJSON:
		err = writeJSON(e.Stdout, "the report", rep.MarshalJSON)
	case o.format == formatSARIF:
		_, err = e.Stdout.Write(sarif)
	case o.format == formatLine:
		err = writeLines(e.Stdout, rep, in, reg, o.color.on(e))
	default:
		err = writeText(e.Stdout, rep, in, reg, textOptions{detail: o.detail, color: o.color.on(e), threshold: o.threshold})
	}
	if err != nil {
		return fail(ExitIO, err)
	}
	if o.serve.set && page != nil {
		err := reportview.Serve(ctx, o.serve.addr, page, func(url string) {
			fmt.Fprintf(e.Stderr, "sisakulint: serving the report view at %s (interrupt to stop)\n", url)
		})
		if err != nil {
			fmt.Fprintf(e.Stderr, "sisakulint: --serve: %v\n", err)
			writeFailed = true
		}
	}
	return exitCode(rep, o.threshold, fixFailed, writeFailed)
}

// writeReportFile writes rep as --format json writes it on stdout.
func writeReportFile(p string, rep lint.Report) error {
	b, err := rep.MarshalJSON()
	if err != nil {
		return err
	}
	return writeFileAtomic(p, append(b, '\n'))
}

// reportPage is the report view of rep.
func reportPage(rep lint.Report, in lint.Inputs, reg *lint.Registry) ([]byte, error) {
	p, err := reportview.Build(rep, in, reg)
	if err != nil {
		return nil, err
	}
	return p.HTML()
}

func parseArgs(args []string, stderr io.Writer) (options, error) {
	o := options{root: ".", threshold: lint.SeverityInfo}
	fs := flag.NewFlagSet("sisakulint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: sisakulint [flags] [PATH...]")
		fs.PrintDefaults()
	}
	fs.StringVar(&o.root, "root", ".", "the repository: every workflow and action.yml under it, or only the PATHs, relative to it (with --read-all, every workflow and action.yml under it, and the PATHs are reported)")
	stdinName := optional{}
	fs.BoolVar(&o.readAll, "read-all", false, "with PATHs: read every workflow and action.yml under --root, or of the repository of --remote, too, and report only on the PATHs: a finding, of any certainty, whose location, evidence or related place is in a PATH; of the states of the inputs, the bits of the exit code count only those of the PATHs; with --fix, write the fixes of the findings reported, which may change a file that is not a PATH")
	fs.Var(&stdinName, "stdin-name", "read one file from stdin, as this path of the repository")
	var values []keyValue // of the keys of the configuration file
	registerKeys(fs, &values)
	var configuration optional
	fs.Var(&configuration, "config", configurationUsage())
	initialize := false
	fs.BoolVar(&initialize, "init", false, initUsage())
	var legacyPath optional
	fs.Var(&legacyPath, "legacy-configuration", legacyUsage)
	var factsOut, api optional
	fs.Var(&factsOut, "write-facts", "write the facts this run asked, and the answers, as a file of facts")
	fs.BoolVar(&o.online, "online", false, "ask the GitHub API what the file of facts does not answer; the token is GITHUB_TOKEN")
	fs.Var(&o.fix, "fix", "write the safe fixes to the files; --fix=review writes all")
	fs.BoolVar(&o.dryRun, "dry-run", false, "with --fix: write nothing, and write on stdout, instead of the report, the diff of what --fix would write (for git apply)")
	fs.Var(&api, "github-api", "the root of the GitHub API, for GitHub Enterprise Server: an https URL, or an http URL of a loopback address (with --online or --remote)")
	var pullRequest, pullRequestHead optional
	fs.Var(&pullRequest, "pull-request", "with --remote: read the head of the pull request N of the repository, and report on the inputs the pull request changes (PATHs: only those of them)")
	fs.Var(&pullRequestHead, "pull-request-head", "with --pull-request: stop (exit 75) when the head of the pull request is not the commit SHA given to this flag; without this flag, the linter reads any head")
	var snapshotDir optional
	fs.Var(&snapshotDir, "write-snapshot", "with --remote: write the files the run read to DIR, a path that is not there, by their paths in the repository (no symlink, no submodule); with --fix, fix the files there")
	var remoteValue optional
	fs.Var(&remoteValue, "remote", "read a repository of GitHub instead of --root, without a clone: OWNER/REPO, OWNER/REPO@REF (a branch, a tag or a commit SHA), or the URL of the repository (.../tree/REF); the token is GITHUB_TOKEN")
	fs.Func("format", "text for people (the default); line, a line for each finding (path:line:column: severity kind: message); json, the report (schema/report-v0.json); or sarif, the report as SARIF 2.1.0, for GitHub code scanning", func(s string) error {
		f, ok := map[string]outputFormat{"text": formatText, "line": formatLine, "json": formatJSON, "sarif": formatSARIF}[s]
		if !ok {
			return fmt.Errorf("%q is not a format (text, line, json, sarif)", s)
		}
		o.format = f
		return nil
	})
	var report optional
	fs.Var(&report, "report", "write the report as JSON to the file `FILE`, in addition to the output on stdout that --format chooses")
	var sarif optional
	fs.Var(&sarif, "sarif", "write the report as SARIF 2.1.0 to the file `FILE`, in addition to the output on stdout that --format chooses")
	var html optional
	fs.Var(&html, "html", "write the report view to this file too: a page that draws each finding as the path of its evidence, marks the line of each quality finding, and lets one try the condition of each finding and each quality finding (the page has lines of the workflows)")
	fs.Var(&o.examples, "examples", "run the examples of every rule and quality rule (--examples=RULE: of that rule or quality rule) with the facts each has, and write them as a catalog with --html or serve it with --serve; reads nothing else")
	fs.Var(&o.serve, "serve", "serve the report view on 127.0.0.1 until interrupted; --serve=ADDR for another loopback address and port (the page has lines of the workflows)")
	fs.Func("color", "color the text: auto (on a terminal, unless NO_COLOR), always, never", func(s string) error {
		m, ok := map[string]colorMode{"auto": colorAuto, "always": colorAlways, "never": colorNever}[s]
		if !ok {
			return fmt.Errorf("%q is not a color (auto, always, never)", s)
		}
		o.color = m
		return nil
	})
	detailSet, verbose := false, false
	fs.Func("detail", "how much the text shows: summary (a line for each kind of finding), normal (the default), full (every finding)", func(s string) error {
		d, ok := map[string]detail{"summary": detailSummary, "normal": detailNormal, "full": detailFull}[s]
		if !ok {
			return fmt.Errorf("%q is not a detail (summary, normal, full)", s)
		}
		o.detail, detailSet = d, true
		return nil
	})
	fs.BoolVar(&verbose, "verbose", false, "the same as --detail full")
	fs.BoolVar(&verbose, "v", false, "the same as --detail full")
	fs.BoolVar(&o.version, "version", false, "write the version of the binary, its commit, the Go release and the platform, and the schemas of the JSON that the binary writes and reads, and read nothing")
	fs.Var(&o.registry, "registry", "write the registry of the rules as JSON (their IDs, fixes, undetected forms, inconclusive kinds) and read nothing; --registry=full also writes the facts each example runs with")
	fs.Var(&o.explain, "explain", "write the rule with this ID (all: every rule; terms: what the item names and values of that Markdown mean) as Markdown for people, and read nothing; may be given again. The form may change: what machines read is --registry")
	if err := fs.Parse(args); err != nil {
		return o, parseError{err}
	}
	if o.registry.set {
		if len(args) != 1 {
			return o, errors.New("--registry takes no other flag and no PATH")
		}
		return o, nil
	}
	if o.version {
		if len(args) != 1 {
			return o, errors.New("--version takes no other flag and no PATH")
		}
		return o, nil
	}
	if o.explain.set {
		if fs.NFlag() != 1 || fs.NArg() != 0 {
			return o, errors.New("--explain takes no other flag and no PATH")
		}
		return o, nil
	}
	if o.examples.set {
		allowed := map[string]bool{"examples": true, "html": true, "serve": true}
		var other []string
		fs.Visit(func(f *flag.Flag) {
			if !allowed[f.Name] {
				other = append(other, "--"+f.Name)
			}
		})
		switch {
		case len(other) != 0 || fs.NArg() != 0:
			return o, fmt.Errorf("--examples reads nothing: it takes only --html and --serve, not %s", strings.Join(append(other, fs.Args()...), " "))
		case html.value == "" && !o.serve.set:
			return o, errors.New("--examples writes a catalog: give --html or --serve")
		}
		o.htmlOut = html.value
		return o, nil
	}
	if initialize {
		other := slices.Clone(fs.Args())
		var pathKey *configurationKey
		fs.Visit(func(f *flag.Flag) {
			switch k := keyNamed(f.Name); {
			case f.Name == "init", legacyPath.set && (f.Name == "legacy-configuration" || f.Name == "root"):
			case k == nil:
				other = append(other, "--"+f.Name)
			case k.path:
				pathKey = k
			}
		})
		switch {
		case pathKey != nil:
			return o, fmt.Errorf("--init does not take --%s: sisakulint reads a relative path in the key %s from the directory of the configuration file, and --init does not know that directory; write %s in the file yourself", pathKey.name, pathKey.name, pathKey.name)
		case len(other) != 0 && legacyPath.set:
			return o, fmt.Errorf("--init with --legacy-configuration reads the legacy configuration file and the files under --root: it takes only --root and the flags whose names are keys of the configuration file, except %s, and not %s", flagNames("and", func(k configurationKey) bool { return k.path }), strings.Join(other, " "))
		case len(other) != 0:
			return o, fmt.Errorf("--init writes a configuration file and reads nothing: it takes only the flags whose names are keys of the configuration file, except %s, and not %s", flagNames("and", func(k configurationKey) bool { return k.path }), strings.Join(other, " "))
		case legacyPath.set && legacyPath.value == "":
			return o, errors.New("--legacy-configuration is empty")
		case o.root == "":
			return o, errors.New("--root is empty; leave it out for the current directory")
		}
		if err := applyValues(&o, values); err != nil { // checked as a run checks them; Main checks the rules
			return o, err
		}
		o.chooseRules(values)
		if legacyPath.set {
			c, err := readLegacyConfiguration(legacyPath.value)
			if err != nil {
				return o, err
			}
			o.legacy, o.legacyPath, o.templateValues = &c, legacyPath.value, values
			return o, nil
		}
		t, err := configurationTemplate(values, nil, nil)
		if err != nil {
			return o, err
		}
		o.template = t
		return o, nil
	}
	if legacyPath.set {
		return o, errors.New("--legacy-configuration is read by --init only: give --init")
	}
	inFile := func(err error) error { // names the configuration file in its errors
		var c configurationError
		if errors.As(err, &c) {
			return configurationError{fmt.Errorf("--config %s: %w", configuration.value, c.error)}
		}
		return err
	}
	if configuration.set {
		if configuration.value == "" {
			return o, errors.New("--config is empty")
		}
		o.configurationPath = configuration.value
		file, err := readConfigurationFile(configuration.value)
		if err != nil {
			return o, inFile(err)
		}
		if !o.readAll && (fs.NArg() > 0 || stdinName.set) {
			file = slices.DeleteFunc(file, func(v keyValue) bool { return v.key.wholeRoot })
		}
		values = mergeValues(values, file)
	}
	if err := applyValues(&o, values); err != nil {
		return o, inFile(err)
	}
	o.chooseRules(values)
	if verbose {
		if detailSet && o.detail != detailFull {
			return o, errors.New("-v is --detail full; it cannot go with another --detail")
		}
		o.detail = detailFull
	}
	for _, f := range []struct {
		name string
		v    optional
		to   *string
	}{{"--write-facts", factsOut, &o.factsOut}, {"--report", report, &o.reportOut}, {"--sarif", sarif, &o.sarifOut}, {"--html", html, &o.htmlOut}} {
		if f.v.set && f.v.value == "" {
			return o, fmt.Errorf("%s is empty", f.name)
		}
		*f.to = f.v.value
	}
	if api.set {
		if !o.online && !remoteValue.set {
			return o, errors.New("--github-api is only for --online and --remote")
		}
		u, err := parseAPI(api.value)
		if err != nil {
			return o, err
		}
		o.githubAPI = u
	}
	if remoteValue.set {
		t, err := parseRemote(remoteValue.value, o.githubAPI)
		if err != nil {
			return o, err
		}
		set := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
		switch {
		case set["root"]:
			return o, errors.New("--remote reads a repository of GitHub; it takes no --root")
		case set["stdin-name"]:
			return o, errors.New("--remote reads a repository of GitHub; it takes no --stdin-name")
		case slices.ContainsFunc(values, func(v keyValue) bool { return v.key.name == "repo" && v.from == originCommandLine }):
			return o, errors.New("--remote names the repository; it takes no --repo")
		case o.fix.safety != lint.SafetyUnset && !snapshotDir.set && !o.dryRun:
			return o, errors.New("--remote reads the files of GitHub and writes none; give --dry-run for the diff of the fixes, or --write-snapshot DIR to fix the files written there")
		}
		if pullRequest.set {
			n, err := strconv.Atoi(pullRequest.value)
			switch {
			case err != nil || n <= 0:
				return o, fmt.Errorf("--pull-request %s: not the number of a pull request", pullRequest.value)
			case t.pull > 0:
				return o, errors.New("--pull-request is not taken when --remote names a pull request by its URL (https://github.com/owner/repo/pull/N)")
			}
			t.pull = n
		}
		if t.pull > 0 {
			switch {
			case t.ref != "":
				return o, errors.New("--pull-request reads the head of the pull request; --remote takes no ref with it (@REF, /tree/REF)")
			case o.readAll:
				return o, errors.New("--pull-request reports on the inputs the pull request changes; it takes no --read-all")
			}
		}
		o.remote, o.repo = &t, t.repo
	}
	switch {
	case snapshotDir.set && !remoteValue.set:
		return o, errors.New("--write-snapshot writes the files that --remote read; give --remote")
	case snapshotDir.set && snapshotDir.value == "":
		return o, errors.New("--write-snapshot is given an empty path")
	}
	o.snapshotDir = snapshotDir.value
	switch {
	case pullRequest.set && !remoteValue.set:
		return o, errors.New("--pull-request reads a pull request of the repository of --remote; give --remote")
	case pullRequestHead.set && (o.remote == nil || o.remote.pull == 0):
		return o, errors.New("--pull-request-head needs --pull-request: --pull-request-head takes the commit SHA expected at the head of the pull request of --pull-request")
	case pullRequestHead.set:
		sha, err := facts.ParseSHA(pullRequestHead.value)
		if err != nil {
			return o, fmt.Errorf("--pull-request-head: %w", err)
		}
		o.pullRequestHead = sha
	}
	if o.root == "" {
		return o, errors.New("--root is empty; leave it out for the current directory")
	}
	if o.dryRun {
		switch {
		case o.fix.safety == lint.SafetyUnset:
			return o, errors.New("--dry-run shows what --fix would write; give --fix or --fix=review")
		case o.format == formatJSON:
			return o, errors.New("--dry-run cannot be used with --format json, because --dry-run writes the diff on stdout; to write the report as JSON too, use --report FILE")
		case o.format == formatSARIF:
			return o, errors.New("--dry-run cannot be used with --format sarif, because --dry-run writes the diff on stdout; to write the report as SARIF too, use --sarif FILE")
		}
	}
	if len(o.added) != 0 && o.fix.safety != lint.SafetyUnset {
		return o, errors.New("--add-attacker cannot be used with --fix: the check of the fixes runs the rules without the added attackers, so a finding that only an added attacker gives could not be checked")
	}
	if (o.htmlOut != "" || o.serve.set) && o.fix.safety != lint.SafetyUnset {
		return o, errors.New("--html and --serve draw the findings before the fixes; they cannot go with --fix")
	}
	o.paths = fs.Args()
	if !afterTerminator(args, o.paths) {
		for _, p := range o.paths {
			if strings.HasPrefix(p, "-") {
				return o, fmt.Errorf("%s: flags go before PATH (or put -- before a PATH that starts with -)", p)
			}
			if o.fix.safety != lint.SafetyUnset && (p == "safe" || p == "review") {
				return o, fmt.Errorf("%s: write --fix=%s (or put -- before a PATH named %s)", p, p, p)
			}
		}
	}
	if o.readAll {
		switch {
		case len(o.paths) == 0:
			return o, errors.New("--read-all reports on the PATHs: give a PATH")
		case stdinName.set:
			return o, errors.New("--read-all reads the files under --root; it takes no --stdin-name")
		}
	}
	if o.remote != nil && o.remote.pull > 0 {
		for _, p := range o.paths {
			if _, err := facts.CleanInputPath(p); err != nil {
				return o, fmt.Errorf("%s: %w", p, err)
			}
		}
	}
	if len(o.exclude) > 0 && !o.readAll && (o.remote == nil || o.remote.pull == 0) && (len(o.paths) > 0 || stdinName.set) {
		return o, errors.New("--exclude leaves paths out of every workflow and action.yml under --root; it takes no PATH and no --stdin-name")
	}
	if stdinName.set {
		n, err := facts.CleanInputPath(stdinName.value)
		if err != nil {
			return o, fmt.Errorf("--stdin-name: %w", err)
		}
		if len(o.paths) > 0 {
			return o, errors.New("--stdin-name reads one file from stdin; it takes no PATH")
		}
		if o.fix.safety != lint.SafetyUnset {
			return o, errors.New("--fix writes files; it cannot write stdin")
		}
		o.stdinName = n
	}
	return o, nil
}

// afterTerminator is whether rest, the arguments flag did not read, come
// after --.
func afterTerminator(args, rest []string) bool {
	i := len(args) - len(rest)
	return len(rest) > 0 && i > 0 && args[i-1] == "--"
}

// optional is a string flag that knows whether it was given.
type optional struct {
	value string
	set   bool
}

func (o *optional) String() string     { return o.value }
func (o *optional) Set(s string) error { o.value, o.set = s, true; return nil }

// writeJSON writes what marshal gives, and a newline. marshal is a
// MarshalJSON, not json.Marshal, which escapes <, > and & again.
func writeJSON(w io.Writer, what string, marshal func() ([]byte, error)) error {
	b, err := marshal()
	if err != nil {
		return fmt.Errorf("%s cannot be written: %w", what, err)
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// acceptances are the acceptances of the file p (--accept), checked against
// reg; none when p is empty.
func acceptances(p string, reg *lint.Registry) ([]lint.Acceptance, error) {
	if p == "" {
		return nil, nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return lint.LoadAcceptances(b, reg)
}

// unmatchedText says that the entry a of the file of acceptances matched no
// inconclusive place.
func unmatchedText(a lint.Acceptance) string {
	return fmt.Sprintf("no inconclusive finding of this run matches the entry of %s %s at %s %s with the span text %q, and the entry does not change the exit code: the place is gone, the text of the place changed, or the rule reported a confirmed or conditional finding or nothing at the place in this run (with an answer to a fact from --facts, --fact or --online, for example); fix the entry or remove the entry", a.Rule, a.KindID, a.Input, a.KeyPath, a.SpanText)
}

// exitCode is the exit code of a run whose report is on stdout.
func exitCode(rep lint.Report, threshold lint.Severity, fixFailed, writeFailed bool) int {
	switch {
	case fixFailed:
		return ExitFix
	case writeFailed:
		return ExitIO
	}
	return int(lint.Classify(rep, threshold))
}
