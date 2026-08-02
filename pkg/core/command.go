package core

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/remote"
	"gopkg.in/yaml.v3"
)

// バージョンとインストール情報を保持する変数
var (
	versionInfo = ""
)

const (
	// ExitStatusSuccessNoProblem はコマンドが成功し、問題が見つからなかった場合の終了ステータス
	ExitStatusSuccessNoProblem = 0
	// ExitStatusSuccessProblemFound はコマンドが成功し、問題が見つかった場合の終了ステータス
	ExitStatusSuccessProblemFound = 1
	// ExitStatusInvalidCommandOption はコマンドラインオプションの解析に失敗した場合の終了ステータス
	ExitStatusInvalidCommandOption = 2
	// ExitStatusFailure はワークフローをチェック中に何らかの致命的なエラーが発生してコマンドが停止した場合の終了ステータス
	ExitStatusFailure = 3
)

func printingUsageHeader(out io.Writer) {
	fmt.Fprintf(out, `Usage: sisakulint [FLAGS] [FILES...] [OPTIONS]

sisakulint is a static and fast-executing linter for {.github/workflows/*.yaml or .*yml} files.

To verify all YAML files in the current repository, simply execute sisakulint without any parameters.
It will auto-detect the closest '.github/workflows' directory for you.

$ sisakulint

# "Note: You can enable the debug mode by running sisakulint with the -debug argument.
# This will provide a detailed output of the syntax tree traversal,
# including the analysis of each node and additional logs,
# helping you to understand the internal workings and diagnose any issues."

$ sisakulint -debug

# "Note": it can be used in reviewdog by supporting sarif output,

$ sisakulint -format "{{sarif .}}"

# Remote scanning: scan GitHub repositories directly via API

$ sisakulint -remote owner/repo
$ sisakulint -remote owner/repo -pr 123
$ sisakulint -remote https://github.com/owner/repo/pull/123
$ sisakulint -remote "org:kubernetes"
$ sisakulint -remote owner/repo -r -D 5

# Documents
- https://sisaku-security.github.io/lint/

# Poster
- https://sechack365.nict.go.jp/achievement/2023/pdf/14C.pdf

Flags:
`)
}

func getCommandVersion() string {
	var buildInfos []byte
	toolVersion := "unknown"
	if versionInfo != "" {
		toolVersion = "v" + versionInfo
	}
	buildInfos = fmt.Appendf(buildInfos, "Tool version: %s\n", toolVersion)
	buildInfos = fmt.Appendf(buildInfos, "Go version: %s\n", runtime.Version())
	buildInfos = fmt.Appendf(buildInfos, "OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)

	info, ok := debug.ReadBuildInfo()
	if ok {
		buildInfos = fmt.Appendf(buildInfos, "Build info:\n")
		for _, setting := range info.Settings {
			if setting.Key == "-buildmode" || setting.Key == "-compiler" ||
				strings.HasPrefix(setting.Key, "GO") ||
				strings.HasPrefix(setting.Key, "vcs") {
				buildInfos = fmt.Appendf(buildInfos, "%s=%s\n", setting.Key, setting.Value)
			}
		}
	}

	return string(buildInfos)
}

// Commandは全体のsisakulintコマンドを表します。与えられたstdin/stdout/stderrは入出力に使用
type Command struct {
	// Stdinはstdinから入力を読み込むためのリーダーです
	Stdin io.Reader
	// Stdoutはstdoutに出力を書き込むためのライターです
	Stdout io.Writer
	// Stderrはstderrに出力を書き込むためのライターです
	Stderr io.Writer
}

// todo: linterを実行して結果を返すメソッド
func (cmd *Command) runLint(args []string, linterOpts *LinterOptions, initConfig bool, generateBoilerplate bool) ([]*ValidateResult, error) {
	l, err := NewLinter(cmd.Stdout, linterOpts)
	if err != nil {
		return nil, err
	}

	if initConfig {
		return nil, l.GenerateDefaultConfig(".")
	}

	if generateBoilerplate {
		return nil, l.GenerateBoilerplate(".")
	}

	if len(args) == 0 {
		return l.LintRepository(".")
	}

	return l.LintFiles(args, nil)
}

// runAutofix returns true if any fixer hit the GitHub API rate limit, so
// Main can surface a non-zero exit and skip the affected file's write
// (issue #474).
func (cmd *Command) runAutofix(results []*ValidateResult, isDryRun bool, baseDir string) (rateLimited bool) {
	for _, res := range results {
		if len(res.AutoFixers) == 0 {
			continue
		}
		fileRateLimited := false
		for _, fixer := range res.AutoFixers {
			if err := fixer.Fix(); err != nil {
				if IsGitHubRateLimitError(err) {
					fileRateLimited = true
					rateLimited = true
				}
				var lintErr *LintingError
				if errors.As(err, &lintErr) {
					lintErr.FilePath = res.FilePath
					lintErr.DisplayError(cmd.Stderr, res.Source)
				} else {
					fmt.Fprintf(cmd.Stderr, "Error while fixing %s: %v\n", fixer.RuleName(), err)
				}
			}
		}
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		err := enc.Encode(res.ParsedWorkflow.BaseNode)
		if err != nil {
			fmt.Fprintf(cmd.Stderr, "Error while marshaling the fixed workflow: %v\n", err)
		}
		data := buf.Bytes()
		if isDryRun {
			fmt.Fprintf(cmd.Stdout, "Fixed workflow %s:\n%s\n", res.FilePath, string(data))
			continue
		}
		if fileRateLimited {
			fmt.Fprintf(cmd.Stderr, "Skipping write for %s due to GitHub API rate limit; re-run after authenticating to complete the fix.\n", res.FilePath)
			continue
		}
		writePath := res.FilePath
		if baseDir != "" && !filepath.IsAbs(writePath) {
			writePath = filepath.Join(baseDir, writePath)
		}
		err = os.WriteFile(writePath, data, 0644) //nolint:gosec // auto-fix overwrites existing workflow files; preserving 0644 for git and CI compatibility
		if err != nil {
			fmt.Fprintf(cmd.Stderr, "Error while writing the fixed workflow: %v\n", err)
			err := os.WriteFile(writePath, res.Source, 0644) //nolint:gosec // restore original workflow file
			if err != nil {
				fmt.Fprintf(cmd.Stderr, "Error while restoring the original workflow: %v\n", err)
			}
		} else {
			fmt.Fprintf(cmd.Stdout, "Fixed workflow %s\n", res.FilePath)
		}
	}
	return rateLimited
}

type ignorePatternFlags []string

func (i *ignorePatternFlags) String() string {
	return "option for ignore patterns"
}
func (i *ignorePatternFlags) Set(v string) error {
	*i = append(*i, v)
	return nil
}

type enabledRuleFlags []string

func (e *enabledRuleFlags) String() string {
	return "option for enabling opt-in rules"
}
func (e *enabledRuleFlags) Set(v string) error {
	*e = append(*e, v)
	return nil
}

type remoteTargetFlags []string

func (t *remoteTargetFlags) String() string {
	if t == nil {
		return ""
	}
	return strings.Join(*t, ",")
}

func (t *remoteTargetFlags) Set(v string) error {
	*t = append(*t, v)
	return nil
}

// todo: sisakulintのmain関数
func (cmd *Command) Main(args []string) int {
	var showVersion bool
	var linterOpts LinterOptions
	var ignorePats ignorePatternFlags
	var enabledRules enabledRuleFlags
	var initConfig bool
	var generateBoilerplate bool
	var generateActionList bool
	var autoFixMode string
	var remoteInput string
	var recursive bool
	var maxDepth int
	var parallelism int
	var limit int
	var githubTokenFlag string
	var pullRequest int
	var expectedHeadSHA string
	var remoteCheckoutDir string
	var remoteTargets remoteTargetFlags

	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(cmd.Stderr)
	flags.Var(&ignorePats, "ignore", "Regular expression matching to error messages you want to ignore. This flag is repeatable")
	flags.Var(&enabledRules, "enable-rule",
		"Enable an opt-in rule by name. Repeatable. "+
			"Currently available opt-in rules: missing-timeout-minutes")
	flags.BoolVar(&generateBoilerplate, "boilerplate", false, "Generate a costomized template file for GitHub Actions workflow")
	flags.StringVar(&linterOpts.CustomErrorMessageFormat, "format", "", "Custom template to format error messages in Go template syntax.")
	flags.StringVar(&linterOpts.ConfigurationFilePath, "config-file", "", "File path to config file")
	flags.BoolVar(&initConfig, "init", false, "Generate default config file at .github/action.yaml in current project. see : https://docs.github.com/ja/actions/creating-actions/metadata-syntax-for-github-actions#github-actions%E3%81%AEyaml%E6%A7%8B%E6%96%87%E3%81%AB%E3%81%A4%E3%81%84%E3%81%A6")
	flags.BoolVar(&generateActionList, "generate-action-list", false, "Generate action list configuration from existing workflow files")
	flags.BoolVar(&linterOpts.IsVerboseOutputEnabled, "verbose", false, "Enable verbose output")
	flags.BoolVar(&linterOpts.IsDebugOutputEnabled, "debug", false, "Enable debug output (for development)")
	flags.BoolVar(&showVersion, "version", false, "Show version and how this binary was installed")
	flags.StringVar(&linterOpts.StdinInputFileName, "stdin-filename", "", "File name when reading input from stdin")
	flags.StringVar(&autoFixMode, "fix", "off", "Enable auto-fix mode. Available options: off, on, dry-run")
	flags.StringVar(&remoteInput, "remote", "", "Remote repository to scan (owner/repo, URL, or search query like 'org:kubernetes')")
	flags.IntVar(&pullRequest, "pr", 0, "Pull request number to scan at its immutable head (-remote only)")
	flags.StringVar(&expectedHeadSHA, "expected-head-sha", "", "Fail if the pull request head no longer matches this SHA (-remote -pr only)")
	flags.StringVar(&remoteCheckoutDir, "remote-checkout-dir", "", "Extract the pull request snapshot into this new directory instead of a temporary directory (-remote -pr only)")
	flags.Var(&remoteTargets, "remote-target", "Repository-relative changed workflow path to report or fix; repeatable (-remote -pr only)")
	flags.BoolVar(&recursive, "r", false, "Enable recursive scanning of reusable workflows (-remote only)")
	flags.IntVar(&maxDepth, "D", 3, "Max recursion depth for recursive scanning (-remote only)")
	flags.IntVar(&parallelism, "p", 3, "Number of parallel scans (-remote only)")
	flags.IntVar(&limit, "l", 30, "Max repositories for search queries (-remote only)")
	flags.StringVar(&githubTokenFlag, "github-token", "",
		"GitHub API token used by rules that call the GitHub API, including commit-sha autofix and known-vulnerable-actions. "+
			"Falls back to SISAKULINT_GITHUB_TOKEN, GITHUB_TOKEN, then GH_TOKEN. "+
			"Without a token, unauthenticated requests are limited to 60 req/h and may interrupt GitHub API checks")

	flags.Usage = func() {
		printingUsageHeader(cmd.Stderr)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// -h or -help
			return ExitStatusSuccessNoProblem
		}
		return ExitStatusInvalidCommandOption
	}

	if autoFixMode != "off" && autoFixMode != "on" && autoFixMode != FileFixDryRun {
		fmt.Fprintf(cmd.Stderr, "Invalid value for -fix: %s\n", autoFixMode)
		return ExitStatusInvalidCommandOption
	}
	if pullRequest < 0 {
		fmt.Fprintln(cmd.Stderr, "Invalid value for -pr: must not be negative")
		return ExitStatusInvalidCommandOption
	}
	if remoteInput == "" && (pullRequest != 0 || expectedHeadSHA != "" || remoteCheckoutDir != "" || len(remoteTargets) > 0) {
		fmt.Fprintln(cmd.Stderr, "-pr, -expected-head-sha, -remote-checkout-dir, and -remote-target require -remote")
		return ExitStatusInvalidCommandOption
	}
	if pullRequest == 0 && remoteInput != "" && (expectedHeadSHA != "" || remoteCheckoutDir != "" || len(remoteTargets) > 0) {
		parsed, err := remote.ParseInput(remoteInput)
		if err != nil || parsed.PullNumber == 0 {
			fmt.Fprintln(cmd.Stderr, "-expected-head-sha, -remote-checkout-dir, and -remote-target require a pull request URL or -pr")
			return ExitStatusInvalidCommandOption
		}
	}
	if remoteInput != "" && autoFixMode == "on" && remoteCheckoutDir == "" {
		parsed, _ := remote.ParseInput(remoteInput)
		if pullRequest > 0 || (parsed != nil && parsed.PullNumber > 0) {
			fmt.Fprintln(cmd.Stderr, "-remote pull request scans require -remote-checkout-dir when -fix on is used")
			return ExitStatusInvalidCommandOption
		}
	}

	if showVersion {
		fmt.Fprintf(
			cmd.Stdout,
			"%s",
			getCommandVersion(),
		)
		return ExitStatusSuccessNoProblem
	}

	linterOpts.ErrorIgnorePatterns = ignorePats
	linterOpts.EnabledOptInRules = enabledRules
	linterOpts.LogOutputDestination = cmd.Stderr

	token, source := ResolveGitHubToken(githubTokenFlag, nil)
	linterOpts.GitHubToken = token
	enableAutofix := autoFixMode == "on" || autoFixMode == FileFixDryRun

	if generateActionList {
		if err := GenerateActionListConfig("."); err != nil {
			fmt.Fprintf(cmd.Stderr, "Error generating action list: %v\n", err)
			return ExitStatusFailure
		}
		return ExitStatusSuccessNoProblem
	}

	if token == "" {
		fmt.Fprintln(cmd.Stderr,
			"sisakulint: no GitHub token detected; GitHub API checks (known-vulnerable-actions, commit-sha autofix) limited to 60 req/h. "+
				"Set GITHUB_TOKEN, GH_TOKEN, SISAKULINT_GITHUB_TOKEN, or pass -github-token to lift the limit.")
	} else if linterOpts.IsVerboseOutputEnabled {
		fmt.Fprintf(cmd.Stderr, "sisakulint: using GitHub token from %s for GitHub API checks.\n", source)
	}

	if remoteInput != "" {
		parsed, err := remote.ParseInput(remoteInput)
		if err != nil {
			fmt.Fprintf(cmd.Stderr, "Invalid remote input: %v\n", err)
			return ExitStatusInvalidCommandOption
		}
		if parsed.PullNumber > 0 {
			if pullRequest > 0 && pullRequest != parsed.PullNumber {
				fmt.Fprintf(cmd.Stderr, "Pull request number mismatch: URL specifies #%d but -pr specifies #%d\n", parsed.PullNumber, pullRequest)
				return ExitStatusInvalidCommandOption
			}
			pullRequest = parsed.PullNumber
		}
		if pullRequest > 0 {
			return cmd.runRemotePullRequestScan(
				parsed,
				pullRequest,
				expectedHeadSHA,
				remoteCheckoutDir,
				remoteTargets,
				autoFixMode,
				&linterOpts,
			)
		}
		return cmd.runRemoteScan(remoteInput, &linterOpts, &remote.ScannerOptions{
			Parallelism: parallelism,
			Recursive:   recursive,
			MaxDepth:    maxDepth,
			Limit:       limit,
			Verbose:     linterOpts.IsVerboseOutputEnabled,
			Output:      cmd.Stderr,
			GitHubToken: linterOpts.GitHubToken,
		})
	}

	errs, err := cmd.runLint(flags.Args(), &linterOpts, initConfig, generateBoilerplate)
	if err != nil {
		fmt.Fprintln(cmd.Stderr, err.Error())
		return ExitStatusFailure
	}
	hasErrors := false
	for _, r := range errs {
		if len(r.Errors) > 0 {
			hasErrors = true
			break
		}
	}
	if hasErrors {
		if enableAutofix {
			if rateLimited := cmd.runAutofix(errs, autoFixMode == FileFixDryRun, ""); rateLimited {
				fmt.Fprintln(cmd.Stderr,
					"sisakulint: commit-sha autofix aborted because the GitHub API rate limit was exceeded. "+
						"Re-run with GITHUB_TOKEN / GH_TOKEN / SISAKULINT_GITHUB_TOKEN set or with -github-token to complete the fix.")
				return ExitStatusFailure
			}
		}
		return ExitStatusSuccessProblemFound
	}

	return ExitStatusSuccessNoProblem
}

// runRemoteScan はリモートリポジトリをスキャンする
func (cmd *Command) runRemoteScan(input string, linterOpts *LinterOptions, scannerOpts *remote.ScannerOptions) int {
	linterOpts.IsRemote = true
	linter, err := NewLinter(cmd.Stdout, linterOpts)
	if err != nil {
		fmt.Fprintf(cmd.Stderr, "Error initializing linter: %v\n", err)
		return ExitStatusFailure
	}

	scannerOpts.LintFunc = func(filepath string, content []byte) (bool, error) {
		result, err := linter.Lint(filepath, content, nil)
		if err != nil {
			return false, err
		}
		return len(result.Errors) > 0, nil
	}

	scanner, err := remote.NewScanner(scannerOpts)
	if err != nil {
		fmt.Fprintf(cmd.Stderr, "Error initializing remote scanner: %v\n", err)
		return ExitStatusFailure
	}

	ctx := context.Background()
	results, err := scanner.Scan(ctx, input)
	if err != nil {
		fmt.Fprintf(cmd.Stderr, "Error scanning remote repositories: %v\n", err)
		return ExitStatusFailure
	}

	hasErrors := false
	for _, result := range results {
		if result.Error != nil {
			fmt.Fprintf(cmd.Stderr, "Error scanning %s: %v\n", result.Repository.FullName, result.Error)
			continue
		}
		if result.HasErrors {
			hasErrors = true
		}
	}

	if hasErrors {
		return ExitStatusSuccessProblemFound
	}

	fmt.Fprintf(cmd.Stdout, "No problems found.\n")
	return ExitStatusSuccessNoProblem
}

// runRemotePullRequestScan materializes the exact PR head as a local project,
// analyses every workflow for repository and cross-file context, and reports
// (or fixes) only workflows changed by the pull request.
func (cmd *Command) runRemotePullRequestScan(
	input *remote.ParsedInput,
	pullNumber int,
	expectedHeadSHA string,
	checkoutDir string,
	requestedTargets []string,
	autoFixMode string,
	linterOpts *LinterOptions,
) int {
	if input.Type == remote.InputTypeSearchQuery || input.Owner == "" || input.Repo == "" {
		fmt.Fprintln(cmd.Stderr, "Pull request scanning requires a single owner/repo repository")
		return ExitStatusInvalidCommandOption
	}
	if input.Ref != "" {
		fmt.Fprintln(cmd.Stderr, "A /tree/<ref> URL cannot be combined with pull request scanning")
		return ExitStatusInvalidCommandOption
	}

	var fetcher *remote.Fetcher
	var err error
	if linterOpts.GitHubToken == "" {
		// Keep direct CLI scans compatible with gh auth and git credential
		// fallback when no flag/environment token was supplied.
		fetcher, err = remote.NewFetcher(1)
	} else {
		fetcher, err = remote.NewFetcherWithToken(1, linterOpts.GitHubToken)
	}
	if err != nil {
		fmt.Fprintf(cmd.Stderr, "Error initializing remote fetcher: %v\n", err)
		return ExitStatusFailure
	}
	snapshot, err := fetcher.MaterializePullRequest(
		context.Background(),
		input.Owner,
		input.Repo,
		pullNumber,
		&remote.PullRequestSnapshotOptions{
			ExpectedHeadSHA: expectedHeadSHA,
			Destination:     checkoutDir,
		},
	)
	if err != nil {
		fmt.Fprintf(cmd.Stderr, "Error preparing pull request snapshot: %v\n", err)
		return ExitStatusFailure
	}
	defer func() {
		if err := snapshot.Close(); err != nil {
			fmt.Fprintf(cmd.Stderr, "Warning: failed to remove pull request snapshot: %v\n", err)
		}
	}()

	targets, err := selectRemoteTargets(requestedTargets, snapshot.TargetWorkflowPaths)
	if err != nil {
		fmt.Fprintf(cmd.Stderr, "Invalid remote target: %v\n", err)
		return ExitStatusInvalidCommandOption
	}
	if len(targets) == 0 {
		if linterOpts.IsVerboseOutputEnabled {
			fmt.Fprintf(cmd.Stderr, "Pull request #%d has no changed workflow files at %s\n", pullNumber, snapshot.HeadSHA)
		}
		return ExitStatusSuccessNoProblem
	}
	if len(snapshot.WorkflowPaths) == 0 {
		fmt.Fprintln(cmd.Stderr, "Pull request snapshot contains no workflow files")
		return ExitStatusFailure
	}

	linterOpts.IsRemote = false
	linterOpts.CurrentWorkingDirectoryPath = snapshot.Root
	linterOpts.ReportFilePaths = targets
	linterOpts.DisableRepositoryFileAutoFixers = true
	linter, err := NewLinter(cmd.Stdout, linterOpts)
	if err != nil {
		fmt.Fprintf(cmd.Stderr, "Error initializing linter: %v\n", err)
		return ExitStatusFailure
	}

	workflowFiles := make([]string, 0, len(snapshot.WorkflowPaths))
	for _, workflow := range snapshot.WorkflowPaths {
		workflowFiles = append(workflowFiles, filepath.Join(snapshot.Root, filepath.FromSlash(workflow)))
	}
	results, err := linter.LintFiles(workflowFiles, nil)
	if err != nil {
		fmt.Fprintf(cmd.Stderr, "Error linting pull request snapshot: %v\n", err)
		return ExitStatusFailure
	}

	targetResults := filterRemoteResults(results, targets)
	hasErrors := false
	for _, result := range targetResults {
		if len(result.Errors) > 0 {
			hasErrors = true
			break
		}
	}
	if !hasErrors {
		return ExitStatusSuccessNoProblem
	}

	if autoFixMode == "on" || autoFixMode == FileFixDryRun {
		if rateLimited := cmd.runAutofix(targetResults, autoFixMode == FileFixDryRun, snapshot.Root); rateLimited {
			fmt.Fprintln(cmd.Stderr,
				"sisakulint: commit-sha autofix aborted because the GitHub API rate limit was exceeded. "+
					"Re-run with GITHUB_TOKEN / GH_TOKEN / SISAKULINT_GITHUB_TOKEN set or with -github-token to complete the fix.")
			return ExitStatusFailure
		}
	}
	return ExitStatusSuccessProblemFound
}

func selectRemoteTargets(requested, changed []string) ([]string, error) {
	changedSet := make(map[string]struct{}, len(changed))
	for _, target := range changed {
		changedSet[normalizeReportPath(target)] = struct{}{}
	}
	if len(requested) == 0 {
		result := append([]string(nil), changed...)
		sort.Strings(result)
		return result, nil
	}

	seen := make(map[string]struct{}, len(requested))
	result := make([]string, 0, len(requested))
	for _, target := range requested {
		normalized := normalizeReportPath(target)
		if filepath.IsAbs(target) || normalized == "." || normalized == ".." || strings.HasPrefix(normalized, "../") {
			return nil, fmt.Errorf("unsafe repository-relative path %q", target)
		}
		if _, ok := changedSet[normalized]; !ok {
			return nil, fmt.Errorf("%q is not a changed workflow in this pull request", target)
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	sort.Strings(result)
	return result, nil
}

func filterRemoteResults(results []*ValidateResult, targets []string) []*ValidateResult {
	targetSet := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		targetSet[normalizeReportPath(target)] = struct{}{}
	}
	filtered := make([]*ValidateResult, 0, len(targets))
	for _, result := range results {
		if _, ok := targetSet[normalizeReportPath(result.FilePath)]; ok {
			filtered = append(filtered, result)
		}
	}
	return filtered
}
