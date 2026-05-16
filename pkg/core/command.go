package core

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
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

// runAutofix returns true if any fixer aborted because of a GitHub API
// rate-limit. The caller uses that signal to surface a non-zero-exit
// warning to the user instead of silently shipping a partially-fixed tree
// (issue #474). Per-file rate-limit failures additionally suppress writing
// that file, since the on-disk result would otherwise mix freshly-pinned
// SHAs with leftover @vN tags and the user has no way to tell which is
// which from the exit code alone.
func (cmd *Command) runAutofix(results []*ValidateResult, isDryRun bool) (rateLimited bool) {
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
			// Skip writing partial output. Some fixers in this file succeeded,
			// but a rate-limited commit-sha resolver would leave a mix of
			// SHA-pinned and tag-pinned actions on disk that is harder to
			// recover from than the original file.
			fmt.Fprintf(cmd.Stderr, "Skipping write for %s due to GitHub API rate limit; re-run after authenticating to complete the fix.\n", res.FilePath)
			continue
		}
		err = os.WriteFile(res.FilePath, data, 0644) //nolint:gosec // auto-fix overwrites existing workflow files; preserving 0644 for git and CI compatibility
		if err != nil {
			fmt.Fprintf(cmd.Stderr, "Error while writing the fixed workflow: %v\n", err)
			err := os.WriteFile(res.FilePath, res.Source, 0644) //nolint:gosec // restore original workflow file
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
	flags.BoolVar(&recursive, "r", false, "Enable recursive scanning of reusable workflows (-remote only)")
	flags.IntVar(&maxDepth, "D", 3, "Max recursion depth for recursive scanning (-remote only)")
	flags.IntVar(&parallelism, "p", 3, "Number of parallel scans (-remote only)")
	flags.IntVar(&limit, "l", 30, "Max repositories for search queries (-remote only)")
	flags.StringVar(&githubTokenFlag, "github-token", "",
		"GitHub API token used by -fix on to resolve commit SHAs. "+
			"Falls back to SISAKULINT_GITHUB_TOKEN, GITHUB_TOKEN, then GH_TOKEN. "+
			"Without a token the unauthenticated 60 req/h limit may truncate fixes silently (issue #474)")

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

	// Resolve the GitHub token used by commit-sha autofix. Even when the
	// caller did not request -fix on, surfacing the source up-front (or the
	// missing-token warning) keeps the behaviour observable: users discover
	// the unauthenticated 60 req/h ceiling before it bites mid-fix
	// (issue #474).
	token, source := ResolveGitHubToken(githubTokenFlag, nil)
	linterOpts.GitHubToken = token
	enableAutofix := autoFixMode == "on" || autoFixMode == FileFixDryRun
	if enableAutofix {
		if token == "" {
			fmt.Fprintln(cmd.Stderr,
				"sisakulint: no GitHub token detected; commit-sha resolution limited to 60 req/h. "+
					"Set GITHUB_TOKEN, GH_TOKEN, SISAKULINT_GITHUB_TOKEN, or pass -github-token to lift the limit.")
		} else if linterOpts.IsVerboseOutputEnabled {
			fmt.Fprintf(cmd.Stderr, "sisakulint: using GitHub token from %s for commit-sha resolution.\n", source)
		}
	}

	if generateActionList {
		if err := GenerateActionListConfig("."); err != nil {
			fmt.Fprintf(cmd.Stderr, "Error generating action list: %v\n", err)
			return ExitStatusFailure
		}
		return ExitStatusSuccessNoProblem
	}

	if remoteInput != "" {
		return cmd.runRemoteScan(remoteInput, &linterOpts, &remote.ScannerOptions{
			Parallelism: parallelism,
			Recursive:   recursive,
			MaxDepth:    maxDepth,
			Limit:       limit,
			Verbose:     linterOpts.IsVerboseOutputEnabled,
			Output:      cmd.Stderr,
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
			if rateLimited := cmd.runAutofix(errs, autoFixMode == FileFixDryRun); rateLimited {
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
