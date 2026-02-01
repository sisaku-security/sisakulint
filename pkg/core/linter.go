package core

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/mattn/go-colorable"
	"github.com/sisaku-security/sisakulint/pkg/ast"
	"golang.org/x/sync/errgroup"
)

// LogLevel は Linter インスタンスで使用されるログレベルを表す型
type LogLevel int

const (
	// LogLevelNoOutputは、ログ出力が無いことを示す。
	LogLevelNoOutput LogLevel = 0
	// LogLevelDetailedOutputは、詳細なログ出力が有効であることを示す。
	LogLevelDetailedOutput = 1
	// LogLevelAllOutputIncludingDebugは、デバッグ情報を含むすべてのログ出力が有効であることを示す。
	LogLevelAllOutputIncludingDebug = 2
)

// OutputColorBehaviorは、出力の色付けの挙動を表す
type OutputColorBehavior int

const (
	// AutoColorは、出力の色付けを自動的に決定
	AutoColor OutputColorBehavior = iota
	// AlwaysColorは、常に出力を色付け
	AlwaysColor
	// NeverColorは、出力を色付けしない
	NeverColor
)

// この構造体は、NewLinter factory関数の呼び出しで使用
// 0値LinterOptions{}は、デフォルトの挙動
type LinterOptions struct {
	// IsVerboseOutputEnabledは、詳細なログ出力が有効であるかどうかを示すflag
	IsVerboseOutputEnabled bool
	// IsDebugOutputEnabledは、Debuglogの出力が有効であるかどうかを示すflag
	IsDebugOutputEnabled bool
	// LogOutputDestinationは、ログ出力を出力するためのio.Writerオブジェクト
	//todo: NOTICE: エラー出力はログ出力に含まれない
	LogOutputDestination io.Writer
	// OutputColorOptionは、エラー出力の色付けのオプション
	//それぞれの列挙値については、ColorOptionKindのドキュメントを参照
	OutputColorOption OutputColorBehavior
	// BoilerplateGenerationは、boilerplateを生成するためのディレクトリパス
	BoilerplateGeneration string
	// ShellcheckExecutableは、shellcheckを実行するための実行可能ファイル
	ShellcheckExecutable string
	// ErrorIgnorePatternsは、エラーをフィルタリングするための正規表現のリスト
	ErrorIgnorePatterns []string
	// ConfigurationFilePathは、設定ファイルのパス
	ConfigurationFilePath string
	// BoilerplateFilePathは、boilerplateファイルのパス
	BoilerplateFilePath string
	// CustomErrorMessageFormatは、エラーメッセージをフォーマットするためのカスタムテンプレート
	CustomErrorMessageFormat string
	// StdinInputFileNameは、標準入力から読み込む際のファイル名
	StdinInputFileName string
	// CurrentWorkingDirectoryPathは、現在の作業ディレクトリのパス
	CurrentWorkingDirectoryPath string
	//todo: OnCheckRulesModifiedは、チェックルールの追加や削除を行うフック
	OnCheckRulesModified func([]Rule) []Rule
}

// Linterは、workflowをlintするための構造体
type Linter struct {
	// projectsは、プロジェクト情報を管理する構造体
	projectInformation *Projects
	// errorOutputは、Linterからのエラー出力に使用されるio.Writerオブジェクト
	errorOutput io.Writer
	// logOutputは、ログ出力に使用されるio.Writerオブジェクト
	logOutput io.Writer
	// loggingLevelは、Linterのログレベルを示す
	loggingLevel LogLevel
	// shellcheckExecutableは、shellcheckの実行可能ファイルのパスまたは名前
	shellcheckExecutablePath string
	// errorIgnorePatternsは、エラーを無視するための正規表現パターンのリスト
	errorIgnorePatterns []*regexp.Regexp
	// defaultConfigurationは、sisakulintの default config を表す
	defaultConfiguration *Config
	// boilerplateGenerationは、boilerplateを生成する
	boilerplateGeneration *Boiler
	// errorFormatterは、エラーメッセージをカスタムフォーマットで出力するためのformatter
	errorFormatter *ErrorFormatter
	// currentWorkingDirectoryは、現在の作業ディレクトリのパス
	currentWorkingDirectory string
	//todo: modifyCheckRulesは、チェックルールを追加または削除するためのフック関数
	modifyCheckRules func([]Rule) []Rule
}

// NewLinterは新しいLinterインスタンスを作成する
// outパラメータは、Linterインスタンスからのエラーを出力するために使用される。出力を望まない場合は、io.Discardを設定してください。
// optsパラメータは、lintの動作を設定するLinterOptionsインスタンス
func NewLinter(errorOutput io.Writer, options *LinterOptions) (*Linter, error) {
	//log levelの設定
	var logLevel = LogLevelNoOutput
	if options.IsVerboseOutputEnabled {
		logLevel = LogLevelDetailedOutput
	} else if options.IsDebugOutputEnabled {
		logLevel = LogLevelAllOutputIncludingDebug
	}
	switch options.OutputColorOption {
	case NeverColor:
		color.NoColor = true
	case AlwaysColor:
		color.NoColor = false
	}
	//カラフル出力
	if file, ok := errorOutput.(*os.File); ok {
		errorOutput = colorable.NewColorable(file)
	}

	//logの出力の設定
	logOutput := io.Discard
	if options.LogOutputDestination != nil {
		logOutput = options.LogOutputDestination
	}

	//設定ファイルの読み込み
	var config *Config
	if options.ConfigurationFilePath != "" {
		con, err := ReadConfigFile(options.ConfigurationFilePath)
		if err != nil {
			return nil, err
		}
		config = con
	}
	//boilerplateファイルの読み込み
	var boiler *Boiler
	if options.BoilerplateFilePath != "" {
		d, err := ReadBoiler(options.BoilerplateFilePath)
		if err != nil {
			return nil, err
		}
		boiler = d
	}

	ignorePatterns := make([]*regexp.Regexp, len(options.ErrorIgnorePatterns))
	for i, pattern := range options.ErrorIgnorePatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid error ignore pattern : %q : %w", pattern, err)
		}
		ignorePatterns[i] = re
	}

	//エラーメッセージのフォーマットの作成
	var errorFormatter *ErrorFormatter
	if options.CustomErrorMessageFormat != "" {
		formatter, err := NewErrorFormatter(options.CustomErrorMessageFormat)
		if err != nil {
			return nil, err
		}
		errorFormatter = formatter
	}

	//working directoryの取得
	workDir := options.CurrentWorkingDirectoryPath
	if workDir == "" {
		if dir, err := os.Getwd(); err == nil {
			workDir = dir
		}
	}

	return &Linter{
		NewProjects(),
		errorOutput,
		logOutput,
		logLevel,
		options.ShellcheckExecutable,
		ignorePatterns,
		config,
		boiler,
		errorFormatter,
		workDir,
		options.OnCheckRulesModified,
	}, nil
}

// logはlog levelがDetailedOutput以上の場合にログを出力する
func (l *Linter) log(args ...interface{}) {
	if l.loggingLevel < LogLevelDetailedOutput {
		return
	}
	//verbose
	fmt.Fprint(l.logOutput, "[sisaku:🤔] ")
	fmt.Fprintln(l.logOutput, args...)
}

// debugはlog levelがAllOutputIncludingDebug以上の場合にログを出力する
func (l *Linter) debug(format string, args ...interface{}) {
	if l.loggingLevel < LogLevelAllOutputIncludingDebug {
		return
	}
	message := fmt.Sprintf("[linter mode] %s\n", format)
	fmt.Fprintf(l.logOutput, message, args...)
}

// debugWriterはlog levelがAllOutputIncludingDebug以上の場合にログを出力する
func (l *Linter) debugWriter() io.Writer {
	if l.loggingLevel < LogLevelAllOutputIncludingDebug {
		return io.Discard
	}
	return l.logOutput
}

// GenerateDefaultConfigは、-init指定の時に、指定されたディレクトリにデフォルトの configファイルを生成する
func (l *Linter) GenerateDefaultConfig(dir string) error {
	l.log("generating default config file...", dir)

	project, err := l.projectInformation.GetProjectForPath(dir)
	if err != nil {
		return err
	}
	if project == nil {
		return errors.New("project not found, Make sure the current project is initialized as a Git repository and the \".github/workflows\" directory exists")
	}

	configPath := filepath.Join(project.RootDirectory(), ".github", "action.yaml")
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("config file already exists: %q", configPath)
	}

	if err := writeDefaultConfigFile(configPath); err != nil {
		return err
	}

	fmt.Fprintf(l.errorOutput, "generated default config file: %q\n", configPath)
	return nil
}

// GenerateBoilerplateは、-boilerplate指定の時に、指定されたディレクトリにデフォルトの configファイルを生成する
func (l *Linter) GenerateBoilerplate(dir string) error {
	l.log("generating boilerplate file...", dir)

	project, err := l.projectInformation.GetProjectForPath(dir)
	if err != nil {
		return err
	}
	if project == nil {
		return errors.New("project not found, Make sure the current project is initialized as a Git repository and the \".github/workflows\" directory exists")
	}

	configPath := filepath.Join(project.RootDirectory(), ".github", "boilerplate.yaml")
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("config file already exists: %q", configPath)
	}

	if err := writeDefaultBoilerplateFile(configPath); err != nil {
		return err
	}

	fmt.Fprintf(l.errorOutput, "generated boilerplate file: %q\n", configPath)
	return nil
}

// LintRepositoryは、指定されたディレクトリのリポジトリをリントする
func (l *Linter) LintRepository(dir string) ([]*ValidateResult, error) {
	l.log("linting repository...", dir)

	project, err := l.projectInformation.GetProjectForPath(dir)
	if err != nil {
		return nil, err
	}
	if project == nil {
		return nil, errors.New("project not found")
	}
	l.log("Detected project:", project.RootDirectory())
	workflowsDir := project.WorkflowDirectory()
	return l.LintDir(workflowsDir, project)
}

// LintDirは、指定されたディレクトリをLint
func (l *Linter) LintDir(dir string, project *Project) ([]*ValidateResult, error) {
	// Preallocate files slice with a reasonable capacity for workflow files
	files := make([]string, 0, 10)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("it could not read %q , failed to walk directory: %w", dir, err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no yaml files found in %q", dir)
	}
	l.log("the number of corrected yaml file", len(files), "yaml files")

	//sort order of filepaths
	sort.Strings(files)

	return l.LintFiles(files, project)
}

// lintFilesは、指定されたyaml workflowをlintしてエラーを返す
// projectパラメタはnilにできる。その場合、ファイルパスからプロジェクトが検出される
func (l *Linter) LintFiles(filepaths []string, project *Project) ([]*ValidateResult, error) {
	fileCount := len(filepaths)
	switch fileCount {
	case 0:
		return nil, nil
	case 1:
		result, err := l.LintFile(filepaths[0], project)
		if err != nil {
			return nil, err
		}
		return []*ValidateResult{result}, nil
	}

	l.log("linting", fileCount, "getting started linting workflows...files")

	currentDir := l.currentWorkingDirectory
	proc := NewConcurrentExecutor(runtime.NumCPU()) //process.go
	debugLog := l.debugWriter()
	actionCacheFactory := NewLocalActionsMetadataCacheFactory(debugLog) //metadata.go
	reusableWorkflowCacheFactory := NewLocalReusableWorkflowCacheFactory(currentDir, debugLog)

	type workspace struct {
		path   string
		result *ValidateResult
		source []byte
	}

	workspaces := make([]workspace, len(filepaths))
	for i, pa := range filepaths {
		//workspaces = append(workspaces, workspace{path: pa})
		workspaces[i] = workspace{path: pa}
	}

	errorGroups := errgroup.Group{}
	for i := range workspaces {
		ws := &workspaces[i]
		localProject := project
		if localProject == nil {
			// このメソッドはl.projectInformationの状態を変更するため、並行して呼び出せない。
			projectForPath, err := l.projectInformation.GetProjectForPath(ws.path)
			if err != nil {
				return nil, err
			}
			localProject = projectForPath
		}
		actionCache := actionCacheFactory.GetCache(localProject) //[173]
		reusableWorkflowCache := reusableWorkflowCacheFactory.GetCache(localProject)

		errorGroups.Go(func() error {
			source, err := os.ReadFile(ws.path)
			if err != nil {
				return fmt.Errorf("%q could not read workflow file: %w", ws.path, err)
			}
			if currentDir != "" {
				if relPath, err := filepath.Rel(currentDir, ws.path); err == nil {
					ws.path = relPath //相対パスの活用
				}
			}
			result, err := l.validate(ws.path, source, localProject, proc, actionCache, reusableWorkflowCache)
			if err != nil {
				return fmt.Errorf("occur error when check %s: %w", ws.path, err)
			}
			ws.source = source
			ws.result = result
			return nil
		})
	}

	proc.Wait()
	if err := errorGroups.Wait(); err != nil {
		return nil, err
	}

	totalErrors := 0
	// Preallocate allResult with the capacity equal to the number of workspaces
	allResult := make([]*ValidateResult, 0, len(workspaces))
	for i := range workspaces {
		totalErrors += len(workspaces[i].result.Errors)
		allResult = append(allResult, workspaces[i].result)
	}

	if l.errorFormatter != nil {
		templateFields := make([]*TemplateFields, 0, totalErrors)
		for i := range workspaces {
			ws := &workspaces[i]
			for _, err := range ws.result.Errors {
				templateFields = append(templateFields, err.ExtractTemplateFields(ws.source))
			}
			//allErrors = append(allErrors, ws.result.Errors...)
			//allAutoFixers = append(allAutoFixers, ws.result.AutoFixers...)
		}
		if err := l.errorFormatter.Print(l.errorOutput, templateFields); err != nil {
			return nil, err
		}
	} else {
		for i := range workspaces {
			ws := &workspaces[i]
			l.displayErrors(ws.result.Errors, ws.source)
			//allErrors = append(allErrors, ws.result.Errors...)
			//allAutoFixers = append(allAutoFixers, ws.result.AutoFixers...)
		}
	}
	l.log("Detected", totalErrors, "errors in", fileCount, "files checked")

	return allResult, nil
}

// LintFileは、指定されたyaml workflowをlintしてエラーを返す
// projectパラメタはnilにできる。その場合、ファイルパスからプロジェクトが検出される
func (l *Linter) LintFile(file string, project *Project) (*ValidateResult, error) {
	if project == nil {
		pa, err := l.projectInformation.GetProjectForPath(file)
		if err != nil {
			return nil, err
		}
		project = pa
	}
	source, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("could not read %q workflow file: %w", file, err)
	}
	if l.currentWorkingDirectory != "" {
		if r, err := filepath.Rel(l.currentWorkingDirectory, file); err == nil {
			file = r
		}
	}
	//todo: process.go
	proc := NewConcurrentExecutor(runtime.NumCPU())
	//todo: action_metadata.go
	localActions := NewLocalActionsMetadataCache(project, l.debugWriter())
	//todo: reusing-workflows.go
	localReusableWorkflow := NewLocalReusableWorkflowCache(project, l.currentWorkingDirectory, l.debugWriter())
	result, err := l.validate(file, source, project, proc, localActions, localReusableWorkflow)
	proc.Wait()

	if err != nil {
		return nil, err
	}
	if l.errorFormatter != nil {
		if err := l.errorFormatter.PrintErrors(l.errorOutput, result.Errors, source); err != nil {
			return nil, fmt.Errorf("error formatting output: %w", err)
		}
	} else {
		l.displayErrors(result.Errors, source)
	}
	return result, nil
}

// Lintはbyteのスライスとして与えられたyaml workflowをlintしてエラーを返す
// pathパラメタは、コンテンツがどこからきたのかを示すfilepathとして使用
// pathパラメタに<stdin>を入力すると出力がSTDINから来たことを示す
// projectパラメタはnilにできる。その場合、ファイルパスからプロジェクトが検出される
func (l *Linter) Lint(filepath string, content []byte, project *Project) (*ValidateResult, error) {
	if project == nil && filepath != "<stdin>" {
		if _, err := os.Stat(filepath); !errors.Is(err, fs.ErrNotExist) {
			p, err := l.projectInformation.GetProjectForPath(filepath)
			if err != nil {
				return nil, err
			}
			project = p
		}
	}

	proc := NewConcurrentExecutor(runtime.NumCPU())
	localActions := NewLocalActionsMetadataCache(project, l.debugWriter())
	localReusableWorkflow := NewLocalReusableWorkflowCache(project, l.currentWorkingDirectory, l.debugWriter())
	result, err := l.validate(filepath, content, project, proc, localActions, localReusableWorkflow)
	proc.Wait()
	if err != nil {
		return nil, err
	}

	if l.errorFormatter != nil {
		if err := l.errorFormatter.PrintErrors(l.errorOutput, result.Errors, content); err != nil {
			return nil, fmt.Errorf("error formatting output: %w", err)
		}
	} else {
		l.displayErrors(result.Errors, content)
	}
	return result, nil
}

func makeRules(filePath string, localActions *LocalActionsMetadataCache, localReusableWorkflow *LocalReusableWorkflowCache) []Rule {
	return []Rule{
		// MatrixRule(),
		CredentialsRule(),
		// EventsRule(),
		JobNeedsRule(),
		// ActionRule(localActions),
		EnvironmentVariableRule(),
		IDRule(),
		PermissionsRule(),
		WorkflowCall(filePath, localReusableWorkflow),
		ExpressionRule(localActions, localReusableWorkflow),
		DeprecatedCommandsRule(),
		NewConditionalRule(),
		TimeoutMinuteRule(),
		CodeInjectionCriticalRule(),    // Detects untrusted input in privileged workflow triggers
		CodeInjectionMediumRule(),      // Detects untrusted input in normal workflow triggers
		EnvVarInjectionCriticalRule(),  // Detects envvar injection in privileged workflow triggers
		EnvVarInjectionMediumRule(),    // Detects envvar injection in normal workflow triggers
		EnvPathInjectionCriticalRule(), // Detects PATH injection in privileged workflow triggers
		EnvPathInjectionMediumRule(),   // Detects PATH injection in normal workflow triggers
		OutputClobberingCriticalRule(), // Detects output clobbering in privileged workflow triggers
		OutputClobberingMediumRule(),   // Detects output clobbering in normal workflow triggers
		CommitShaRule(),
		NewDependabotGitHubActionsRule(filePath), // Checks dependabot.yaml has github-actions ecosystem when unpinned actions found
		ArtifactPoisoningRule(),
		NewArtifactPoisoningMediumRule(),
		NewActionListRule(),
		NewUntrustedCheckoutRule(),
		NewCachePoisoningRule(),
		NewCachePoisoningPoisonableStepRule(),
		NewSecretExposureRule(),                                       // Detects toJSON(secrets) and secrets[dynamic-access]
		NewUnmaskedSecretExposureRule(),                               // Detects fromJson(secrets.XXX).yyy unmasked exposure
		NewImproperAccessControlRule(),                                // Detects improper access control with label-based approval and synchronize events
		ImpostorCommitRuleFactory(),                                   // Detects impostor commits from fork network
		NewUntrustedCheckoutTOCTOUCriticalRule(),                      // Detects TOCTOU with labeled event type and mutable refs
		NewUntrustedCheckoutTOCTOUHighRule(),                          // Detects TOCTOU with deployment environment and mutable refs
		NewRefConfusionRule(),                                         // Detects ref confusion attacks (same name branch and tag)
		NewObfuscationRule(),                                          // Detects obfuscated workflow patterns
		NewKnownVulnerableActionsRule(),                               // Detects actions with known security vulnerabilities
		NewBotConditionsRule(),                                        // Detects spoofable bot detection conditions
		NewArtipackedRule(),                                           // Detects credential leakage via artifact upload
		NewUnsoundContainsRule(),                                      // Detects bypassable contains() function usage in conditions
		NewSelfHostedRunnersRule(),                                    // Detects self-hosted runner usage which may be dangerous in public repos
		NewArchivedUsesRule(),                                         // Detects usage of archived actions/reusable workflows
		NewUnpinnedImagesRule(),                                       // Detects container images not pinned by SHA256 digest
		NewSecretsInArtifactsRule(),                                   // Detects secrets exposure in artifact uploads (CWE-312)
		NewSecretExfiltrationRule(),                                   // Detects secret exfiltration via network commands
		NewReusableWorkflowTaintRule(filePath, localReusableWorkflow), // Detects untrusted inputs passed to reusable workflows
		NewDangerousTriggersCriticalRule(),                            // Detects dangerous triggers without any mitigations
		NewDangerousTriggersMediumRule(),                              // Detects dangerous triggers with partial mitigations
		NewSecretsInheritRuleWithCache(localReusableWorkflow),         // Detects excessive secret inheritance using 'secrets: inherit'
		ArgumentInjectionCriticalRule(),
		ArgumentInjectionMediumRule(),
	}
}

// ValidateResultは、workflowの検証結果を表す
// この構造体は、Linter.validateメソッドの戻り値として使用される
// FilePathは、検証されたファイルのパス
// Sourceは、検証されたworkflowのソースコード
// ParsedWorkflowは、検証されたworkflowの構文木
// Errorsは、検証中に発生したエラーのリスト
// AutoFixersは、検証中に生成されたAutoFixerのリスト
type ValidateResult struct {
	FilePath       string
	Source         []byte
	ParsedWorkflow *ast.Workflow
	Errors         []*LintingError
	AutoFixers     []AutoFixer
	Repository     string
}

func (l *Linter) validate(
	filePath string,
	content []byte,
	project *Project,
	_ *ConcurrentExecutor, // proc parameter is unused
	localActions *LocalActionsMetadataCache,
	localReusableWorkflow *LocalReusableWorkflowCache,
) (*ValidateResult, error) {
	var validationStart time.Time
	if l.loggingLevel >= LogLevelDetailedOutput {
		validationStart = time.Now()
	}

	l.log("validating workflow...", filePath)
	if project != nil {
		l.log("Detected project:", project.RootDirectory())
	}

	var cfg *Config
	if l.defaultConfiguration != nil {
		cfg = l.defaultConfiguration
	} else if project != nil {
		cfg = project.ProjectConfig()
	}
	if cfg != nil {
		l.debug("setting configuration: %#v", cfg)
	} else {
		l.debug("no configuration file")
	}

	parsedWorkflow, allErrors := Parse(content)

	if l.loggingLevel >= LogLevelDetailedOutput {
		elapsed := time.Since(validationStart)
		l.log("parsed workflow in", len(allErrors), elapsed.Milliseconds(), "ms", filePath)
	}

	var allAutoFixers []AutoFixer

	if parsedWorkflow != nil {
		dbg := l.debugWriter()

		rules := makeRules(filePath, localActions, localReusableWorkflow)

		v := NewSyntaxTreeVisitor()
		for _, rule := range rules {
			v.AddVisitor(rule)
		}

		if dbg != nil {
			v.EnableDebugOutput(dbg)
			for _, rule := range rules {
				rule.EnableDebugOutput(dbg)
			}
		}
		if cfg != nil {
			for _, rule := range rules {
				rule.UpdateConfig(cfg)
			}
		}
		if err := v.VisitTree(parsedWorkflow); err != nil {
			l.debug("error occurred while visiting syntax tree: %v", err)
			return nil, err
		}

		for _, rule := range rules {
			errs := rule.Errors()
			l.debug("%s found %d errors", rule.RuleNames(), len(errs))
			allErrors = append(allErrors, errs...)
			autoFixers := rule.AutoFixers()
			allAutoFixers = append(allAutoFixers, autoFixers...)
		}

		if l.errorFormatter != nil {
			for _, rule := range rules {
				l.errorFormatter.RegisterRule(rule)
			}
		}
	}

	l.filterAndLogErrors(filePath, &allErrors, &allAutoFixers, validationStart)

	return &ValidateResult{
		FilePath:       filePath,
		Source:         content,
		ParsedWorkflow: parsedWorkflow,
		Errors:         allErrors,
		AutoFixers:     allAutoFixers,
	}, nil
}

func (l *Linter) filterAndLogErrors(filePath string, allErrors *[]*LintingError, allAutoFixers *[]AutoFixer, validationStart time.Time) {
	if len(l.errorIgnorePatterns) > 0 {
		filtered := make([]*LintingError, 0, len(*allErrors))
		for _, err := range *allErrors {
			ignored := false
			for _, pattern := range l.errorIgnorePatterns {
				if pattern.MatchString(err.Type) {
					ignored = true
					break
				}
			}
			if !ignored {
				filtered = append(filtered, err)
			}
		}
		*allErrors = filtered
		filteredAutoFixers := make([]AutoFixer, 0, len(*allAutoFixers))
		for _, fixer := range *allAutoFixers {
			ignored := false
			for _, pattern := range l.errorIgnorePatterns {
				if pattern.MatchString(fixer.RuleName()) {
					ignored = true
					break
				}
			}
			if !ignored {
				filteredAutoFixers = append(filteredAutoFixers, fixer)
			}
		}
		*allAutoFixers = filteredAutoFixers
	}
	for _, err := range *allErrors {
		err.FilePath = filePath
	}

	sort.Stable(ByRuleErrorPosition(*allErrors))

	if l.loggingLevel >= LogLevelDetailedOutput {
		elapsed := time.Since(validationStart)
		l.log("Found total", len(*allErrors), "errors found in", elapsed.Milliseconds(), "found in ms", filePath)
	}
}

// displayErrorsは、指定されたエラーを出力する
func (l *Linter) displayErrors(errors []*LintingError, source []byte) {
	for _, err := range errors {
		err.DisplayError(l.errorOutput, source)
	}
}
