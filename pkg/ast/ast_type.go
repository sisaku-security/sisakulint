package ast

import "gopkg.in/yaml.v3"

// Position はファイル内の位置を表します。
type Position struct {
	// Line は位置の行番号です。この値は1から始まります。
	Line int
	// Col は位置の列番号です。この値は1から始まります。
	Col int
}

// String represents generic string value in YAML file with position.
type String struct {
	// Value is a raw value of the string.
	Value string
	// Quoted represents the string is quoted with ' or " in the YAML source.
	Quoted bool
	// Literal represents the string is literal style in the YAML source.
	Literal bool
	// Pos is a position of the string in source.
	Pos *Position

	// BaseNode is a base node of the string in the YAML source.
	BaseNode *yaml.Node
}

// Bool はYAMLファイル内の汎用的な真偽値を位置情報付きで表します。
type Bool struct {
	// Value は真偽値の生の値です。
	Value bool
	// Expression はこのセクションに対して式構文 ${{ }} が使用された場合の文字列です。
	Expression *String
	// Pos はソース内の位置情報です。
	Pos *Position
}

// Int はYAMLファイル内の汎用的な整数値を位置情報付きで表します。
type Int struct {
	// Value は整数値の生の値です。
	Value int
	// Expression はこのセクションに対して式構文 ${{ }} が使用された場合の文字列です。
	Expression *String
	// Pos はソース内の位置情報です。
	Pos *Position
}

// Float はYAMLファイル内の汎用的な浮動小数点数を位置情報付きで表します。
type Float struct {
	// Value は浮動小数点数の生の値です。
	Value float64
	// Expression はこのセクションに対して式構文 ${{ }} が使用された場合の文字列です。
	Expression *String
	// Pos はソース内の位置情報です。
	Pos *Position
}

// Event インターフェースは'on'セクション内のワークフローイベントを表します。
type Event interface {
	// EventName はこのワークフローをトリガーするイベントの名前を返します。
	EventName() string
}

// WebhookEventFilter はWebhookイベントのフィルターを表します。例えば 'branches', 'paths-ignore' などです。
// Webhookイベントはこれらのフィルターによってフィルタリングされます。一部のフィルターは排他的です。
// * https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#using-filters
type WebhookEventFilter struct {
	// Name はフィルターの名前です。例えば 'branches', 'tags' など。
	Name *String
	// Values はフィルター値のリストです。
	Values []*String
}

// WebhookEvent はWebhookイベントに基づくイベントタイプを表します。
// 一部のイベントは'types'フィールドを持つことができません。'push' と 'pull' イベントのみが 'tags', 'tags-ignore',
// 'paths' および 'paths-ignore' フィールドを持つことができます。'workflow_run' イベントのみが 'workflows' フィールドを持つことができます。
// * https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#onevent_nametypes
type WebhookEvent struct {
	// Hook はWebhookイベントの名前です。
	Hook *String
	// Types はWebhookイベントのタイプのリストです。ここに列挙されたタイプのみがワークフローをトリガーします。
	Types []*String
	// Branches は 'branches' フィルターです。省略された場合はnilです。
	Branches *WebhookEventFilter
	// BranchesIgnore は 'branches-ignore' フィルターです。省略された場合はnilです。
	BranchesIgnore *WebhookEventFilter
	// Tags は 'tags' フィルターです。省略された場合はnilです。
	Tags *WebhookEventFilter
	// TagsIgnore は 'tags-ignore' フィルターです。省略された場合はnilです。
	TagsIgnore *WebhookEventFilter
	// Paths は 'paths' フィルターです。省略された場合はnilです。
	Paths *WebhookEventFilter
	// PathsIgnore は 'paths-ignore' フィルターです。省略された場合はnilです。
	PathsIgnore *WebhookEventFilter
	// Workflows は 'workflow_run' イベントによってトリガーされるワークフロー名のリストです。
	Workflows []*String
	// Pos はソース内の位置情報です。
	Pos *Position
}

// ScheduledEvent はワークフローによってスケジュールされたイベントを表します。
// * https://docs.github.com/en/actions/learn-github-actions/events-that-trigger-workflows#scheduled-events
type ScheduledEvent struct {
	// Cron はワークフローをスケジュールするためのcron文字列のリストです。
	Cron []*String
	// Pos はソース内の位置情報です。
	Pos *Position
}

// WorkflowDispatchEventInputType は workflow_dispatch イベントの入力のタイプを表します。
// * https://github.blog/changelog/2021-11-10-github-actions-input-types-for-manual-workflows/
type WorkflowDispatchEventInputType uint8

const (
	// WorkflowDispatchEventInputTypeNone は workflow_dispatch イベントの入力にタイプが指定されていないことを表します。
	WorkflowDispatchEventInputTypeNone WorkflowDispatchEventInputType = iota
	// WorkflowDispatchEventInputTypeString は workflow_dispatch イベントの入力の文字列タイプを表します。
	WorkflowDispatchEventInputTypeString
	// WorkflowDispatchEventInputTypeNumber は workflow_dispatch イベントの入力の数値タイプを表します。
	WorkflowDispatchEventInputTypeNumber
	// WorkflowDispatchEventInputTypeBoolean は workflow_dispatch イベントの入力のブールタイプを表します。
	WorkflowDispatchEventInputTypeBoolean
	// WorkflowDispatchEventInputTypeChoice は workflow_dispatch イベントの入力の選択肢タイプを表します。
	WorkflowDispatchEventInputTypeChoice
	// WorkflowDispatchEventInputTypeEnvironment は workflow_dispatch イベントの入力の環境タイプを表します。
	WorkflowDispatchEventInputTypeEnvironment
)

// DispatchInput はワークフローを手動でディスパッチする際の入力を表します。
// * https://docs.github.com/en/actions/learn-github-actions/events-that-trigger-workflows#workflow_dispatch
type DispatchInput struct {
	// Name はワークフローを手動でディスパッチする際に指定される入力の名前です。
	Name *String
	// Description はワークフローを手動でディスパッチする際に指定される入力の説明です。
	Description *String
	// Required はこの入力がディスパッチ時に必須かどうかを示すフラグです。
	Required *Bool
	// Default はディスパッチ時の入力のデフォルト値です。
	Default *String
	// Type は入力のタイプを表します。
	//* https://docs.github.com/en/actions/learn-github-actions/events-that-trigger-workflows#workflow_dispatch
	Type WorkflowDispatchEventInputType
	// Options は選択肢タイプのオプションのリストです。
	Options []*String
}

// WorkflowDispatchEvent はワークフローを手動でディスパッチするイベントを表します。
// * https://docs.github.com/en/actions/learn-github-actions/events-that-trigger-workflows#workflow_dispatch
type WorkflowDispatchEvent struct {
	// Inputs は入力名から入力属性へのマッピングです。キーは大文字小文字を区別しないため小文字になっています。
	Inputs map[string]*DispatchInput
	// Pos はソース内の位置情報です。
	Pos *Position
}

// RepositoryDispatchEvent は repository_dispatch イベントの設定を表します。
// * https://docs.github.com/en/actions/learn-github-actions/events-that-trigger-workflows#repository_dispatch
type RepositoryDispatchEvent struct {
	// Types はワークフローをトリガーすることができるタイプのリストです。
	Types []*String
	// Pos はソース内の位置情報です。
	Pos *Position
}

// WorkflowCallEventInputType は workflow_call イベントにおける入力のタイプを表します。
type WorkflowCallEventInputType uint8

const (
	// WorkflowCallEventInputTypeInvalid は無効な入力タイプをデフォルト値として表します。
	WorkflowCallEventInputTypeInvalid WorkflowCallEventInputType = iota
	// WorkflowCallEventInputTypeBoolean はブール値の入力タイプを表します。
	WorkflowCallEventInputTypeBoolean
	// WorkflowCallEventInputTypeNumber は数値の入力タイプを表します。
	WorkflowCallEventInputTypeNumber
	// WorkflowCallEventInputTypeString は文字列の入力タイプを表します。
	WorkflowCallEventInputTypeString
)

// WorkflowCallEventInput は workflow_call イベントの入力設定を表します。
// * https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#onworkflow_callinputs
type WorkflowCallEventInput struct {
	// Name は入力の名前です。
	Name *String
	// Description は入力の説明です。
	Description *String
	// Default は入力のデフォルト値です。nil はデフォルト値がないことを意味します。
	Default *String
	// Required は入力が必須かオプションかを表します。この値が nil の場合、明示的に指定されていないと見なされます。
	// その場合、デフォルト値は '必須ではない' となります。
	Required *Bool
	// Type は入力のタイプで、'boolean'、'number'、または 'string' のいずれかでなければなりません。このプロパティは必須です。
	//* https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#onworkflow_callinput_idtype
	Type WorkflowCallEventInputType
	// ID は入力のIDです。入力IDは大文字小文字を区別しないため、小文字になっています。
	ID string
}

// WorkflowCallEventSecret は workflow_call イベントの秘密設定を表します。
// * https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#onworkflow_callsecrets
type WorkflowCallEventSecret struct {
	// Name は秘密の名前です。
	Name *String
	// Description は秘密の説明です。
	Description *String
	// Required は秘密が必須かオプションかを表します。この値が nil の場合、オプションと見なされます。
	//* https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#onworkflow_callsecretssecret_idrequired
	Required *Bool
}

// WorkflowCallEventOutput は workflow_call イベントのアウトプット設定を表します。
// * https://docs.github.com/en/actions/using-workflows/reusing-workflows#using-outputs-from-a-reusable-workflow
type WorkflowCallEventOutput struct {
	// Name はアウトプットの名前です。
	Name *String
	// Description はアウトプットの説明です。
	Description *String
	// Value はアウトプットの値のための式です。
	Value *String
}

// WorkflowCallEvent は workflow_call イベントの設定を表します。
// * https://docs.github.com/en/actions/learn-github-actions/events-that-trigger-workflows#workflow-reuse-events
type WorkflowCallEvent struct {
	// Inputs は workflow_call イベントの入力の配列です。
	// この値は他のフィールドとは異なり、マップではなく配列として設定されています。これは入力のデフォルト値をチェックする際に順序が重要であるためです。
	//* https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#onworkflow_callinputs
	Inputs []*WorkflowCallEventInput
	// Secrets はシークレットの名前からシークレットの設定へのマッピングです。'secrets' が省略された場合、このフィールドには nil が設定されます。
	// キーは大文字小文字を区別しないため、小文字になっています。
	//* https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#onworkflow_callsecrets
	Secrets map[string]*WorkflowCallEventSecret
	// Outputs はアウトプットの名前からアウトプットの設定へのマッピングです。キーは大文字小文字を区別しないため、小文字になっています。
	//* https://docs.github.com/en/actions/using-workflows/reusing-workflows#using-outputs-from-a-reusable-workflow
	Outputs map[string]*WorkflowCallEventOutput
	// Pos はソース内の位置です。
	Pos *Position
}

// PermissionScope はそれぞれのパーミッションスコープ（例: "issues", "checks", ...）のための構造体です。
// * https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token
type PermissionScope struct {
	// Name はスコープの名前です。
	Name *String
	// Value はスコープのパーミッション値です。
	Value *String
}

// Permissions はワークフローファイル内のパーミッション設定のセットです。
// すべてのパーミッションを一度に設定することも、それぞれのパーミッションを個別に設定することもできます。
// * https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#permissions
type Permissions struct {
	// All はすべてのスコープに対する一度に設定されるパーミッション値です。
	All *String
	// Scopes はスコープ名からそのパーミッション設定へのマッピングです。
	Scopes map[string]*PermissionScope
	// Pos はソース内の位置です。
	Pos *Position
}

// DefaultsRun はシェルがどのように実行されるかの設定です。
// * https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#defaultsrun
type DefaultsRun struct {
	// Shell は実行されるシェルの名前です。
	Shell *String
	// WorkingDirectory はデフォルトの作業ディレクトリのパスです。
	WorkingDirectory *String
	// Pos はソース内の位置です。
	Pos *Position
}

// Defaults はシェルを実行するためのデフォルト設定のセットです。
// * https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#defaults
type Defaults struct {
	// Run はシェルを実行する方法の設定です。
	Run *DefaultsRun
	// Pos はソース内の位置です。
	Pos *Position
}

// Concurrency はワークフローの並行実行の設定です。
// * https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#concurrency
type Concurrency struct {
	// Group は並行実行グループの名前です。
	Group *String
	// CancelInProgress はこのワークフローをキャンセルすると進行中の他のジョブもキャンセルされるかどうかを示すフラグです。
	CancelInProgress *Bool
	// Queue は同じグループ内でペンディングになったジョブ/ワークフローの扱い方 ("single" または "max") です。
	// * https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#example-queueing-multiple-pending-runs
	Queue *String
	// Pos はソース内の位置です。
	Pos *Position
}

// ここからjob sectionです。
// todo: jobs.<job_id>.environment
// Environment は環境の設定を表します。
// * https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idenvironment
type Environment struct {
	// Name はワークフローが使用する環境の名前です。
	Name *String
	// URL はデプロイメントAPIの 'environment_url' にマップされるURLです。空の値は何も指定されていないことを意味します。
	URL *String
	// Pos はソース内の位置です。
	Pos *Position
}

// ExecKind はステップがどのように実行されるかの種類を表します。ステップはアクションを実行するか、シェルスクリプトを実行します。
type ExecKind uint8

const (
	// ExecKindAction はステップがアクションを実行するための種類です。
	ExecKindAction ExecKind = iota
	// ExecKindRun はステップがシェルスクリプトを実行するための種類です。
	ExecKindRun
)

// Exec はステップがどのように実行されるかのインターフェースです。ワークフロー内のステップはアクションを実行するか、スクリプトを実行します。
type Exec interface {
	// Kind はステップ実行の種類を返します。
	Kind() ExecKind
}

// ExecRun はステップでシェルスクリプトを実行する方法の設定を表します。
// * https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idstepsrun
type ExecRun struct {
	// Run は実行するスクリプトです。
	Run *String
	// Shell はオプションの 'shell' フィールドを表します。Nilは何も指定されていないことを意味します。
	Shell *String
	// WorkingDirectory はオプションの 'working-directory' フィールドを表します。Nilは何も指定されていないことを意味します。
	WorkingDirectory *String
	// RunPos は 'run' セクションの位置です。
	RunPos *Position
}

// Input はステップで使用される入力の設定を表します。
// * https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idstepswith
type Input struct {
	// Name は入力の名前です。
	Name *String
	// Value は入力の値です。
	Value *String
}

// todo: jobs.<job_id>.steps[*].uses
// ExecAction はステップでアクションを実行する設定を表します。
// uses キーワードを使用してアクションのパスやDockerイメージを指定します。
// また、with キーワードを使用してアクションに渡す入力やパラメータを設定できます。
// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idstepsuses
type ExecAction struct {
	// Uses は実行するアクションのパスやDockerイメージを指定します。
	Uses *String
	// Inputs は 'with' セクションでアクションに渡す入力の設定を表します。キーは大文字小文字を区別しないため小文字で格納されます。
	Inputs map[string]*Input
	//todo: jobs.<job_id>.steps[*].with.entrypoint
	// Entrypoint は 'with' セクションでオプションの 'entrypoint' フィールドを表します。Nilは何も指定されていないことを意味します。
	// 'entrypoint' フィールドはDockerコンテナのエントリポイントをオーバーライドするために使用されます。
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idstepswithentrypoint
	Entrypoint *String
	//todo: jobs.<job_id>.steps[*].with.args
	// Args は 'with' セクションでオプションの 'args' フィールドを表します。Nilは何も指定されていないことを意味します。
	// 'args' フィールドはコンテナに渡される引数を指定するために使用されます。
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idstepswithargs
	Args *String
}

// RawYAMLValueKind は生のYAML値の種類を表します。
type RawYAMLValueKind int

const (
	// RawYAMLValueKindObject は生のYAML値がオブジェクトであることを表します。
	RawYAMLValueKindObject = RawYAMLValueKind(yaml.MappingNode)
	// RawYAMLValueKindArray は生のYAML値が配列であることを表します。
	RawYAMLValueKindArray = RawYAMLValueKind(yaml.SequenceNode)
	// RawYAMLValueKindString は生のYAML値が文字列であることを表します。
	RawYAMLValueKindString = RawYAMLValueKind(yaml.ScalarNode)
)

// RawYAMLValue はマトリックスの変数で使用される値を表します。マッピングや配列を含む任意の値を設定できます。
type RawYAMLValue interface {
	// Kind は生のYAML値の種類を返します。
	Kind() RawYAMLValueKind
	// Equals は他の値と等しいかどうかを返します。
	Equals(other RawYAMLValue) bool
	// Pos はソースファイル内の値の開始位置を返します。
	Pos() *Position
	// String は値の文字列表現を返します。
	String() string
}

// RawYAMLObject は生のYAMLマッピング値を表します。
type RawYAMLObject struct {
	// Props はプロパティ名からその値へのマップです。
	// キーは大文字小文字を区別しないため小文字で格納されます。
	Props map[string]RawYAMLValue
	// Posi はソース内の位置を表します。
	Posi *Position
}

// RawYAMLArray は生のYAML配列値を表します。
type RawYAMLArray struct {
	// Elems は配列値の要素のリストです。
	Elems []RawYAMLValue
	Posi  *Position
}

// RawYAMLString は生のYAMLスカラー値を表します。
type RawYAMLString struct {
	// Value はスカラーノードの文字列表現です。
	Value string
	Posi  *Position
}

// MatrixRow is one row of matrix. One matrix row can take multiple values.
// todo: jobs.<job_id>.strategy.matrix
// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idstrategymatrix
// MatrixRow はマトリックスの値の一行を表します。
type MatrixRow struct {
	// Name はマトリックスの値の名前です。
	Name *String
	// Values はマトリックスの値が取り得るバリエーションの値です。
	Values []RawYAMLValue
	// Expression はこのセクションで ${{ }} の式構文が使用された場合の文字列です。
	Expression *String
}

// MatrixAssign はマトリックスの行で取るべき値を表します。
type MatrixAssign struct {
	// Key はマトリックスの値の名前です。
	Key *String
	// Value は行から選択された値です。
	Value RawYAMLValue
}

// MatrixCombination はマトリックスのバリエーションを定義するためのマトリックス値の割り当ての組み合わせを表します。
type MatrixCombination struct {
	// Assigns はマトリックス値の割り当てのマップです。キーは大文字小文字を区別しないため小文字で格納されます。
	Assigns map[string]*MatrixAssign
	// Expression はこのセクションで ${{ }} の式構文が使用された場合の文字列です。
	Expression *String
}

// MatrixCombinations は 'include' と 'exclude' 用のマトリックス割り当ての組み合わせのリストを表します。
type MatrixCombinations struct {
	// Combinations はマトリックスの組み合わせリストです。
	Combinations []*MatrixCombination
	// Expression はこのセクションで ${{ }} の式構文が使用された場合の文字列です。
	Expression *String
}

// Matrix はジョブのマトリックスバリエーションの設定を表します。
type Matrix struct {
	// Values は名前から値へのマッピングを格納します。キーは大文字小文字を区別しないため小文字で格納されます。
	Rows map[string]*MatrixRow
	// Include はマトリックスの組み合わせを実行する際のマトリックス値と追加値の組み合わせリストです。
	Include *MatrixCombinations
	// Exclude は実行しないマトリックス値の組み合わせリストです。このリストの組み合わせは実行するマトリックスの組み合わせから削除されます。
	Exclude *MatrixCombinations
	// Expression はこのセクションで ${{ }} の式構文が使用された場合の文字列です。
	Expression *String
	// Pos はソース内の位置を表します。
	Pos *Position
}

// todo: jobs.<job_id>.strategy.fail-fast
type Strategy struct {
	// Matrix is matrix of combinations of values. Each combination will run the job once.
	Matrix *Matrix
	// FailFast is flag to show if other jobs should stop when one job fails.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idstrategyfail-fast
	FailFast *Bool
	// MaxParallel is how many jobs should be run at once.
	//todo: jobs.<job_id>.strategy.max-parallel
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idstrategymax-parallel
	MaxParallel *Int
	// Pos is a position in source.
	Pos *Position
}

// EnvVar represents key-value of environment variable setup.
type EnvVar struct {
	// Name is name of the environment variable.
	Name *String
	// Value is string value of the environment variable.
	Value *String
}

// Env represents set of environment variables.
type Env struct {
	// Vars is mapping from env var name to env var value.
	Vars map[string]*EnvVar
	// Expression is an expression string which contains ${{ ... }}. When this value is not empty,
	// Vars should be nil.
	Expression *String
}

// Step is step configuration. Step runs one action or one shell script.
// todo: jobs.<job_id>.steps
// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idsteps
type Step struct {
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idstepsid
	ID *String
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idstepsif
	If *String
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idstepsname
	Name *String
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idstepsrun
	Exec Exec
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idstepsenv
	Env *Env
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idstepscontinue-on-error
	ContinueOnError *Bool
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idstepstimeout-minutes
	TimeoutMinutes *Float
	// Pos is a position in source.
	Pos      *Position
	BaseNode *yaml.Node
}

// todo: jobs.<job_id>.container.credentials
// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idcontainercredentials
type Credentials struct {
	// Username is username for authentication.
	Username *String
	// Password is password for authentication.
	Password *String
	// Pos is a position in source.
	Pos *Position

	BaseNode *yaml.Node
}

// todo: jobs.<job_id>.container
// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idcontainer
type Container struct {
	// Image is specification of Docker image.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idcontainerimage
	Image *String
	// Credentials is credentials configuration of the Docker container.
	Credentials *Credentials
	// Env is environment variables setup in the container.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idcontainerenv
	Env *Env
	// Ports is list of port number mappings of the container.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idcontainerports
	Ports []*String
	// Volumes are list of volumes to be mounted to the container.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idcontainervolumes
	Volumes []*String
	// Options is options string to run the container.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idcontaineroptions
	Options *String
	// Pos is a position in source.
	Pos *Position

	BaseNode *yaml.Node
}

// todo: jobs.<job_id>.services
// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idservices
type Service struct {
	// Name is name of the service.
	Name *String
	// Container is configuration of container which runs the service.
	Container *Container
}

// todo: jobs.<job_id>.outputs
// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idoutputs
type Output struct {
	// Name is name of output.
	Name *String
	// Value is value of output.
	Value *String
}

// todo: jobs.<job_id>.runs-on
// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idruns-on
type Runner struct {
	// Labels is list label names to select a runner to run a job. There are preset labels and user defined labels. Runner matching to the labels is selected.
	Labels []*String
	// LabelsExpr is a string when expression syntax ${{ }} is used for this section. Related issue is #164.
	LabelsExpr *String
	// Group is a group of runners specified in runs-on: section. It is nil when no group is specified.
	// *https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#choosing-runners-in-a-group
	Group *String
}

// WorkflowCallInput is a normal input for workflow call.
type WorkflowCallInput struct {
	// Name is a name of the input.
	Name *String
	// Value is a value of the input.
	Value *String
}

// todo: jobs.<job_id>.with
// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idwith
type WorkflowCallSecret struct {
	// Name is a name of the secret
	Name *String
	// Value is a value of the secret
	Value *String
}

// todo: jobs.<job_id>.uses
// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_iduses
type WorkflowCall struct {
	// Uses is a workflow specification to be called. This field is mandatory.
	Uses *String
	// Inputs is a map from input name to input value at 'with:'. Keys are in lower case since input names are case-insensitive.
	Inputs map[string]*WorkflowCallInput
	// Secrets is a map from secret name to secret value at 'secrets:'. Keys are in lower case since input names are case-insensitive.
	Secrets        map[string]*WorkflowCallSecret
	InheritSecrets bool
}

// todo: jobs
// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobs
type Job struct {
	// ID is an ID of the job, which is key of job configuration objects.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_id
	ID *String
	// Name is a name of job that user can specify freely.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idname
	Name *String
	// Needs is list of job IDs which should be run before running this job.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idneeds
	Needs []*String
	// RunsOn is runner configuration which run the job.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idruns-on
	RunsOn *Runner
	// Permissions is permission configuration for running the job.
	Permissions *Permissions
	// Environment is environment specification where the job runs.
	Environment *Environment
	// Concurrency is concurrency configuration on running the job.
	Concurrency *Concurrency
	// Outputs is map from output name to output specifications.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idoutputs
	Outputs map[string]*Output
	// Env is environment variables setup while running the job.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idenv
	Env *Env
	// Defaults is default configurations of how to run scripts.
	Defaults *Defaults
	// If is a condition whether this job should be run.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idif
	If *String
	// Steps is list of steps to be run in the job.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idsteps
	Steps []*Step
	// TimeoutMinutes is timeout value of running the job in minutes.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes
	TimeoutMinutes *Float
	// Strategy is strategy configuration of running the job.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idstrategy
	Strategy *Strategy
	// ContinueOnError is a flag to show if execution should continue on error.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idcontinue-on-error
	ContinueOnError *Bool
	// Container is container configuration to run the job.
	Container *Container
	// Services is map from service names to service configurations. Keys are in lower case since they are case-insensitive.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idservices
	Services map[string]*Service
	// WorkflowCall is a workflow call by 'uses:'.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_iduses
	WorkflowCall *WorkflowCall
	// Pos is a position in source.
	Pos *Position

	// BaseNode is a base node of the YAML file.
	BaseNode *yaml.Node
}

// Workflow is root of workflow syntax tree, which represents one workflow configuration file.
type Workflow struct {
	// Name is name of the workflow. This field can be nil when user didn't specify the name explicitly.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#name
	Name *String
	// Description is description of the workflow.
	Description *String
	// RunName is the name of workflow runs. This field can be set dynamically using ${{ }}.
	// *https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#run-name
	RunName *String
	// On is list of events which can trigger this workflow.
	On []Event
	// Permissions is configuration of permissions of this workflow.
	Permissions *Permissions
	// Env is a default set of environment variables while running this workflow.
	// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#env
	Env *Env
	// Defaults is default configuration of how to run scripts.
	Defaults *Defaults
	// Concurrency is concurrency configuration of entire workflow. Each jobs also can their own concurrency configurations.
	Concurrency *Concurrency
	// Jobs is mappings from job ID to the job object. Keys are in lower case since they are case-insensitive.
	Jobs map[string]*Job
	// BaseNode is a base node of the YAML file.
	BaseNode *yaml.Node
}
