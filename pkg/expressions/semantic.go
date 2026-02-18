package expressions

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

//todo: Functions, Global variables, Semantics checker, ExprSemanticsChecker, ExprType, UntrustedInputChecker

var reFormatPlaceholder = regexp.MustCompile(`{\d+}`)

func ordinal(i int) string {
	suffix := "th"
	switch i % 10 {
	case 1:
		if i%100 != 11 {
			suffix = "st"
		}
	case 2:
		if i%100 != 12 {
			suffix = "nd"
		}
	case 3:
		if i%100 != 13 {
			suffix = "rd"
		}
	}
	return fmt.Sprintf("%d%s", i, suffix)
}

//todo: Functions

// FuncSignatureは、関数のシグネチャを表す型で、戻り値と引数の型を保持します。
type FuncSignature struct {
	// Nameは関数の名前です。
	Name string
	// Retは関数の戻り値の型です。
	Ret ExprType
	// Paramsは関数のパラメータの型のリストです。このリストの最後の要素は、
	// 可変長引数として複数回（0回を含む）指定される可能性があります。
	Params []ExprType
	// VariableLengthParamsは可変長引数を処理するためのフラグです。このフラグがtrueに設定されている場合、
	// これはParamsの最後の型が複数回指定される可能性があることを意味します（0回を含む）。trueを設定すると、
	// Paramsの長さは0よりも大きいことを意味します。
	VariableLengthParams bool
}

func (sig *FuncSignature) String() string {
	ts := make([]string, 0, len(sig.Params))
	for _, p := range sig.Params {
		ts = append(ts, p.String())
	}
	elip := ""
	if sig.VariableLengthParams {
		elip = "..."
	}
	return fmt.Sprintf("%s(%s%s) -> %s", sig.Name, strings.Join(ts, ", "), elip, sig.Ret.String())
}

// BuiltinFuncSignaturesはすべての組み込み関数のシグネチャのセットです。すべての関数名は
// 大文字小文字を区別せずに比較されるため、すべて小文字で表記されています。
// * https://docs.github.com/en/actions/learn-github-actions/expressions#functions
var BuiltinFuncSignatures = map[string][]*FuncSignature{
	"contains": {
		{
			Name: "contains",
			Ret:  BoolType{},
			Params: []ExprType{
				StringType{},
				StringType{},
			},
		},
		{
			Name: "contains",
			Ret:  BoolType{},
			Params: []ExprType{
				&ArrayType{Elem: UnknownType{}},
				UnknownType{},
			},
		},
	},
	"startswith": {
		{
			Name: "startsWith",
			Ret:  BoolType{},
			Params: []ExprType{
				StringType{},
				StringType{},
			},
		},
	},
	"endswith": {
		{
			Name: "endsWith",
			Ret:  BoolType{},
			Params: []ExprType{
				StringType{},
				StringType{},
			},
		},
	},
	"format": {
		{
			Name: "format",
			Ret:  StringType{},
			Params: []ExprType{
				StringType{},
				UnknownType{}, // variable length
			},
			VariableLengthParams: true,
		},
	},
	"join": {
		{
			Name: "join",
			Ret:  StringType{},
			Params: []ExprType{
				&ArrayType{Elem: StringType{}},
				StringType{},
			},
		},
		{
			Name: "join",
			Ret:  StringType{},
			Params: []ExprType{
				StringType{},
				StringType{},
			},
		},
		{
			Name: "join",
			Ret:  StringType{},
			Params: []ExprType{
				&ArrayType{Elem: StringType{}},
			},
		},
		{
			Name: "join",
			Ret:  StringType{},
			Params: []ExprType{
				StringType{},
			},
		},
	},
	"tojson": {{
		Name: "toJSON",
		Ret:  StringType{},
		Params: []ExprType{
			UnknownType{},
		},
	}},
	"fromjson": {{
		Name: "fromJSON",
		Ret:  UnknownType{},
		Params: []ExprType{
			StringType{},
		},
	}},
	"hashfiles": {{
		Name: "hashFiles",
		Ret:  StringType{},
		Params: []ExprType{
			StringType{},
		},
		VariableLengthParams: true,
	}},
	"success": {{
		Name:   "success",
		Ret:    BoolType{},
		Params: []ExprType{},
	}},
	"always": {{
		Name:   "always",
		Ret:    BoolType{},
		Params: []ExprType{},
	}},
	"canceled": {{
		Name:   "canceled",
		Ret:    BoolType{},
		Params: []ExprType{},
	}},
	// British English spelling alias for canceled function
	// https://docs.github.com/en/actions/learn-github-actions/expressions#status-check-functions
	"cancelled": {{ //nolint:misspell
		Name:   "cancelled", //nolint:misspell
		Ret:    BoolType{},
		Params: []ExprType{},
	}},
	"failure": {{
		Name:   "failure",
		Ret:    BoolType{},
		Params: []ExprType{},
	}},
	// case function for conditional logic (switch-case style)
	// https://github.blog/changelog/2026-01-29-github-actions-smarter-editing-clearer-debugging-and-a-new-case-function/
	// Syntax: case(condition1, value1, condition2, value2, ..., defaultValue)
	// Minimum 3 arguments: condition, valueIfTrue, defaultValue
	"case": {{
		Name: "case",
		Ret:  UnknownType{},
		Params: []ExprType{
			BoolType{},    // first condition
			UnknownType{}, // first value
			UnknownType{}, // default value (also serves as variadic pattern)
		},
		VariableLengthParams: true,
	}},
}

//todo:  Global variables

// BuiltinGlobalVariableTypes でグローバル変数の定義
// * https://docs.github.com/en/actions/learn-github-actions/contexts#github-context
var BuiltinGlobalVariableTypes = map[string]ExprType{
	"github": NewStrictObjectType(map[string]ExprType{
		"action":            StringType{},
		"action_path":       StringType{},
		"action_ref":        StringType{},
		"action_repository": StringType{},
		"action_status":     StringType{},
		"actor":             StringType{},
		"actor_id":          StringType{},
		"api_url":           StringType{},
		"base_ref":          StringType{},
		"env":               StringType{},
		// Note: Stricter type check for this payload would be possible
		"event":               NewEmptyObjectType(),
		"event_name":          StringType{},
		"event_path":          StringType{},
		"graphql_url":         StringType{},
		"head_ref":            StringType{},
		"job":                 StringType{},
		"job_workflow_sha":    StringType{},
		"ref":                 StringType{},
		"ref_name":            StringType{},
		"ref_protected":       StringType{},
		"ref_type":            StringType{},
		"path":                StringType{},
		"repository":          StringType{},
		"repository_id":       StringType{},
		"repository_owner":    StringType{},
		"repository_owner_id": StringType{},
		"repositoryurl":       StringType{}, // repositoryUrl
		"retention_days":      NumberType{},
		"run_id":              StringType{},
		"run_number":          StringType{},
		"run_attempt":         StringType{},
		"server_url":          StringType{},
		"sha":                 StringType{},
		"token":               StringType{},
		"triggering_actor":    StringType{},
		"workflow":            StringType{},
		"workflow_ref":        StringType{},
		"workflow_sha":        StringType{},
		"workspace":           StringType{},
	}),
	//* https://docs.github.com/en/actions/learn-github-actions/contexts#env-context
	"env": NewMapObjectType(StringType{}), // env.<env_name>
	//* https://docs.github.com/en/actions/learn-github-actions/contexts#job-context
	"job": NewStrictObjectType(map[string]ExprType{
		"container": NewStrictObjectType(map[string]ExprType{
			"id":      StringType{},
			"network": StringType{},
		}),
		"services": NewMapObjectType(
			NewStrictObjectType(map[string]ExprType{
				"id":      StringType{}, // job.services.<service id>.id
				"network": StringType{},
				"ports":   NewMapObjectType(StringType{}),
			}),
		),
		"status": StringType{},
	}),
	//* https://docs.github.com/en/actions/learn-github-actions/contexts#steps-context
	"steps": NewEmptyStrictObjectType(), // This value will be updated contextually
	//* https://docs.github.com/en/actions/learn-github-actions/contexts#runner-context
	"runner": NewStrictObjectType(map[string]ExprType{
		"name":       StringType{},
		"os":         StringType{},
		"arch":       StringType{},
		"temp":       StringType{},
		"tool_cache": StringType{},
		"debug":      StringType{},
	}),
	//* https://docs.github.com/en/actions/learn-github-actions/contexts#secrets-context
	"secrets": NewMapObjectType(StringType{}),
	//* https://docs.github.com/en/actions/learn-github-actions/contexts#strategy-context
	"strategy": NewObjectType(map[string]ExprType{
		"fail-fast":    BoolType{},
		"job-index":    NumberType{},
		"job-total":    NumberType{},
		"max-parallel": NumberType{},
	}),
	//* https://docs.github.com/en/actions/learn-github-actions/contexts#matrix-context
	"matrix": NewEmptyStrictObjectType(), // This value will be updated contextually
	//* https://docs.github.com/en/actions/learn-github-actions/contexts#needs-context
	"needs": NewEmptyStrictObjectType(), // This value will be updated contextually
	//* https://docs.github.com/en/actions/learn-github-actions/contexts#inputs-context
	//* https://docs.github.com/en/actions/learn-github-actions/reusing-workflows
	"inputs": NewEmptyStrictObjectType(),
	//* https://docs.github.com/en/actions/learn-github-actions/contexts#vars-context
	"vars": NewMapObjectType(StringType{}), // vars.<var_name>
}

//todo:  Semantics checker

// ExprSemanticsCheckerは式構文の意味チェックを行うものです。与えられた式構文ツリー内の値の型をチェックします。
// さらに、format() 組み込み関数の引数など、その他の意味論的なチェックも行います。構文の詳細については、以下のリンクを参照してください。
// * https://docs.github.com/en/actions/learn-github-actions/contexts
// * https://docs.github.com/en/actions/learn-github-actions/expressions
type ExprSemanticsChecker struct {
	funcs                 map[string][]*FuncSignature
	vars                  map[string]ExprType
	errs                  []*ExprError
	varsCopied            bool
	githubVarCopied       bool
	untrusted             *UntiChecker
	availableContexts     []string
	availableSpecialFuncs []string
	configVars            []string
}

// NewExprSemanticsCheckerは新しいExprSemanticsCheckerインスタンスを作成します。checkUntrustedInputが
// trueに設定されている場合、このチェッカーは可能性のある信頼性のない入力を使用してエラーを生成します。
func NewExprSemanticsChecker(checkUntrustedInput bool, configVars []string) *ExprSemanticsChecker {
	c := &ExprSemanticsChecker{
		funcs:           BuiltinFuncSignatures,
		vars:            BuiltinGlobalVariableTypes,
		varsCopied:      false,
		githubVarCopied: false,
		configVars:      configVars,
	}
	if checkUntrustedInput {
		c.untrusted = NewUntiChecker(BuiltinUntrustedInputs)
	}
	return c
}

func errorAtExpr(e ExprNode, msg string) *ExprError {
	t := e.Token()
	return &ExprError{
		Message: msg,
		Offset:  t.Offset,
		Line:    t.Line,
		Column:  t.Column,
	}
}

func errorfAtExpr(e ExprNode, format string, args ...interface{}) *ExprError {
	return errorAtExpr(e, fmt.Sprintf(format, args...))
}

func (sema *ExprSemanticsChecker) errorf(e ExprNode, format string, args ...interface{}) {
	sema.errs = append(sema.errs, errorfAtExpr(e, format, args...))
}

func (sema *ExprSemanticsChecker) ensureVarsCopied() {
	if sema.varsCopied {
		return
	}

	// Make shallow copy of current variables map not to pollute global variable
	copied := make(map[string]ExprType, len(sema.vars))
	for k, v := range sema.vars {
		copied[k] = v
	}
	sema.vars = copied
	sema.varsCopied = true
}

func (sema *ExprSemanticsChecker) ensureGithubVarCopied() {
	if sema.githubVarCopied {
		return
	}
	sema.ensureVarsCopied()

	sema.vars["github"] = sema.vars["github"].DeepCopy()
}

// UpdateMatrixは与えられたオブジェクト型に対してマトリックスオブジェクトを更新します。
// マトリックスの値はジョブ構成の 'matrix' セクションに従って変更されるため、型を更新する必要があります。
func (sema *ExprSemanticsChecker) UpdateMatrix(ty *ObjectType) {
	sema.ensureVarsCopied()
	sema.vars["matrix"] = ty
}

// UpdateSteps updates 'steps' context object to given object type.
func (sema *ExprSemanticsChecker) UpdateSteps(ty *ObjectType) {
	sema.ensureVarsCopied()
	sema.vars["steps"] = ty
}

// UpdateNeeds updates 'needs' context object to given object type.
func (sema *ExprSemanticsChecker) UpdateNeeds(ty *ObjectType) {
	sema.ensureVarsCopied()
	sema.vars["needs"] = ty
}

// UpdateSecrets updates 'secrets' context object to given object type.
func (sema *ExprSemanticsChecker) UpdateSecrets(ty *ObjectType) {
	sema.ensureVarsCopied()

	// 自動的に提供されたシークレットと手動で定義されたシークレットをマージします。
	// ACTIONS_STEP_DEBUG と ACTIONS_RUNNER_DEBUG は、ワークフローの呼び出し元から提供される（#130）。
	copied := NewStrictObjectType(map[string]ExprType{
		"github_token":         StringType{},
		"actions_step_debug":   StringType{},
		"actions_runner_debug": StringType{},
	})
	for n, v := range ty.Props {
		copied.Props[n] = v
	}
	sema.vars["secrets"] = copied
}

// UpdateInputs updates 'inputs' context object to given object type.
func (sema *ExprSemanticsChecker) UpdateInputs(ty *ObjectType) {
	sema.ensureVarsCopied()
	o := sema.vars["inputs"].(*ObjectType)
	if len(o.Props) == 0 && o.IsStrict() {
		sema.vars["inputs"] = ty
		return
	}
	// `workflow_call` と `workflow_dispatch` の両方がワークフローのトリガーとして使用される場合、`inputs` コンテキストは
	// 両方のイベントで使用できます。両方のケースをカバーするために、`inputs` コンテキストを1つのオブジェクト型にマージします（#263）。
	sema.vars["inputs"] = o.Merge(ty)
}

// UpdateDispatchInputs updates 'github.event.inputs' and 'inputs' objects to given object type.
// * https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#workflow_dispatch
func (sema *ExprSemanticsChecker) UpdateDispatchInputs(ty *ObjectType) {
	sema.UpdateInputs(ty)

	// `github.event.inputs` を更新します。
	// `inputs.*` とは異なり、`github.event.inputs.*` の型は常に文字列であるため、
	// `ty` から新しい型を作成する必要があります（例：{foo: boolean, bar: number} -> {foo: string, bar: string}）。

	p := make(map[string]ExprType, len(ty.Props))
	for n := range ty.Props {
		p[n] = StringType{}
	}
	ty = NewStrictObjectType(p)

	sema.ensureGithubVarCopied()
	sema.vars["github"].(*ObjectType).Props["event"].(*ObjectType).Props["inputs"] = ty
}

// UpdateJobs updates 'jobs' context object to given object type.
func (sema *ExprSemanticsChecker) UpdateJobs(ty *ObjectType) {
	sema.ensureVarsCopied()
	sema.vars["jobs"] = ty
}

// SetContextAvailabilityは、セマンティクスチェック時に利用可能なコンテキスト名を設定します。
// 一部のコンテキストは、使用できる場所に制限があることがあります。
// * https://docs.github.com/en/actions/learn-github-actions/contexts#context-availability
// 'avail'パラメータの要素は、大文字小文字を区別せずにコンテキスト名をチェックするために小文字である必要があります。
// このメソッドがチェック前に呼び出されない場合、ExprSemanticsCheckerはデフォルトで任意のコンテキストが利用可能であると考えます。
// ワークフローのキーに対する利用可能なコンテキストは sisakulint.ContextAvailabilityから取得できます。
func (sema *ExprSemanticsChecker) SetContextAvailability(avail []string) {
	sema.availableContexts = avail
}

func (sema *ExprSemanticsChecker) checkAvailableContext(n *VariableNode) {
	if len(sema.availableContexts) == 0 {
		return
	}

	ctx := strings.ToLower(n.Name)
	for _, c := range sema.availableContexts {
		if c == ctx {
			return
		}
	}

	s := "contexts are"
	if len(sema.availableContexts) == 1 {
		s = "context is"
	}
	sema.errorf(
		n,
		"context %q is not allowed here. Available contexts are %s and %s. For more details, please visit: https://docs.github.com/en/actions/learn-github-actions/contexts#context-availability",
		n.Name,
		s,
		quotes(sema.availableContexts),
	)
}

// SetSpecialFunctionAvailabilityはセマンティクスチェック時の利用可能な特別な関数の名前を設定します。
// 一部の関数は使用できる場所に制限があります。
// 'avail' パラメータの要素は、大文字小文字を区別せずに関数名を確認するために小文字である必要があります。
// このメソッドがチェック前に呼び出されない場合、ExprSemanticsCheckerはデフォルトで特別な関数を許可しないものと見なします。
// todo:  関数名は sisakulint.SpecialFunctionNames のグローバル定数から取得できます。
func (sema *ExprSemanticsChecker) SetSpecialFunctionAvailability(avail []string) {
	sema.availableSpecialFuncs = avail
}

func (sema *ExprSemanticsChecker) checkSpecialFunctionAvailability(n *FuncCallNode) {
	f := strings.ToLower(n.Callee)
	// SpecialFunctionNames は、特別な関数名から利用可能なワークフロー キーへのマップです。
	// 一部の関数は特定の位置でのみ使用できます。 この変数は、次のような場合に役立ちます。
	// どの関数が特別で、どのワークフロー キーがそれらをサポートしているかを把握します。
	//* https://docs.github.com/en/actions/learn-github-actions/contexts#context-availability
	var SpecialFunctionNames = map[string][]string{
		"always":    {"jobs.<job_id>.if", "jobs.<job_id>.steps.if"},
		"canceled":  {"jobs.<job_id>.if", "jobs.<job_id>.steps.if"},
		"cancelled": {"jobs.<job_id>.if", "jobs.<job_id>.steps.if"}, //nolint:misspell
		"failure":   {"jobs.<job_id>.if", "jobs.<job_id>.steps.if"},
		"hashfiles": {"jobs.<job_id>.steps.continue-on-error",
			"jobs.<job_id>.steps.env", "jobs.<job_id>.steps.if",
			"jobs.<job_id>.steps.name", "jobs.<job_id>.steps.run",
			"jobs.<job_id>.steps.timeout-minutes", "jobs.<job_id>.steps.with",
			"jobs.<job_id>.steps.working-directory"},
		"success": {"jobs.<job_id>.if", "jobs.<job_id>.steps.if"},
	}
	// WorkflowKeyAvailability returns availability of given workflow key context and special functions.

	allowed, ok := SpecialFunctionNames[f]
	if !ok {
		return
	}
	for _, sp := range sema.availableSpecialFuncs {
		if sp == f {
			return
		}
	}
	sema.errorf(
		n,
		"function %q is not allowed here. Available functions are %q in %s. For more details, please visit: https://docs.github.com/en/actions/learn-github-actions/contexts#context-availability",
		n.Callee,
		n.Callee,
		quotes(allowed),
	)
}

func (sema *ExprSemanticsChecker) visitUntrustedCheckerOnEnterNode(n ExprNode) {
	if sema.untrusted != nil {
		sema.untrusted.OnVisitNodeEnter(n)
	}
}

func (sema *ExprSemanticsChecker) visitUntrustedCheckerOnLeaveNode(n ExprNode) {
	if sema.untrusted != nil {
		sema.untrusted.OnVisitNodeLeave(n)
	}
}

func (sema *ExprSemanticsChecker) checkVariable(n *VariableNode) ExprType {
	v, ok := sema.vars[n.Name]
	if !ok {
		ss := make([]string, 0, len(sema.vars))
		for n := range sema.vars {
			ss = append(ss, n)
		}
		sema.errorf(n, "undefined variable %q. available variables are %s", n.Token().Value, SortedQuotes(ss))
		return UnknownType{}
	}

	sema.checkAvailableContext(n)
	return v
}

func (sema *ExprSemanticsChecker) checkObjectDeref(n *ObjectDerefNode) ExprType {
	switch ty := sema.check(n.Receiver).(type) {
	case UnknownType:
		return UnknownType{}
	case *ObjectType:
		if t, ok := ty.Props[n.Property]; ok {
			return t
		}
		if ty.Mapped != nil {
			if v, ok := n.Receiver.(*VariableNode); ok && v.Name == "vars" {
				sema.checkConfigVariables(n)
			}
			return ty.Mapped
		}
		/* if ty.IsStrict() {
			sema.errorf(n, "property %q is not defined in object type %s", n.Property, ty.String())
		} */
		return UnknownType{}
	case *ArrayType:
		if !ty.Deref {
			sema.errorf(n, "The receiver of object dereference %q must have a type of 'object', but it has a type of %q", n.Property, ty.String())
			return UnknownType{}
		}
		switch et := ty.Elem.(type) {
		case UnknownType:
			// When element type is any, map the any type to any. Reuse `ty`
			return ty
		case *ObjectType:
			// Map element type of delererenced array
			var elem ExprType = UnknownType{}
			if t, ok := et.Props[n.Property]; ok {
				elem = t
			} else if et.Mapped != nil {
				elem = et.Mapped
			} else if et.IsStrict() {
				sema.errorf(n, "property %q is not defined in the object %s type as an element of a filtered array", n.Property, et.String())
			}
			return &ArrayType{elem, true}
		default:
			sema.errorf(
				n,
				"The property filtered by %q during object filtering, must have a type of 'object', but it has a type of %q",
				n.Property,
				ty.Elem.String(),
			)
			return UnknownType{}
		}
	default:
		sema.errorf(n, "The receiver for object dereference of %q must have a type of 'object', but it has a type of %q", n.Property, ty.String())
		return UnknownType{}
	}
}

func (sema *ExprSemanticsChecker) checkConfigVariables(n *ObjectDerefNode) {
	//*  https://docs.github.com/en/actions/learn-github-actions/variables#naming-conventions-for-configuration-variables
	if strings.HasPrefix(n.Property, "github_") {
		sema.errorf(
			n,
			"The configuration variable name %q should not start with the 'GITHUB_' prefix (case insensitive). Please refer to the naming conventions at https://docs.github.com/en/actions/learn-github-actions/variables#naming-conventions-for-configuration-variables for more information.",
			n.Property,
		)
		return
	}
	for _, r := range n.Property {
		// Note: `n.Property` was already converted to lower case by parser
		// Note: First character cannot be number, but it was already checked by parser
		if '0' <= r && r <= '9' || 'a' <= r && r <= 'z' || r == '_' {
			continue
		}
		sema.errorf(
			n,
			"The configuration variable name %q can only contain alphabets, decimal numbers, and underscores '_'. Please refer to the naming conventions at https://docs.github.com/en/actions/learn-github-actions/variables#naming-conventions-for-configuration-variables for more information.",
			n.Property,
		)
		return
	}

	if sema.configVars == nil {
		return
	}
	if len(sema.configVars) == 0 {
		sema.errorf(
			n,
			"No configuration variables are allowed because the variables list is empty in action.yaml. You may have forgotten to add the variable %q to the list.",
			n.Property,
		)
		return
	}

	for _, v := range sema.configVars {
		if strings.EqualFold(v, n.Property) {
			return
		}
	}

	sema.errorf(
		n,
		"The configuration variable %q is undefined. The defined configuration variables in action.yaml are: %s",
		n.Property,
		SortedQuotes(sema.configVars),
	)
}

func (sema *ExprSemanticsChecker) checkArrayDeref(n *ArrayDerefNode) ExprType {
	switch ty := sema.check(n.Receiver).(type) {
	case UnknownType:
		return &ArrayType{UnknownType{}, true}
	case *ArrayType:
		ty.Deref = true
		return ty
	case *ObjectType:
		// Object filtering is available for objects, not only arrays (#66)

		if ty.Mapped != nil {
			// For map object or loose object at receiver of .*
			switch mty := ty.Mapped.(type) {
			case UnknownType:
				return &ArrayType{UnknownType{}, true}
			case *ObjectType:
				return &ArrayType{mty, true}
			default:
				sema.errorf(n, "elements of object at receiver of object filtering `.*` must be type of object but got %q. the type of receiver was %q", mty.String(), ty.String())
				return UnknownType{}
			}
		}

		// For strict object at receiver of .*
		found := false
		for _, t := range ty.Props {
			if _, ok := t.(*ObjectType); ok {
				found = true
				break
			}
		}
		if !found {
			sema.errorf(n, "object type %q cannot be filtered by object filtering `.*` since it has no object element", ty.String())
			return UnknownType{}
		}

		return &ArrayType{UnknownType{}, true}
	default:
		sema.errorf(n, "receiver of object filtering `.*` must be type of array or object but got %q", ty.String())
		return UnknownType{}
	}
}

func (sema *ExprSemanticsChecker) checkIndexAccess(n *IndexAccessNode) ExprType {
	// UntrustedInputCheckerが正しく機能するためには、インデックスはオペランドよりも前に訪問する必要があります。
	// たとえば、foo[aaa.bbb].bar のようなネストが式内にある場合でも、ネストはトップダウンの順序で発生します。
	// プロパティ/インデックスのアクセスチェックはボトムアップの順序で行われます。
	// したがって、ネストしたindex nodeをオペランドの前に訪問する限り、インデックスは再帰的に最初にチェックされます。

	idx := sema.check(n.Index)

	switch ty := sema.check(n.Operand).(type) {
	case UnknownType:
		return UnknownType{}
	case *ArrayType:
		switch idx.(type) {
		case UnknownType, NumberType:
			return ty.Elem
		default:
			sema.errorf(n.Index, "index access of array must be type of number but got %q", idx.String())
			return UnknownType{}
		}
	case *ObjectType:
		switch idx.(type) {
		case UnknownType:
			return UnknownType{}
		case StringType:
			// Index access with string literal like foo['bar']
			if lit, ok := n.Index.(*StringNode); ok {
				if prop, ok := ty.Props[lit.Value]; ok {
					return prop
				}
				if ty.Mapped != nil {
					return ty.Mapped
				}
				/* if ty.IsStrict() {
					sema.errorf(n, "property %q is not defined in object type %s", lit.Value, ty.String())
				} */
			}
			if ty.Mapped != nil {
				return ty.Mapped
			}
			return UnknownType{} // Fallback
		default:
			sema.errorf(n.Index, "property access of object must be type of string but got %q", idx.String())
			return UnknownType{}
		}
	default:
		sema.errorf(n, "index access operand must be type of object or array but got %q", ty.String())
		return UnknownType{}
	}
}

func checkFuncSignature(n *FuncCallNode, sig *FuncSignature, args []ExprType) *ExprError {
	lp, la := len(sig.Params), len(args)
	if sig.VariableLengthParams && (lp > la) || !sig.VariableLengthParams && lp != la {
		atLeast := ""
		if sig.VariableLengthParams {
			atLeast = "at least "
		}
		return errorfAtExpr(
			n,
			"number of arguments is wrong. function %q takes %s %d parameters but %d arguments are given",
			sig.String(),
			atLeast,
			lp,
			la,
		)
	}

	for i := 0; i < len(sig.Params); i++ {
		p, a := sig.Params[i], args[i]
		if !p.Assignable(a) {
			return errorfAtExpr(
				n.Args[i],
				"%s argument of function call is not assignable. %q cannot be assigned to %q. called function type is %q",
				ordinal(i+1),
				a.String(),
				p.String(),
				sig.String(),
			)
		}
	}

	//goではこのチェックでは可変長パラメータのための0引数は許可されません。
	//これは hashFiles() と format() のチェックに役立つためです。
	if sig.VariableLengthParams {
		rest := args[lp:]
		p := sig.Params[lp-1]
		for i, a := range rest {
			if !p.Assignable(a) {
				return errorfAtExpr(
					n.Args[lp+i],
					"%s argument of function call is not assignable. %q cannot be assigned to %q. called function type is %q",
					ordinal(lp+i+1),
					a.String(),
					p.String(),
					sig.String(),
				)
			}
		}
	}

	return nil
}

func (sema *ExprSemanticsChecker) checkBuiltinFunctionCall(n *FuncCallNode, sig *FuncSignature) {
	sema.checkSpecialFunctionAvailability(n)
	// Special checks for specific built-in functions
	switch n.Callee {
	case "format":
		lit, ok := n.Args[0].(*StringNode)
		if !ok {
			return
		}
		l := len(n.Args) - 1 // -1 means removing first format string argument

		// Find all placeholders in format string
		holders := make(map[int]struct{}, l)
		for _, m := range reFormatPlaceholder.FindAllString(lit.Value, -1) {
			i, _ := strconv.Atoi(m[1 : len(m)-1])
			holders[i] = struct{}{}
		}

		for i := 0; i < l; i++ {
			_, ok := holders[i]
			if !ok {
				sema.errorf(n, "The format string %q does not contain the placeholder {%d}. Please remove the argument that is unused in the format string.", lit.Value, i)
				continue
			}
			delete(holders, i) // forget it to check unused placeholders
		}

		for i := range holders {
			sema.errorf(n, "The format string %q contains the placeholder {%d}, but only %d argument(s) are provided for formatting. Please make sure the number of arguments matches the placeholders in the format string.",
				lit.Value, i, l)
		}
	case "case":
		// The runner enforces an odd argument count at parse time (EvenParameters error).
		// Syntax: case(pred1, val1, pred2, val2, ..., default) — pairs plus one default.
		// See: https://github.com/actions/runner/blob/main/src/Sdk/Expressions/ExpressionParser.cs
		if len(n.Args)%2 == 0 {
			sema.errorf(n, "case() requires an odd number of arguments (predicate-value pairs plus a default), but %d arguments were given", len(n.Args))
		}
	}
}

func (sema *ExprSemanticsChecker) checkFuncCall(n *FuncCallNode) ExprType {
	// Check function name in case insensitive. For example, toJson and toJSON are the same function.
	callee := strings.ToLower(n.Callee)
	sigs, ok := sema.funcs[callee]
	if !ok {
		ss := make([]string, 0, len(sema.funcs))
		for n := range sema.funcs {
			ss = append(ss, n)
		}
		sema.errorf(n, "undefined function %q. available functions are %s", n.Callee, SortedQuotes(ss))
		return UnknownType{}
	}

	tys := make([]ExprType, 0, len(n.Args))
	for _, a := range n.Args {
		tys = append(tys, sema.check(a))
	}

	// Check all overloads
	errs := []*ExprError{}
	for _, sig := range sigs {
		err := checkFuncSignature(n, sig, tys)
		if err == nil {
			// When one of overload pass type check, overload was resolved correctly
			sema.checkBuiltinFunctionCall(n, sig)
			return sig.Ret
		}
		errs = append(errs, err)
	}
	sema.errs = append(sema.errs, errs...)

	return UnknownType{}
}

func (sema *ExprSemanticsChecker) checkNotOp(n *NotOpNode) ExprType {
	ty := sema.check(n.Operand)
	if !(BoolType{}).Assignable(ty) {
		sema.errorf(n, "The type of the operand for the '!' operator, %q, is not assignable to the 'bool' type.", ty.String())
	}
	return BoolType{}
}

func (sema *ExprSemanticsChecker) checkCompareOp(n *CompareOpNode) ExprType {
	sema.check(n.Left)
	sema.check(n.Right)
	//* https://docs.github.com/en/actions/learn-github-actions/expressions#operators
	return BoolType{}
}

func (sema *ExprSemanticsChecker) checkLogicalOp(n *LogicalOpNode) ExprType {
	lty := sema.check(n.Left)
	rty := sema.check(n.Right)
	return lty.Merge(rty)
}

func (sema *ExprSemanticsChecker) check(expr ExprNode) ExprType {
	sema.visitUntrustedCheckerOnEnterNode(expr)       // Call this method in top-down order
	defer sema.visitUntrustedCheckerOnLeaveNode(expr) // Call this method in bottom-up order

	switch e := expr.(type) {
	case *VariableNode:
		return sema.checkVariable(e)
	case *NullNode:
		return NullType{}
	case *BoolNode:
		return BoolType{}
	case *StringNode:
		return StringType{}
	case *IntNode, *FloatNode:
		return NumberType{}
	case *ObjectDerefNode:
		return sema.checkObjectDeref(e)
	case *ArrayDerefNode:
		return sema.checkArrayDeref(e)
	case *IndexAccessNode:
		return sema.checkIndexAccess(e)
	case *FuncCallNode:
		return sema.checkFuncCall(e)
	case *NotOpNode:
		return sema.checkNotOp(e)
	case *CompareOpNode:
		return sema.checkCompareOp(e)
	case *LogicalOpNode:
		return sema.checkLogicalOp(e)
	default:
		panic("unreachable")
	}
}

// Checkは与えられた式構文木のsemanticをチェックします。チェックが正常に完了した場合、
// 最初の戻り値として式の型を返し、式のチェック中に発生したすべてのエラーを2番目の戻り値として返します。
func (sema *ExprSemanticsChecker) Check(expr ExprNode) (ExprType, []*ExprError) {
	sema.errs = []*ExprError{}
	if sema.untrusted != nil {
		sema.untrusted.Init()
	}
	ty := sema.check(expr)
	errs := sema.errs
	if sema.untrusted != nil {
		sema.untrusted.OnVisitEnd()
		errs = append(errs, sema.untrusted.Errs()...)
	}
	return ty, errs
}
