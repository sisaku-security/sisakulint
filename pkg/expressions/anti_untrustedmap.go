package expressions

import (
	"strings"
)

// ContextPropertyMap はコンテキストオブジェクトのプロパティ参照をマッチするための再帰的なマップです。
// ContextPropertyMap はuntrusted inputのチェッカーの検索ツリーのノードとして使用されます。
// このマップのルートは各コンテキスト名を表し、その親は再帰的なプロパティを表します。
type ContextPropertyMap struct {
	Name     string
	Parent   *ContextPropertyMap
	Children map[string]*ContextPropertyMap
}

func (m *ContextPropertyMap) String() string {
	var b strings.Builder
	m.buildPath(&b)
	return b.String()
}

// このマップで子オブジェクトのプロパティを検索します。
func (m *ContextPropertyMap) findObjectProp(name string) (*ContextPropertyMap, bool) {
	if m != nil && m.Children != nil {
		if c, ok := m.Children[name]; ok {
			return c, true
		}
	}
	return nil, false
}

// 子の配列要素を検索します。これは、受信者が配列であるオブジェクトフィルタの特別なケースです。
func (m *ContextPropertyMap) findArrayElem() (*ContextPropertyMap, bool) {
	return m.findObjectProp("*")
}

// 親をたどって `github.event.commits.*.body` のようなパスを構築します。
func (m *ContextPropertyMap) buildPath(b *strings.Builder) {
	if m.Parent != nil && m.Parent.Name != "" {
		m.Parent.buildPath(b)
		b.WriteRune('.')
	}
	b.WriteString(m.Name)
}

// NewContextPropertyMap は新しいContextPropertyMapのインスタンスを作成します。
func NewContextPropertyMap(name string, children ...*ContextPropertyMap) *ContextPropertyMap {
	m := &ContextPropertyMap{
		Name:     name,
		Parent:   nil,
		Children: nil, // cheldren は nil で初期化します。
	}
	if len(children) > 0 {
		m.Children = make(map[string]*ContextPropertyMap, len(children))
		for _, c := range children {
			c.Parent = m
			m.Children[c.Name] = c
		}
	}
	return m
}

// ContextPropertySearchRoots は信用できない入力のリストです。
// 例えば    1.ネストされたオブジェクトプロパティアクセス、
//
//	2.配列インデックスアクセス、
//	3.オブジェクトフィルタでuntrusted inputアクセス
//
// などなどを効果的に検出するためのツリー構造を形成します。
// このマップの各値は検索のルートを表すため、それらの名前はコンテキストの名前です。
type ContextPropertySearchRoots map[string]*ContextPropertyMap

// AddRoot は信用できない入力を検出するための新しいルートを検索に追加します。
func (ms ContextPropertySearchRoots) AddRoot(m *ContextPropertyMap) {
	ms[m.Name] = m
}

// BuiltinUntrustedInputs は untrusted inputsのリストです。
// これらの入力は `run:` スクリプトで""untrusted!""として検出されます。
//* https://securitylab.github.com/research/github-actions-untrusted-input/
//* https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
//* https://github.com/github/codeql/blob/main/javascript/ql/src/experimental/Security/CWE-094/examples/pull_request_target_bad.yml
/*
github.event.issue.title
github.event.issue.body
github.event.pull_request.title
github.event.pull_request.body
github.event.comment.body
github.event.review.body
github.event.pages.*.page_name
github.event.commits.*.message
github.event.head_commit.message
github.event.head_commit.author.email
github.event.head_commit.author.name
github.event.commits.*.author.email
github.event.commits.*.author.name
github.event.pull_request.head.ref
github.event.pull_request.head.label
github.event.pull_request.head.repo.default_branch
github.head_ref
*/
var BuiltinUntrustedInputs = ContextPropertySearchRoots{
	//todo: github.event.issue.title , github.event.issue.body
	"github": NewContextPropertyMap("github",
		NewContextPropertyMap("event",
			NewContextPropertyMap("issue",
				NewContextPropertyMap("title"),
				NewContextPropertyMap("body"),
			),
			//todo: github.event.pull_request.title , github.event.pull_request.body
			NewContextPropertyMap("pull_request",
				NewContextPropertyMap("title"),
				NewContextPropertyMap("body"),
				NewContextPropertyMap("head",
					NewContextPropertyMap("ref"),
					NewContextPropertyMap("label"),
					NewContextPropertyMap("sha"),
					NewContextPropertyMap("repo",
						NewContextPropertyMap("default_branch"),
					),
				),
			),
			//todo: github.event.comment.body
			NewContextPropertyMap("comment",
				NewContextPropertyMap("body"),
			),
			//todo: github.event.review.body
			NewContextPropertyMap("review",
				NewContextPropertyMap("body"),
			),
			//todo: github.event.pages.*.page_name
			NewContextPropertyMap("review_comment",
				NewContextPropertyMap("body"),
			),
			NewContextPropertyMap("pages",
				NewContextPropertyMap("*",
					NewContextPropertyMap("page_name"),
				),
			),
			//todo: github.event.commits.*.message
			NewContextPropertyMap("commits",
				NewContextPropertyMap("*",
					NewContextPropertyMap("message"),
					NewContextPropertyMap("author",
						NewContextPropertyMap("email"),
						NewContextPropertyMap("name"),
					),
				),
			),
			//todo: github.event.head_commit.message , github.event.head_commit.author.email , github.event.head_commit.author.name
			NewContextPropertyMap("head_commit",
				NewContextPropertyMap("message"),
				NewContextPropertyMap("author",
					NewContextPropertyMap("email"),
					NewContextPropertyMap("name"),
				),
			),
			//todo: github.event.discussion.title , github.event.discussion.body
			NewContextPropertyMap("discussion",
				NewContextPropertyMap("title"),
				NewContextPropertyMap("body"),
			),
		),
		//todo: github.head_ref
		NewContextPropertyMap("head_ref"),
	),
}

// CreateUntrustedInputsWithTaintedReusableWorkflowInputs creates a new ContextPropertySearchRoots
// that includes the standard untrusted inputs plus tainted inputs from reusable workflows.
// This should be used when checking a reusable workflow that may receive untrusted data
// through its inputs.
//
// taintedInputNames is a list of input names that are known to be tainted
// (i.e., they receive untrusted data from the caller workflow)
func CreateUntrustedInputsWithTaintedReusableWorkflowInputs(taintedInputNames []string) ContextPropertySearchRoots {
	// Create a copy of the builtin untrusted inputs
	roots := make(ContextPropertySearchRoots, len(BuiltinUntrustedInputs)+1)
	for k, v := range BuiltinUntrustedInputs {
		roots[k] = v
	}

	// Add inputs.* for tainted input names
	if len(taintedInputNames) > 0 {
		inputChildren := make([]*ContextPropertyMap, len(taintedInputNames))
		for i, name := range taintedInputNames {
			inputChildren[i] = NewContextPropertyMap(name)
		}
		roots["inputs"] = NewContextPropertyMap("inputs", inputChildren...)
	}

	return roots
}

// CreateUntrustedInputsForReusableWorkflow creates untrusted inputs that treat ALL inputs.*
// as potentially tainted. This is a conservative approach used when the caller's
// input values are not known at analysis time.
//
// inputNames is a list of all input names defined in the reusable workflow
func CreateUntrustedInputsForReusableWorkflow(inputNames []string) ContextPropertySearchRoots {
	// Create a copy of the builtin untrusted inputs
	roots := make(ContextPropertySearchRoots, len(BuiltinUntrustedInputs)+1)
	for k, v := range BuiltinUntrustedInputs {
		roots[k] = v
	}

	// Add all inputs as potentially tainted
	if len(inputNames) > 0 {
		inputChildren := make([]*ContextPropertyMap, len(inputNames))
		for i, name := range inputNames {
			inputChildren[i] = NewContextPropertyMap(name)
		}
		roots["inputs"] = NewContextPropertyMap("inputs", inputChildren...)
	} else {
		// If no input names provided, treat any inputs.* access as tainted
		// by using a wildcard
		roots["inputs"] = NewContextPropertyMap("inputs",
			NewContextPropertyMap("*"),
		)
	}

	return roots
}
