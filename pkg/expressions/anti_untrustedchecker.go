package expressions

import (
	"strings"
)

// UntiCheckerは、式構文木内の信頼できない入力を検出するためのチェッカーです。
// このチェッカーは、オブジェクトプロパティアクセス、配列インデックスアクセス、およびオブジェクトフィルターを信頼できない入力に対してチェックします。
// 信頼できない入力へのパスを検出し、このインスタンスで見つかったエラーを保存します。これらのエラーは、Errsメソッドを介して取得できます。
type UntiChecker struct {
	roots           ContextPropertySearchRoots // 信頼できない入力パスを定義する検索ツリー
	filteringObject bool                       // 現在のノードがオブジェクトフィルターであるかどうか
	cur             []*ContextPropertyMap      // 現在のノードの信頼できない入力マップ
	start           ExprNode                   // 現在の式の開始ノード
	errs            []*ExprError               // 現在の式で見つかったエラー
	funcArgDepth    int                        // 関数引数内のネスト深度（0の場合は関数引数外）
}

// NewUntiCheckerは、新しいUntiCheckerインスタンスを作成します。
// roots引数は、検索ツリー内の信頼できない入力パスを定義します。
func NewUntiChecker(roots ContextPropertySearchRoots) *UntiChecker {
	return &UntiChecker{
		roots:           roots,
		filteringObject: false,
		cur:             nil,
		start:           nil,
		errs:            []*ExprError{},
	}
}

// resetは、次の検索のために状態をリセットします。
func (u *UntiChecker) reset() {
	u.start = nil
	u.filteringObject = false
	u.cur = u.cur[:0]
	// funcArgDepthはリセットしない（関数引数のコンテキストは維持する）
}

// compactは、現在のノードの信頼できない入力マップをコンパクトにし、nil値を削除します。
func (u *UntiChecker) compact() {
	delta := 0
	for i, c := range u.cur {
		if c == nil {
			delta++
			continue
		}
		if delta > 0 {
			u.cur[i-delta] = c
		}
	}
	u.cur = u.cur[:len(u.cur)-delta]
}

// onVarは、変数ノードが訪問されたときに呼び出されます。
// ルートコンテキスト（現在は "github" のみ）を見つけ、現在のノードの信頼できない入力マップに追加します。
func (u *UntiChecker) onVar(v *VariableNode) {
	c, ok := u.roots[v.Name]
	if !ok {
		return
	}
	u.start = v
	u.cur = append(u.cur, c)
}

// onPropAccessは、プロパティアクセスノードが訪問されたときに呼び出されます。
// 現在のノードの信頼できない入力マップ内で指定された名前のオブジェクトプロパティを見つけます。
// プロパティが見つからない場合、現在のノードの信頼できない入力マップをnilに設定します。
func (u *UntiChecker) onPropAccess(name string) {
	compact := false
	for i, cur := range u.cur {
		c, ok := cur.findObjectProp(name)
		if !ok {
			u.cur[i] = nil
			compact = true
			continue
		}
		u.cur[i] = c // depth + 1
	}
	if compact {
		u.compact()
	}
}

// onIndexAccessは、インデックスアクセスノードが訪問されたときに呼び出されます。
// 現在のノードの信頼できない入力マップ内で配列要素を見つけます。
// 要素が見つからない場合、現在のノードの信頼できない入力マップをnilに設定します。
func (u *UntiChecker) onIndexAccess() {
	if u.filteringObject {
		u.filteringObject = false
		return // 例えば、`github.event.*.body[0]`を`github.event.commits[0].body`としてマッチさせる
	}

	compact := false
	for i, cur := range u.cur {
		if c, ok := cur.findArrayElem(); ok {
			u.cur[i] = c
			continue
		}
		u.cur[i] = nil
		compact = true
	}
	if compact {
		u.compact()
	}
}

// onObjectFilterは、オブジェクトフィルターノードが訪問されたときに呼び出されます。
// 現在のノードの信頼できない入力マップをオブジェクトフィルターの子に設定します。
// 現在のノードの信頼できない入力マップが空の場合、それをnilに設定します。
func (u *UntiChecker) onObjectFilter() {
	u.filteringObject = true

	compact := false
	for i, cur := range u.cur {
		// 配列のオブジェクトフィルター
		if c, ok := cur.findArrayElem(); ok {
			u.cur[i] = c
			continue
		}

		if len(cur.Children) == 0 {
			u.cur[i] = nil
			compact = true
		}

		// オブジェクトのオブジェクトフィルター
		first := true
		for _, c := range cur.Children {
			if first {
				u.cur[i] = c
				first = false
			} else {
				u.cur = append(u.cur, c)
			}
		}
	}
	if compact {
		u.compact()
	}
}

// endは、ノードの訪問が終了したときに呼び出されます。
// 現在のノードの信頼できない入力マップで見つかった信頼できない入力へのパスを構築します。
// 1つの信頼できない入力のみが見つかった場合、その入力に対してエラーを追加します。
// 複数の信頼できない入力が見つかった場合、それらすべてに対してエラーを追加します。
func (u *UntiChecker) end() {
	u.endWithIntermediateCheck(false)
}

// endInFuncArgは、関数引数内でノードの訪問が終了したときに呼び出されます。
// 中間ノード（Childrenを持つノード）も検出対象とします。
// これにより、toJSON(github.event.pull_request)のようなパターンを検出できます。
func (u *UntiChecker) endInFuncArg() {
	u.endWithIntermediateCheck(true)
}

// endWithIntermediateCheckは、ノードの訪問が終了したときの共通処理です。
// checkIntermediateがtrueの場合、中間ノードも検出対象とします。
func (u *UntiChecker) endWithIntermediateCheck(checkIntermediate bool) {
	// Preallocate inputs slice with a reasonable capacity based on the expected number of inputs
	inputs := make([]string, 0, len(u.cur))
	intermediateInputs := make([]string, 0)

	for _, cur := range u.cur {
		if cur.Children != nil {
			// 中間ノード（リーフではない）
			if checkIntermediate {
				var b strings.Builder
				cur.buildPath(&b)
				intermediateInputs = append(intermediateInputs, b.String())
			}
			continue
		}
		// リーフノード
		var b strings.Builder
		cur.buildPath(&b)
		inputs = append(inputs, b.String())
	}

	// リーフノードのエラー報告
	if len(inputs) == 1 {
		err := errorfAtExpr(
			u.start,
			"%q is potentially untrusted. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions for more details.",
			inputs[0],
		)
		u.errs = append(u.errs, err)
	} else if len(inputs) > 1 {
		// 複数の信頼できない入力が検出された場合、式がオブジェクトフィルター構文で複数のプロパティを抽出していることを意味します。エラーメッセージにすべてのプロパティを表示します。
		err := errorfAtExpr(
			u.start,
			"Object filter extracts potentially untrusted properties %s. Avoid using the value directly in inline scripts. Instead, pass the value through an environment variable. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions for more details.",
			SortedQuotes(inputs),
		)
		u.errs = append(u.errs, err)
	}

	// 中間ノードのエラー報告（関数引数として渡された場合）
	if len(intermediateInputs) > 0 && len(inputs) == 0 {
		// リーフノードがなく、中間ノードのみが検出された場合
		if len(intermediateInputs) == 1 {
			err := errorfAtExpr(
				u.start,
				"%q contains potentially untrusted properties. Avoid passing entire objects to functions in inline scripts. Instead, access specific safe properties or pass values through environment variables. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions for more details.",
				intermediateInputs[0],
			)
			u.errs = append(u.errs, err)
		} else {
			err := errorfAtExpr(
				u.start,
				"Objects %s contain potentially untrusted properties. Avoid passing entire objects to functions in inline scripts. Instead, access specific safe properties or pass values through environment variables. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions for more details.",
				SortedQuotes(intermediateInputs),
			)
			u.errs = append(u.errs, err)
		}
	}

	u.reset()
}

// OnVisitNodeEnterは、子ノードの訪問前にノードを訪問する際に呼び出されるべきコールバックです。
// 関数呼び出しに入ったときにfuncArgDepthをインクリメントします。
func (u *UntiChecker) OnVisitNodeEnter(n ExprNode) {
	if _, ok := n.(*FuncCallNode); ok {
		u.funcArgDepth++
	}
}

// OnVisitNodeLeaveは、子ノードの訪問後にノードを訪問する際に呼び出されるべきコールバックです。
// 訪問されたノードのタイプに応じて適切なメソッドを呼び出します。
func (u *UntiChecker) OnVisitNodeLeave(n ExprNode) {
	switch n := n.(type) {
	case *VariableNode:
		if u.funcArgDepth > 0 {
			u.endInFuncArg()
		} else {
			u.end()
		}
		u.onVar(n)
	case *ObjectDerefNode:
		u.onPropAccess(n.Property)
	case *IndexAccessNode:
		if lit, ok := n.Index.(*StringNode); ok {
			// 特別なケース、例えばgithub['event']['issue']['title']
			u.onPropAccess(lit.Value)
			break
		}
		u.onIndexAccess()
	case *ArrayDerefNode:
		u.onObjectFilter()
	case *FuncCallNode:
		// 関数呼び出しの場合、引数内のuntrustedオブジェクト（中間ノード含む）を検出
		u.endInFuncArg()
		u.funcArgDepth-- // 関数引数のコンテキストを終了
	default:
		if u.funcArgDepth > 0 {
			u.endInFuncArg()
		} else {
			u.end()
		}
	}
}

// OnVisitEndは、構文木全体の訪問後に呼び出されるべきコールバックです。
// このコールバックは、式のルートに信頼できない入力アクセスがある場合を処理するために必要です。
func (u *UntiChecker) OnVisitEnd() {
	u.end()
}

// Errsは、このチェッカーによって検出されたエラーを返します。
// このメソッドは、構文木のすべてのノードを訪問した後
func (u *UntiChecker) Errs() []*ExprError {
	return u.errs
}

// Init initializes a state of checker.
func (u *UntiChecker) Init() {
	u.errs = u.errs[:0]
	u.funcArgDepth = 0
	u.reset()
}
