package expressions

import (
	"fmt"
	"strconv"
	"strings"
	"text/scanner"
)

// TokenKindはトークンの種類を示します。
type TokenKind int

// Tokenを文字列として表現するメソッド
func (t *Token) String() string {
	return fmt.Sprintf("%s:%d:%d:%d", t.Kind.String(), t.Line, t.Column, t.Offset)
}

// 与えられた文字が空白文字であるかどうかをチェック
func isWhitespace(r rune) bool {
	return r == ' ' || r == '\n' || r == '\r' || r == '\t'
}

// 与えられた文字がアルファベットであるかどうかをチェック
func isAlpha(r rune) bool {
	return ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z')
}

// 与えられた文字が数字であるかどうかをチェック
func isNum(r rune) bool {
	return '0' <= r && r <= '9'
}

// 与えられた文字が16進数の数字であるかどうかをチェック
// nolint:unused
func isHexNum(r rune) bool {
	return isNum(r) || ('a' <= r && r <= 'f') || ('A' <= r && r <= 'F')
}

// 与えられた文字が英数字であるかどうかをチェック
func isAlnum(r rune) bool {
	return isAlpha(r) || isNum(r)
}

// 期待される文字の一覧
const expectedPunctChars = "'', '}', '(', ')', '[', ']', '.', '!', '<', '>', '=', '&', '|', '*', ',', ' '"
const expectedDigitChars = "'0'..'9'"
const expectedAlphaChars = "'a'..'z', 'A'..'Z', '_'"
const expectedAllChars = expectedAlphaChars + ", " + expectedDigitChars + ", " + expectedPunctChars

// tokenの種類の一覧
const (
	TokenKindUnknown      TokenKind = iota // 不明なトークンの種類のデフォルト値です。
	TokenKindEnd                           // トークンシーケンスの終了を示すトークンです。このトークンがないシーケンスは無効です。
	TokenKindIdent                         // 識別子のトークンです。
	TokenKindString                        // 文字列リテラルのトークンです。
	TokenKindInt                           // 16進数を含む整数のトークンです。
	TokenKindFloat                         // 浮動小数点数のトークンです。
	TokenKindLeftParen                     // '('
	TokenKindRightParen                    // ')'
	TokenKindLeftBracket                   // '['
	TokenKindRightBracket                  // ']'
	TokenKindDot                           // '.'
	TokenKindNot                           // '!'
	TokenKindLess                          // '<'
	TokenKindLessEq                        // '<='
	TokenKindGreater                       // '>'
	TokenKindGreaterEq                     // '>='
	TokenKindEq                            // '=='
	TokenKindNotEq                         // '!='
	TokenKindAnd                           // '&&'
	TokenKindOr                            // '||'
	TokenKindStar                          // '*'
	TokenKindComma                         // ','
)

func (t TokenKind) String() string {
	switch t {
	case TokenKindUnknown:
		return "UNKNOWN"
	case TokenKindEnd:
		return "END"
	case TokenKindIdent:
		return "IDENT"
	case TokenKindString:
		return "STRING"
	case TokenKindInt:
		return "INTEGER"
	case TokenKindFloat:
		return "FLOAT"
	case TokenKindLeftParen:
		return "("
	case TokenKindRightParen:
		return ")"
	case TokenKindLeftBracket:
		return "["
	case TokenKindRightBracket:
		return "]"
	case TokenKindDot:
		return "."
	case TokenKindNot:
		return "!"
	case TokenKindLess:
		return "<"
	case TokenKindLessEq:
		return "<="
	case TokenKindGreater:
		return ">"
	case TokenKindGreaterEq:
		return ">="
	case TokenKindEq:
		return "=="
	case TokenKindNotEq:
		return "!="
	case TokenKindAnd:
		return "&&"
	case TokenKindOr:
		return "||"
	case TokenKindStar:
		return "*"
	case TokenKindComma:
		return ","
	default:
		//log.Warnf("Unknown TokenKind: %v", t) // 例: ログに警告を出力
		return "UNKNOWN"
	}
}

// Tokenizerは式の構文を字句解析するための構造体
// * https://docs.github.com/en/actions/learn-github-actions/expressions
type Tokenizer struct {
	source   string           // 字句解析するソース文字列です。
	scanner  scanner.Scanner  // Goの標準ライブラリから提供されるスキャナーです。
	lexError *ExprError       // 字句解析中に発生したエラーを保持します。
	start    scanner.Position // トークンの開始位置を示します。
}

// NewTokenizer は新しい Tokenizer インスタンスを作成します。
func NewTokenizer(src string) *Tokenizer {
	t := &Tokenizer{
		source: src,
		start: scanner.Position{
			Offset: 0,
			Line:   1,
			Column: 1,
		},
	}
	t.scanner.Init(strings.NewReader(src))
	t.scanner.Error = func(_ *scanner.Scanner, m string) {
		t.error(fmt.Sprintf("scan error while tokenizing expression:  %s", m))
	}
	return t
}

// error はエラーメッセージをセットします。
func (t *Tokenizer) error(msg string) {
	if t.lexError == nil {
		p := t.scanner.Pos()
		t.lexError = &ExprError{
			Message: msg,
			Offset:  p.Offset,
			Line:    p.Line,
			Column:  p.Column,
		}
	}
}

// token はトークンを作成して返します。
func (t *Tokenizer) token(kind TokenKind) *Token {
	p := t.scanner.Pos()
	s := t.start
	return &Token{
		Kind:   kind,
		Value:  t.source[s.Offset:p.Offset],
		Offset: s.Offset,
		Line:   s.Line,
		Column: s.Column,
	}
}

// eof はファイルの終端を示すトークンを返します。
func (t *Tokenizer) eof() *Token {
	return &Token{
		Kind:   TokenKindEnd,
		Value:  "",
		Offset: t.start.Offset,
		Line:   t.start.Line,
		Column: t.start.Column,
	}
}

// eat は次の文字を読み飛ばし、その後の文字を返します。
func (t *Tokenizer) eat() rune {
	t.scanner.Next()
	return t.scanner.Peek()
}

// skipWhite は空白をスキップします。
func (t *Tokenizer) skipWhite() {
	for {
		if r := t.scanner.Peek(); !isWhitespace(r) {
			// Always update t.start to current position after skipping whitespace
			// This ensures each token starts at the correct position
			t.start = t.scanner.Pos()
			return
		}
		t.scanner.Next()
	}
}

// unexpected は予期しない文字に遭遇したときのエラーメッセージをセットし、EOFトークンを返します。
func (t *Tokenizer) unexpected(r rune, where string, expected string) *Token {
	var what string
	if r == scanner.EOF {
		what = "EOF"
	} else {
		what = "char " + strconv.QuoteRune(r)
	}

	note := ""
	if r == '"' {
		note = ". do you mean string literals? only single quotes are available for string delimiter"
	}

	msg := fmt.Sprintf(
		"got unexpected %s while lexing %s, expecting %s%s",
		what,
		where,
		expected,
		note,
	)

	t.error(msg)
	return t.eof()
}

// unexpectedEOF は予期しないEOFエラーメッセージをセットし、EOFトークンを返します。
func (t *Tokenizer) unexpectedEOF() *Token {
	t.error("unexpected EOF while tokenizing expression")
	return t.eof()
}

// lexIdent は識別子を字句解析します。
func (t *Tokenizer) lexIdent() *Token {
	t.start = t.scanner.Pos() // トークンの開始位置を設定
	for {
		if r := t.eat(); !isAlnum(r) && r != '_' && r != '-' {
			return t.token(TokenKindIdent)
		}
	}
}

// lexNum は数値を字句解析します。
func (t *Tokenizer) lexNum() *Token {
	r := t.scanner.Peek()
	if r == '-' {
		r = t.eat()
	}
	if r == '0' {
		r = t.eat()
		if r == 'x' {
			t.scanner.Next()
			return t.lexHexInt()
		}
	} else {
		if !isNum(r) {
			return t.unexpected(r, "整数部", expectedDigitChars)
		}
		for {
			r = t.eat()
			if !isNum(r) {
				break
			}
		}
	}
	k := TokenKindInt
	if r == '.' {
		r = t.eat()
		if !isNum(r) {
			return t.unexpected(r, "小数部", expectedDigitChars)
		}
		for {
			r = t.eat()
			if !isNum(r) {
				break
			}
		}
		k = TokenKindFloat
	}
	if r == 'e' || r == 'E' {
		r = t.eat()
		if r == '-' {
			r = t.eat()
		}
		if r == '0' {
			r = t.eat()
		} else {
			if !isNum(r) {
				return t.unexpected(r, "指数部", expectedDigitChars)
			}
			for {
				r = t.eat()
				if !isNum(r) {
					break
				}
			}
		}
		k = TokenKindFloat
	}
	if isAlnum(r) {
		s := t.source[t.start.Offset:t.scanner.Pos().Offset]
		return t.unexpected(r, "char after number "+s, expectedPunctChars)
	}
	return t.token(k)
}

// lexHexInt は16進数を字句解析します。
func (t *Tokenizer) lexHexInt() *Token {
	r := t.scanner.Peek()
	if r == '0' {
		r = t.eat()
	} else {
		if !isHexNum(r) {
			return t.unexpected(r, "16 number", expectedDigitChars+", 'a'..'f', 'A'..'F'")
		}
		for {
			r = t.eat()
			if !isHexNum(r) {
				break
			}
		}
	}
	if isAlnum(r) {
		s := t.source[t.start.Offset:t.scanner.Pos().Offset]
		return t.unexpected(r, "char after 16 number "+s, expectedPunctChars)
	}
	return t.token(TokenKindInt)
}

// lexString は文字列を字句解析します。
func (t *Tokenizer) lexString() *Token {
	for {
		switch t.eat() {
		case '\'':
			if t.eat() != '\'' {
				return t.token(TokenKindString)
			}
		case scanner.EOF:
			return t.unexpected(scanner.EOF, "end of char literal", "'''")
		}
	}
}

// lexEnd は `}}` の終了マーカーを字句解析します。
func (t *Tokenizer) lexEnd() *Token {
	r := t.eat()
	if r != '}' {
		return t.unexpected(r, "end marker }}", "'}'")
	}
	t.scanner.Next()
	// }} は補完の終了マーカーです。
	return t.token(TokenKindEnd)
}

// lexLess は `<` または `<=` を字句解析します。
func (t *Tokenizer) lexLess() *Token {
	k := TokenKindLess
	if t.eat() == '=' {
		k = TokenKindLessEq
		t.scanner.Next()
	}
	return t.token(k)
}

// lexGreater は `>` または `>=` を字句解析します。
func (t *Tokenizer) lexGreater() *Token {
	k := TokenKindGreater
	if t.eat() == '=' {
		k = TokenKindGreaterEq
		t.scanner.Next()
	}
	return t.token(k)
}

// lexEq は `==` を字句解析します。
func (t *Tokenizer) lexEq() *Token {
	if r := t.eat(); r != '=' {
		return t.unexpected(r, "== operator", "'='")
	}
	t.scanner.Next()
	return t.token(TokenKindEq)
}

// lexBang は `!` または `!=` を字句解析します。
func (t *Tokenizer) lexBang() *Token {
	k := TokenKindNot
	if t.eat() == '=' {
		t.scanner.Next()
		k = TokenKindNotEq
	}
	return t.token(k)
}

// lexAnd は `&&` を字句解析します。
func (t *Tokenizer) lexAnd() *Token {
	if r := t.eat(); r != '&' {
		return t.unexpected(r, "&& operator", "'&'")
	}
	t.scanner.Next()
	return t.token(TokenKindAnd)
}

// lexOr は `||` を字句解析します。
func (t *Tokenizer) lexOr() *Token {
	if r := t.eat(); r != '|' {
		return t.unexpected(r, "|| operator", "'|'")
	}
	t.scanner.Next()
	return t.token(TokenKindOr)
}

// lexChar は指定された TokenKind に対応する文字を字句解析します。
func (t *Tokenizer) lexChar(k TokenKind) *Token {
	t.scanner.Next()
	return t.token(k)
}

// AnalyzeToken は次のトークンを逐次的に字句解析します。このメソッドの最初の呼び出し前に、Init()メソッドでLexerを初期化する必要があります。
// このメソッドは状態を持ちます。トークンを字句解析することでLexerはオフセットを進めます。オフセットを取得するには、GetCurrentOffset()メソッドを使用してください。
func (t *Tokenizer) AnalyzeToken() *Token {
	t.skipWhite()

	r := t.scanner.Peek()
	if r == scanner.EOF {
		return t.unexpectedEOF()
	}

	if isAlpha(r) || r == '_' {
		return t.lexIdent()
	}

	if isNum(r) {
		return t.lexNum()
	}

	switch r {
	case '\'':
		return t.lexString()
	case '}':
		return t.lexEnd()
	case '!':
		return t.lexBang()
	case '<':
		return t.lexLess()
	case '>':
		return t.lexGreater()
	case '=':
		return t.lexEq()
	case '&':
		return t.lexAnd()
	case '|':
		return t.lexOr()
	case '(':
		return t.lexChar(TokenKindLeftParen)
	case ')':
		return t.lexChar(TokenKindRightParen)
	case '[':
		return t.lexChar(TokenKindLeftBracket)
	case ']':
		return t.lexChar(TokenKindRightBracket)
	case '.':
		return t.lexChar(TokenKindDot)
	case '*':
		return t.lexChar(TokenKindStar)
	case ',':
		return t.lexChar(TokenKindComma)
	default:
		return t.unexpected(r, "expression", expectedAllChars)
	}
}

// GetCurrentOffset は現在の走査位置を返します。
func (t *Tokenizer) GetCurrentOffset() int {
	return t.scanner.Pos().Offset
}

// GetError は字句解析中に発生したエラーを返します。複数のエラーが発生した場合、最初のものが返されます。
func (t *Tokenizer) GetError() *ExprError {
	return t.lexError
}

// AnalyzeExpressionSyntax は指定された文字列を式の構文として字句解析します。
// パラメータには式の終了を表す '}}' が含まれている必要があります。
// それ以外の場合、unexpected EOFに遭遇したというエラーを報告します。
func AnalyzeExpressionSyntax(src string) ([]*Token, int, *ExprError) {
	lexerInstance := NewTokenizer(src)
	var tokens []*Token
	for {
		token := lexerInstance.AnalyzeToken()
		if lexerInstance.lexError != nil {
			return nil, lexerInstance.scanner.Pos().Offset, lexerInstance.lexError
		}
		tokens = append(tokens, token)
		if token.Kind == TokenKindEnd {
			return tokens, lexerInstance.scanner.Pos().Offset, nil
		}
	}
}
