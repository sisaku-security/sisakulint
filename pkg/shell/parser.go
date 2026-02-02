package shell

import (
	"bytes"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const evalCommand = "eval"

type ShellVarUsage struct {
	VarName    string
	StartPos   int
	EndPos     int
	IsQuoted   bool
	InEval     bool
	InShellCmd bool
	InCmdSubst bool
	Context    string
}

type VarArgUsage struct {
	ShellVarUsage
	CommandName       string
	ArgPosition       int
	HasDoubleDash     bool
	IsAfterDoubleDash bool
}

type ShellParser struct {
	script string
	file   *syntax.File
}

func NewShellParser(script string) *ShellParser {
	p := &ShellParser{script: script}
	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	reader := strings.NewReader(script)
	file, err := parser.Parse(reader, "")
	if err == nil {
		p.file = file
	}
	return p
}

// walkContext tracks the current context during AST traversal.
type walkContext struct {
	inEval     bool
	inShellCmd bool
	inCmdSubst bool
}

func (p *ShellParser) FindEnvVarUsages(varName string) []ShellVarUsage {
	if p.file == nil {
		return nil
	}

	var usages []ShellVarUsage
	ctx := &walkContext{}
	p.walkNode(p.file, varName, ctx, &usages)
	return usages
}

// walkNode recursively traverses the AST with proper context tracking.
func (p *ShellParser) walkNode(node syntax.Node, varName string, ctx *walkContext, usages *[]ShellVarUsage) {
	if node == nil {
		return
	}

	switch x := node.(type) {
	case *syntax.File:
		for _, stmt := range x.Stmts {
			p.walkNode(stmt, varName, ctx, usages)
		}

	case *syntax.Stmt:
		p.walkNode(x.Cmd, varName, ctx, usages)
		for _, redirect := range x.Redirs {
			p.walkNode(redirect, varName, ctx, usages)
		}

	case *syntax.CallExpr:
		cmdName := p.getCommandName(x)
		newCtx := *ctx
		if cmdName == evalCommand {
			newCtx.inEval = true
		} else if p.isShellCommand(x) {
			newCtx.inShellCmd = true
		}
		for _, assign := range x.Assigns {
			p.walkNode(assign, varName, &newCtx, usages)
		}
		for _, arg := range x.Args {
			p.walkNode(arg, varName, &newCtx, usages)
		}

	case *syntax.Assign:
		if x.Value != nil {
			p.walkNode(x.Value, varName, ctx, usages)
		}
		if x.Array != nil {
			p.walkNode(x.Array, varName, ctx, usages)
		}

	case *syntax.Word:
		for _, part := range x.Parts {
			p.walkNode(part, varName, ctx, usages)
		}

	case *syntax.DblQuoted:
		for _, part := range x.Parts {
			p.walkNode(part, varName, ctx, usages)
		}

	case *syntax.SglQuoted:
		// Single quotes don't expand variables

	case *syntax.ParamExp:
		if x.Param != nil && x.Param.Value == varName {
			usage := ShellVarUsage{
				VarName:    varName,
				StartPos:   int(x.Pos().Offset()),
				EndPos:     int(x.End().Offset()),
				IsQuoted:   p.isParamExpQuoted(x),
				InEval:     ctx.inEval,
				InShellCmd: ctx.inShellCmd,
				InCmdSubst: ctx.inCmdSubst,
				Context:    p.getContextFromPos(int(x.Pos().Offset()), int(x.End().Offset())),
			}
			*usages = append(*usages, usage)
		}
		// Also check nested expressions (e.g., ${var:-$default})
		if x.Exp != nil && x.Exp.Word != nil {
			p.walkNode(x.Exp.Word, varName, ctx, usages)
		}

	case *syntax.CmdSubst:
		newCtx := *ctx
		newCtx.inCmdSubst = true
		for _, stmt := range x.Stmts {
			p.walkNode(stmt, varName, &newCtx, usages)
		}

	case *syntax.ArithmExp:
		if x.X != nil {
			p.walkArithm(x.X, varName, ctx, usages)
		}

	case *syntax.ProcSubst:
		for _, stmt := range x.Stmts {
			p.walkNode(stmt, varName, ctx, usages)
		}

	case *syntax.BinaryCmd:
		p.walkNode(x.X, varName, ctx, usages)
		p.walkNode(x.Y, varName, ctx, usages)

	case *syntax.IfClause:
		for _, cond := range x.Cond {
			p.walkNode(cond, varName, ctx, usages)
		}
		for _, then := range x.Then {
			p.walkNode(then, varName, ctx, usages)
		}
		if x.Else != nil {
			p.walkNode(x.Else, varName, ctx, usages)
		}

	case *syntax.WhileClause:
		for _, cond := range x.Cond {
			p.walkNode(cond, varName, ctx, usages)
		}
		for _, do := range x.Do {
			p.walkNode(do, varName, ctx, usages)
		}

	case *syntax.ForClause:
		if x.Loop != nil {
			p.walkLoop(x.Loop, varName, ctx, usages)
		}
		for _, do := range x.Do {
			p.walkNode(do, varName, ctx, usages)
		}

	case *syntax.CaseClause:
		if x.Word != nil {
			p.walkNode(x.Word, varName, ctx, usages)
		}
		for _, item := range x.Items {
			p.walkNode(item, varName, ctx, usages)
		}

	case *syntax.CaseItem:
		for _, pattern := range x.Patterns {
			p.walkNode(pattern, varName, ctx, usages)
		}
		for _, stmt := range x.Stmts {
			p.walkNode(stmt, varName, ctx, usages)
		}

	case *syntax.Block:
		for _, stmt := range x.Stmts {
			p.walkNode(stmt, varName, ctx, usages)
		}

	case *syntax.Subshell:
		for _, stmt := range x.Stmts {
			p.walkNode(stmt, varName, ctx, usages)
		}

	case *syntax.FuncDecl:
		p.walkNode(x.Body, varName, ctx, usages)

	case *syntax.ArithmCmd:
		if x.X != nil {
			p.walkArithm(x.X, varName, ctx, usages)
		}

	case *syntax.TestClause:
		if x.X != nil {
			p.walkTest(x.X, varName, ctx, usages)
		}

	case *syntax.DeclClause:
		for _, assign := range x.Args {
			p.walkNode(assign, varName, ctx, usages)
		}

	case *syntax.Redirect:
		if x.Word != nil {
			p.walkNode(x.Word, varName, ctx, usages)
		}
		// Handle heredoc content
		if x.Hdoc != nil {
			p.walkNode(x.Hdoc, varName, ctx, usages)
		}

	case *syntax.ArrayExpr:
		for _, elem := range x.Elems {
			p.walkNode(elem, varName, ctx, usages)
		}

	case *syntax.ArrayElem:
		if x.Value != nil {
			p.walkNode(x.Value, varName, ctx, usages)
		}

	case *syntax.ExtGlob:
		if x.Pattern != nil {
			p.walkNode(x.Pattern, varName, ctx, usages)
		}

	case *syntax.BraceExp:
		for _, elem := range x.Elems {
			p.walkNode(elem, varName, ctx, usages)
		}

	case *syntax.CoprocClause:
		p.walkNode(x.Stmt, varName, ctx, usages)

	case *syntax.LetClause:
		for _, expr := range x.Exprs {
			p.walkArithm(expr, varName, ctx, usages)
		}

	case *syntax.TimeClause:
		if x.Stmt != nil {
			p.walkNode(x.Stmt, varName, ctx, usages)
		}
	}
}

// walkArithm handles arithmetic expression nodes.
func (p *ShellParser) walkArithm(node syntax.ArithmExpr, varName string, ctx *walkContext, usages *[]ShellVarUsage) {
	if node == nil {
		return
	}

	switch x := node.(type) {
	case *syntax.BinaryArithm:
		p.walkArithm(x.X, varName, ctx, usages)
		p.walkArithm(x.Y, varName, ctx, usages)
	case *syntax.UnaryArithm:
		p.walkArithm(x.X, varName, ctx, usages)
	case *syntax.ParenArithm:
		p.walkArithm(x.X, varName, ctx, usages)
	case *syntax.Word:
		p.walkNode(x, varName, ctx, usages)
	}
}

// walkTest handles test expression nodes.
func (p *ShellParser) walkTest(node syntax.TestExpr, varName string, ctx *walkContext, usages *[]ShellVarUsage) {
	if node == nil {
		return
	}

	switch x := node.(type) {
	case *syntax.BinaryTest:
		p.walkTest(x.X, varName, ctx, usages)
		p.walkTest(x.Y, varName, ctx, usages)
	case *syntax.UnaryTest:
		p.walkTest(x.X, varName, ctx, usages)
	case *syntax.ParenTest:
		p.walkTest(x.X, varName, ctx, usages)
	case *syntax.Word:
		p.walkNode(x, varName, ctx, usages)
	}
}

// walkLoop handles loop nodes.
func (p *ShellParser) walkLoop(node syntax.Loop, varName string, ctx *walkContext, usages *[]ShellVarUsage) {
	if node == nil {
		return
	}

	switch x := node.(type) {
	case *syntax.WordIter:
		for _, word := range x.Items {
			p.walkNode(word, varName, ctx, usages)
		}
	case *syntax.CStyleLoop:
		p.walkArithm(x.Init, varName, ctx, usages)
		p.walkArithm(x.Cond, varName, ctx, usages)
		p.walkArithm(x.Post, varName, ctx, usages)
	}
}

func (p *ShellParser) isParamExpQuoted(pe *syntax.ParamExp) bool {
	var quoted bool

	syntax.Walk(p.file, func(node syntax.Node) bool {
		if dq, ok := node.(*syntax.DblQuoted); ok {
			for _, part := range dq.Parts {
				if paramExp, ok := part.(*syntax.ParamExp); ok {
					if paramExp == pe {
						quoted = true
						return false
					}
				}
			}
		}
		return true
	})

	return quoted
}

func (p *ShellParser) getCommandName(call *syntax.CallExpr) string {
	if len(call.Args) == 0 {
		return ""
	}

	var buf bytes.Buffer
	printer := syntax.NewPrinter()
	if err := printer.Print(&buf, call.Args[0]); err != nil {
		return ""
	}
	return strings.TrimSpace(buf.String())
}

func (p *ShellParser) isShellCommand(call *syntax.CallExpr) bool {
	if len(call.Args) < 2 {
		return false
	}

	cmdName := p.getCommandName(call)
	shellCmds := []string{"sh", "bash", "zsh", "ksh", "dash"}

	for _, shell := range shellCmds {
		if cmdName == shell {
			for i := 1; i < len(call.Args); i++ {
				var buf bytes.Buffer
				printer := syntax.NewPrinter()
				if err := printer.Print(&buf, call.Args[i]); err != nil {
					continue
				}
				if strings.TrimSpace(buf.String()) == "-c" {
					return true
				}
			}
		}
	}
	return false
}

func (p *ShellParser) getContextFromPos(start, end int) string {
	if start < 0 || end > len(p.script) {
		return ""
	}

	lineStart := strings.LastIndex(p.script[:start], "\n")
	if lineStart == -1 {
		lineStart = 0
	} else {
		lineStart++
	}

	lineEnd := strings.Index(p.script[end:], "\n")
	if lineEnd == -1 {
		lineEnd = len(p.script)
	} else {
		lineEnd += end
	}

	line := p.script[lineStart:lineEnd]

	if len(line) > 80 {
		relStart := start - lineStart
		contextStart := max(relStart-30, 0)
		contextEnd := min(relStart+50, len(line))
		line = "..." + line[contextStart:contextEnd] + "..."
	}

	return strings.TrimSpace(line)
}

func (u *ShellVarUsage) IsUnsafeUsage() bool {
	// Unquoted variables are always unsafe (word splitting and glob expansion)
	if !u.IsQuoted {
		return true
	}
	// Variables inside eval are unsafe even when quoted (eval parses the value again)
	if u.InEval {
		return true
	}
	// Variables inside sh -c / bash -c are unsafe even when quoted (nested shell parsing)
	if u.InShellCmd {
		return true
	}
	// Quoted variables inside command substitution are safe
	// e.g., $(echo "$VAR") is safe because the variable is quoted
	// Only unquoted variables in command substitution are dangerous (handled by !u.IsQuoted above)
	return false
}

func (p *ShellParser) HasDangerousPattern() bool {
	if p.file == nil {
		return false
	}

	var found bool
	syntax.Walk(p.file, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok {
			cmdName := p.getCommandName(call)
			if cmdName == evalCommand || p.isShellCommand(call) {
				found = true
				return false
			}
		}
		return true
	})

	return found
}

func (p *ShellParser) GetDangerousPatternType() string {
	if p.file == nil {
		return ""
	}

	var patternType string
	syntax.Walk(p.file, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok {
			cmdName := p.getCommandName(call)
			if cmdName == evalCommand {
				patternType = evalCommand
				return false
			}
			if p.isShellCommand(call) {
				patternType = cmdName + " -c"
				return false
			}
		}
		return true
	})

	return patternType
}

type NetworkCommandCall struct {
	CommandName string
	Args        []CommandArg
	Position    syntax.Pos
	InCmdSubst  bool
	InPipe      bool
}

type CommandArg struct {
	Value        string
	LiteralValue string
	Position     syntax.Pos
	IsFlag       bool
	VarNames     []string
	GHAExprs     []string
}

func (p *ShellParser) FindNetworkCommands() []NetworkCommandCall {
	if p.file == nil {
		return nil
	}

	var calls []NetworkCommandCall
	ctx := &networkWalkContext{}
	p.walkForNetworkCommands(p.file, ctx, &calls)
	return calls
}

type networkWalkContext struct {
	inCmdSubst bool
	inPipe     bool
}

func (p *ShellParser) walkForNetworkCommands(node syntax.Node, ctx *networkWalkContext, calls *[]NetworkCommandCall) {
	if node == nil {
		return
	}

	switch x := node.(type) {
	case *syntax.File:
		for _, stmt := range x.Stmts {
			p.walkForNetworkCommands(stmt, ctx, calls)
		}

	case *syntax.Stmt:
		p.walkForNetworkCommands(x.Cmd, ctx, calls)
		for _, redirect := range x.Redirs {
			p.walkForNetworkCommands(redirect, ctx, calls)
		}

	case *syntax.CallExpr:
		cmdName := p.getCommandName(x)
		if p.isNetworkCommand(cmdName) {
			call := p.parseNetworkCommand(x, ctx)
			*calls = append(*calls, call)
		}

		for _, assign := range x.Assigns {
			p.walkForNetworkCommands(assign, ctx, calls)
		}
		for _, arg := range x.Args {
			p.walkForNetworkCommands(arg, ctx, calls)
		}

	case *syntax.BinaryCmd:
		newCtx := *ctx
		if x.Op == syntax.Pipe {
			newCtx.inPipe = true
		}
		p.walkForNetworkCommands(x.X, &newCtx, calls)
		p.walkForNetworkCommands(x.Y, &newCtx, calls)

	case *syntax.CmdSubst:
		newCtx := *ctx
		newCtx.inCmdSubst = true
		for _, stmt := range x.Stmts {
			p.walkForNetworkCommands(stmt, &newCtx, calls)
		}

	case *syntax.IfClause:
		for _, cond := range x.Cond {
			p.walkForNetworkCommands(cond, ctx, calls)
		}
		for _, then := range x.Then {
			p.walkForNetworkCommands(then, ctx, calls)
		}
		if x.Else != nil {
			p.walkForNetworkCommands(x.Else, ctx, calls)
		}

	case *syntax.WhileClause:
		for _, cond := range x.Cond {
			p.walkForNetworkCommands(cond, ctx, calls)
		}
		for _, do := range x.Do {
			p.walkForNetworkCommands(do, ctx, calls)
		}

	case *syntax.ForClause:
		if x.Loop != nil {
			p.walkForNetworkCommandsLoop(x.Loop, ctx, calls)
		}
		for _, do := range x.Do {
			p.walkForNetworkCommands(do, ctx, calls)
		}

	case *syntax.CaseClause:
		if x.Word != nil {
			p.walkForNetworkCommands(x.Word, ctx, calls)
		}
		for _, item := range x.Items {
			p.walkForNetworkCommands(item, ctx, calls)
		}

	case *syntax.CaseItem:
		for _, pattern := range x.Patterns {
			p.walkForNetworkCommands(pattern, ctx, calls)
		}
		for _, stmt := range x.Stmts {
			p.walkForNetworkCommands(stmt, ctx, calls)
		}

	case *syntax.Block:
		for _, stmt := range x.Stmts {
			p.walkForNetworkCommands(stmt, ctx, calls)
		}

	case *syntax.Subshell:
		for _, stmt := range x.Stmts {
			p.walkForNetworkCommands(stmt, ctx, calls)
		}

	case *syntax.FuncDecl:
		p.walkForNetworkCommands(x.Body, ctx, calls)

	case *syntax.ProcSubst:
		for _, stmt := range x.Stmts {
			p.walkForNetworkCommands(stmt, ctx, calls)
		}

	case *syntax.ArithmCmd:
		// Arithmetic commands don't contain network calls

	case *syntax.TestClause:
		p.walkForNetworkCommandsTest(x.X, ctx, calls)

	case *syntax.DeclClause:
		for _, assign := range x.Args {
			p.walkForNetworkCommands(assign, ctx, calls)
		}

	case *syntax.Assign:
		if x.Value != nil {
			p.walkForNetworkCommands(x.Value, ctx, calls)
		}
		if x.Array != nil {
			p.walkForNetworkCommands(x.Array, ctx, calls)
		}

	case *syntax.ArrayExpr:
		for _, elem := range x.Elems {
			p.walkForNetworkCommands(elem, ctx, calls)
		}

	case *syntax.ArrayElem:
		if x.Value != nil {
			p.walkForNetworkCommands(x.Value, ctx, calls)
		}

	case *syntax.CoprocClause:
		p.walkForNetworkCommands(x.Stmt, ctx, calls)

	case *syntax.TimeClause:
		if x.Stmt != nil {
			p.walkForNetworkCommands(x.Stmt, ctx, calls)
		}

	case *syntax.Word:
		for _, part := range x.Parts {
			p.walkForNetworkCommands(part, ctx, calls)
		}

	case *syntax.DblQuoted:
		for _, part := range x.Parts {
			p.walkForNetworkCommands(part, ctx, calls)
		}

	case *syntax.SglQuoted, *syntax.ParamExp, *syntax.Redirect, *syntax.Lit:
		// These nodes don't contain network commands
	}
}

// walkForNetworkCommandsLoop handles loop nodes for network command detection.
func (p *ShellParser) walkForNetworkCommandsLoop(node syntax.Loop, ctx *networkWalkContext, calls *[]NetworkCommandCall) {
	if node == nil {
		return
	}

	switch x := node.(type) {
	case *syntax.WordIter:
		for _, word := range x.Items {
			p.walkForNetworkCommands(word, ctx, calls)
		}
	case *syntax.CStyleLoop:
		// C-style loop expressions don't contain network commands
	}
}

// walkForNetworkCommandsTest handles test expressions for network command detection.
func (p *ShellParser) walkForNetworkCommandsTest(node syntax.TestExpr, ctx *networkWalkContext, calls *[]NetworkCommandCall) {
	if node == nil {
		return
	}

	switch x := node.(type) {
	case *syntax.BinaryTest:
		p.walkForNetworkCommandsTest(x.X, ctx, calls)
		p.walkForNetworkCommandsTest(x.Y, ctx, calls)
	case *syntax.UnaryTest:
		p.walkForNetworkCommandsTest(x.X, ctx, calls)
	case *syntax.ParenTest:
		p.walkForNetworkCommandsTest(x.X, ctx, calls)
	case *syntax.Word:
		p.walkForNetworkCommands(x, ctx, calls)
	}
}

func (p *ShellParser) isNetworkCommand(cmdName string) bool {
	networkCmds := map[string]bool{
		"curl":   true,
		"wget":   true,
		"nc":     true,
		"netcat": true,
		"http":   true,
		"https":  true,
	}
	return networkCmds[cmdName]
}

func (p *ShellParser) parseNetworkCommand(call *syntax.CallExpr, ctx *networkWalkContext) NetworkCommandCall {
	cmd := NetworkCommandCall{
		CommandName: p.getCommandName(call),
		Position:    call.Pos(),
		InCmdSubst:  ctx.inCmdSubst,
		InPipe:      ctx.inPipe,
	}

	for i := 1; i < len(call.Args); i++ {
		arg := p.parseCommandArg(call.Args[i])
		cmd.Args = append(cmd.Args, arg)
	}

	return cmd
}

func (p *ShellParser) parseCommandArg(word *syntax.Word) CommandArg {
	rawValue := p.wordToString(word)
	literalValue := p.extractLiteralValue(word)

	arg := CommandArg{
		Value:        rawValue,
		LiteralValue: literalValue,
		Position:     word.Pos(),
	}

	if strings.HasPrefix(literalValue, "-") {
		arg.IsFlag = true
	}

	p.analyzeWordParts(word, &arg)

	return arg
}

func (p *ShellParser) extractLiteralValue(word *syntax.Word) string {
	var result strings.Builder

	for _, part := range word.Parts {
		p.extractLiteralFromPart(part, &result)
	}

	return result.String()
}

func (p *ShellParser) extractLiteralFromPart(part syntax.WordPart, result *strings.Builder) {
	switch x := part.(type) {
	case *syntax.Lit:
		result.WriteString(x.Value)
	case *syntax.DblQuoted:
		for _, inner := range x.Parts {
			p.extractLiteralFromPart(inner, result)
		}
	case *syntax.SglQuoted:
		result.WriteString(x.Value)
	case *syntax.ParamExp:
		if x.Param != nil {
			if x.Short {
				result.WriteString("$")
				result.WriteString(x.Param.Value)
			} else {
				result.WriteString("${")
				result.WriteString(x.Param.Value)
				result.WriteString("}")
			}
		}
	case *syntax.CmdSubst:
		var buf bytes.Buffer
		printer := syntax.NewPrinter()
		if err := printer.Print(&buf, x); err == nil {
			result.WriteString(buf.String())
		}
	}
}

func (p *ShellParser) wordToString(word *syntax.Word) string {
	var buf bytes.Buffer
	printer := syntax.NewPrinter()
	if err := printer.Print(&buf, word); err != nil {
		return ""
	}
	return strings.TrimSpace(buf.String())
}

func (p *ShellParser) analyzeWordParts(word *syntax.Word, arg *CommandArg) {
	rawValue := arg.Value
	ghaExprs := extractGHAExpressionsFromString(rawValue)
	arg.GHAExprs = ghaExprs

	syntax.Walk(word, func(node syntax.Node) bool {
		if paramExp, ok := node.(*syntax.ParamExp); ok {
			if paramExp.Param != nil && paramExp.Param.Value != "" {
				arg.VarNames = append(arg.VarNames, paramExp.Param.Value)
			}
		}
		return true
	})
}

func extractGHAExpressionsFromString(s string) []string {
	var exprs []string
	offset := 0

	for {
		idx := strings.Index(s[offset:], "${{")
		if idx == -1 {
			break
		}

		start := offset + idx
		endIdx := strings.Index(s[start:], "}}")
		if endIdx == -1 {
			break
		}

		expr := strings.TrimSpace(s[start+3 : start+endIdx])
		exprs = append(exprs, expr)

		offset = start + endIdx + 2
	}

	return exprs
}

func (p *ShellParser) FindVarUsageAsCommandArg(varName string, cmdNames []string) []VarArgUsage {
	if p.file == nil {
		return nil
	}

	var usages []VarArgUsage
	cmdNameMap := make(map[string]bool)
	for _, cmd := range cmdNames {
		cmdNameMap[cmd] = true
	}

	syntax.Walk(p.file, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok {
			cmdName := p.getCommandName(call)
			if !cmdNameMap[cmdName] {
				return true
			}

			doubleDashPos := p.findDoubleDashPosition(call)
			for argIdx, arg := range call.Args[1:] {
				actualIdx := argIdx + 1
				p.findVarInArg(arg, varName, cmdName, actualIdx, doubleDashPos, &usages)
			}
		}
		return true
	})

	return usages
}

func (p *ShellParser) findDoubleDashPosition(call *syntax.CallExpr) int {
	for i, arg := range call.Args[1:] {
		var buf bytes.Buffer
		printer := syntax.NewPrinter()
		if err := printer.Print(&buf, arg); err != nil {
			continue
		}
		if strings.TrimSpace(buf.String()) == "--" {
			return i + 1
		}
	}
	return -1
}

func (p *ShellParser) findVarInArg(node syntax.Node, varName string, cmdName string, argPos int, doubleDashPos int, usages *[]VarArgUsage) {
	if node == nil {
		return
	}

	switch x := node.(type) {
	case *syntax.Word:
		for _, part := range x.Parts {
			p.findVarInArg(part, varName, cmdName, argPos, doubleDashPos, usages)
		}
	case *syntax.DblQuoted:
		for _, part := range x.Parts {
			p.findVarInArg(part, varName, cmdName, argPos, doubleDashPos, usages)
		}
	case *syntax.ParamExp:
		if x.Param != nil && x.Param.Value == varName {
			usage := VarArgUsage{
				ShellVarUsage: ShellVarUsage{
					VarName:    varName,
					StartPos:   int(x.Pos().Offset()),
					EndPos:     int(x.End().Offset()),
					IsQuoted:   p.isParamExpQuoted(x),
					InEval:     false,
					InShellCmd: false,
					InCmdSubst: false,
					Context:    p.getContextFromPos(int(x.Pos().Offset()), int(x.End().Offset())),
				},
				CommandName:       cmdName,
				ArgPosition:       argPos,
				HasDoubleDash:     doubleDashPos != -1,
				IsAfterDoubleDash: doubleDashPos != -1 && argPos > doubleDashPos,
			}
			*usages = append(*usages, usage)
		}
		if x.Exp != nil && x.Exp.Word != nil {
			p.findVarInArg(x.Exp.Word, varName, cmdName, argPos, doubleDashPos, usages)
		}
	}
}
