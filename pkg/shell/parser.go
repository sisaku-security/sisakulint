package shell

import (
	"bytes"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

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
		if cmdName == "eval" {
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
			if cmdName == "eval" || p.isShellCommand(call) {
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
			if cmdName == "eval" {
				patternType = "eval"
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

// NetworkCommandCall represents a network command call found in the script
type NetworkCommandCall struct {
	CommandName string
	Args        []CommandArg
	Position    syntax.Pos
	InCmdSubst  bool
	InPipe      bool
}

// CommandArg represents a command argument
type CommandArg struct {
	Value    string
	Position syntax.Pos
	IsFlag   bool
	VarNames []string // Shell variables ($VAR)
	GHAExprs []string // GitHub Actions expressions (${{ }})
}

// FindNetworkCommands finds all network command calls in the script
func (p *ShellParser) FindNetworkCommands() []NetworkCommandCall {
	if p.file == nil {
		return nil
	}

	var calls []NetworkCommandCall
	ctx := &networkWalkContext{}
	p.walkForNetworkCommandsWithFallback(p.file, ctx, &calls)
	return calls
}

// networkWalkContext tracks context during network command search
type networkWalkContext struct {
	inCmdSubst bool
	inPipe     bool
}

// walkForNetworkCommandsWithFallback tries AST parsing first, falls back to regex on error
func (p *ShellParser) walkForNetworkCommandsWithFallback(node syntax.Node, ctx *networkWalkContext, calls *[]NetworkCommandCall) {
	if p.file != nil {
		p.walkForNetworkCommands(node, ctx, calls)
	}

	// If AST parsing failed or file is nil, try fallback regex-based detection on the original script
	if len(*calls) == 0 && p.script != "" {
		p.findNetworkCommandsByRegex(p.script, calls)
	}
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

		// Still traverse nested structures
		for _, arg := range x.Args {
			p.walkForNetworkCommands(arg, ctx, calls)
		}

	case *syntax.BinaryCmd:
		// Handle pipes
		newCtx := *ctx
		if x.Op == syntax.Pipe {
			newCtx.inPipe = true
		}
		p.walkForNetworkCommands(x.X, ctx, calls)
		p.walkForNetworkCommands(x.Y, &newCtx, calls)

	case *syntax.CmdSubst:
		newCtx := *ctx
		newCtx.inCmdSubst = true
		for _, stmt := range x.Stmts {
			p.walkForNetworkCommands(stmt, &newCtx, calls)
		}

	case *syntax.Word:
		for _, part := range x.Parts {
			p.walkForNetworkCommands(part, ctx, calls)
		}

	case *syntax.DblQuoted, *syntax.SglQuoted, *syntax.ParamExp, *syntax.Redirect:
		// Leaf nodes or handled separately
	}
}

// isNetworkCommand checks if the command is a network-related command
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

// parseNetworkCommand extracts arguments from a network command call
func (p *ShellParser) parseNetworkCommand(call *syntax.CallExpr, ctx *networkWalkContext) NetworkCommandCall {
	cmd := NetworkCommandCall{
		CommandName: p.getCommandName(call),
		Position:    call.Pos(),
		InCmdSubst:  ctx.inCmdSubst,
		InPipe:      ctx.inPipe,
	}

	// Parse arguments (skip command name at index 0)
	for i := 1; i < len(call.Args); i++ {
		arg := p.parseCommandArg(call.Args[i])
		cmd.Args = append(cmd.Args, arg)
	}

	return cmd
}

// parseCommandArg extracts information from a command argument
func (p *ShellParser) parseCommandArg(word *syntax.Word) CommandArg {
	arg := CommandArg{
		Value:    p.wordToString(word),
		Position: word.Pos(),
	}

	// Check if it's a flag
	if strings.HasPrefix(arg.Value, "-") {
		arg.IsFlag = true
	}

	// Extract variables and GitHub Actions expressions
	p.analyzeWordParts(word, &arg)

	return arg
}

// wordToString converts a Word node to its string representation
func (p *ShellParser) wordToString(word *syntax.Word) string {
	var buf bytes.Buffer
	printer := syntax.NewPrinter()
	if err := printer.Print(&buf, word); err != nil {
		return ""
	}
	return strings.TrimSpace(buf.String())
}

// analyzeWordParts extracts variables and GHA expressions from word parts
func (p *ShellParser) analyzeWordParts(word *syntax.Word, arg *CommandArg) {
	// Get the raw string value to search for ${{ }}
	rawValue := arg.Value

	// Extract GHA expressions (not parsed by shell parser)
	ghaExprs := extractGHAExpressionsFromString(rawValue)
	arg.GHAExprs = ghaExprs

	// Extract shell variables from AST
	syntax.Walk(word, func(node syntax.Node) bool {
		if paramExp, ok := node.(*syntax.ParamExp); ok {
			if paramExp.Param != nil && paramExp.Param.Value != "" {
				arg.VarNames = append(arg.VarNames, paramExp.Param.Value)
			}
		}
		return true
	})
}

// extractGHAExpressionsFromString extracts GitHub Actions expressions from a string
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

// findNetworkCommandsByRegex finds network commands using regex as fallback
func (p *ShellParser) findNetworkCommandsByRegex(script string, calls *[]NetworkCommandCall) {
	lines := strings.Split(script, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue // Skip comments
		}

		networkCmds := []string{"curl", "wget", "nc", "netcat"}
		for _, cmd := range networkCmds {
			if strings.Contains(line, cmd) {
				// Extract arguments after the command
				call := NetworkCommandCall{
					CommandName: cmd,
					Position:    syntax.Pos{},
				}

				// Find arguments containing ${{ }}
				ghaExprs := extractGHAExpressionsFromString(line)
				for _, expr := range ghaExprs {
					arg := CommandArg{
						Value:    expr,
						GHAExprs: []string{expr},
					}
					call.Args = append(call.Args, arg)
				}

				if len(call.Args) > 0 {
					*calls = append(*calls, call)
					break // Found this line's command
				}
			}
		}
	}
}
