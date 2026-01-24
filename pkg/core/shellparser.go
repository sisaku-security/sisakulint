package core

import (
	"bytes"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ShellVarUsage represents how an environment variable is used in a shell script
type ShellVarUsage struct {
	VarName    string // Variable name (e.g., "MY_VAR")
	StartPos   int    // Start position in the script
	EndPos     int    // End position in the script
	IsQuoted   bool   // Whether the variable is properly double-quoted
	InEval     bool   // Whether it's inside eval
	InShellCmd bool   // Whether it's inside sh -c, bash -c, etc.
	InCmdSubst bool   // Whether it's inside $() or ``
	Context    string // Surrounding context for debugging
}

// ShellParser provides utilities for parsing shell scripts using mvdan/sh
type ShellParser struct {
	script string
	file   *syntax.File
	parser *syntax.Parser
}

// NewShellParser creates a new shell parser
func NewShellParser(script string) *ShellParser {
	p := &ShellParser{
		script: script,
		parser: syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash)),
	}

	// Parse the script into AST
	reader := strings.NewReader(script)
	file, err := p.parser.Parse(reader, "")
	if err == nil {
		p.file = file
	}

	return p
}

// shellCommandPatterns matches dangerous shell execution patterns (for fallback)
var shellCommandPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\beval\s+`),
	regexp.MustCompile(`\b(?:sh|bash|zsh|ksh|dash)\s+-c\s+`),
}

// envVarPattern matches environment variable references: $VAR or ${VAR} (for fallback)
var envVarPattern = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)

// FindEnvVarUsages finds all usages of the specified environment variable in the script
func (p *ShellParser) FindEnvVarUsages(varName string) []ShellVarUsage {
	if p.file == nil {
		// Fallback to regex-based parsing if AST parsing failed
		return p.findEnvVarUsagesFallback(varName)
	}

	var usages []ShellVarUsage

	// Track context during AST walk
	var inEval, inShellCmd, inCmdSubst bool
	var evalDepth, shellCmdDepth, cmdSubstDepth int

	syntax.Walk(p.file, func(node syntax.Node) bool {
		switch x := node.(type) {
		case *syntax.CallExpr:
			// Check if this is eval or sh -c
			cmdName := p.getCommandName(x)
			if cmdName == "eval" {
				evalDepth++
				inEval = true
			} else if p.isShellCommand(x) {
				shellCmdDepth++
				inShellCmd = true
			}

		case *syntax.CmdSubst:
			cmdSubstDepth++
			inCmdSubst = true

		case *syntax.ParamExp:
			if x.Param != nil && x.Param.Value == varName {
				usage := ShellVarUsage{
					VarName:    varName,
					StartPos:   int(x.Pos().Offset()),
					EndPos:     int(x.End().Offset()),
					IsQuoted:   p.isParamExpQuoted(x),
					InEval:     inEval,
					InShellCmd: inShellCmd,
					InCmdSubst: inCmdSubst,
					Context:    p.getContextFromPos(int(x.Pos().Offset()), int(x.End().Offset())),
				}
				usages = append(usages, usage)
			}
		}
		return true
	})

	// If no usages found via AST but script contains the variable, fallback
	if len(usages) == 0 && strings.Contains(p.script, "$"+varName) {
		return p.findEnvVarUsagesFallback(varName)
	}

	return usages
}

// isParamExpQuoted checks if a parameter expansion is properly double-quoted
func (p *ShellParser) isParamExpQuoted(pe *syntax.ParamExp) bool {
	var quoted bool

	syntax.Walk(p.file, func(node syntax.Node) bool {
		switch x := node.(type) {
		case *syntax.DblQuoted:
			for _, part := range x.Parts {
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

// getCommandName extracts the command name from a CallExpr
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

// isShellCommand checks if a CallExpr is a shell invocation (sh -c, bash -c, etc.)
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
				arg := strings.TrimSpace(buf.String())
				if arg == "-c" {
					return true
				}
			}
		}
	}
	return false
}

// getContextFromPos returns the surrounding line for error messages
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
		contextStart := relStart - 30
		if contextStart < 0 {
			contextStart = 0
		}
		contextEnd := relStart + 50
		if contextEnd > len(line) {
			contextEnd = len(line)
		}
		line = "..." + line[contextStart:contextEnd] + "..."
	}

	return strings.TrimSpace(line)
}

// findEnvVarUsagesFallback uses regex for scripts that can't be parsed
func (p *ShellParser) findEnvVarUsagesFallback(varName string) []ShellVarUsage {
	matches := envVarPattern.FindAllStringSubmatchIndex(p.script, -1)
	usages := make([]ShellVarUsage, 0, len(matches))

	for _, match := range matches {
		if len(match) < 4 {
			continue
		}

		fullStart := match[0]
		fullEnd := match[1]
		nameStart := match[2]
		nameEnd := match[3]

		foundVar := p.script[nameStart:nameEnd]
		if foundVar != varName {
			continue
		}

		usage := ShellVarUsage{
			VarName:    foundVar,
			StartPos:   fullStart,
			EndPos:     fullEnd,
			IsQuoted:   p.isQuotedAtPos(fullStart, fullEnd),
			InEval:     p.isInEvalAtPos(fullStart),
			InShellCmd: p.isInShellCommandAtPos(fullStart),
			InCmdSubst: p.isInCmdSubstAtPos(fullStart),
			Context:    p.getContextFromPos(fullStart, fullEnd),
		}
		usages = append(usages, usage)
	}

	return usages
}

// isQuotedAtPos checks if position is inside double quotes (fallback)
func (p *ShellParser) isQuotedAtPos(start, end int) bool {
	doubleQuotes := 0
	singleQuotes := 0
	escaped := false

	for i := 0; i < start; i++ {
		c := p.script[i]
		if escaped {
			escaped = false
			continue
		}

		if c == '\\' {
			escaped = true
			continue
		}

		if c == '\'' && doubleQuotes%2 == 0 {
			singleQuotes++
		}

		if c == '"' && singleQuotes%2 == 0 {
			doubleQuotes++
		}
	}

	isInsideDoubleQuotes := doubleQuotes%2 == 1 && singleQuotes%2 == 0

	if isInsideDoubleQuotes {
		afterVar := p.script[end:]
		quotesAfter := 0
		escapedAfter := false

		for i := 0; i < len(afterVar); i++ {
			c := afterVar[i]
			if escapedAfter {
				escapedAfter = false
				continue
			}

			if c == '\\' {
				escapedAfter = true
				continue
			}

			if c == '"' {
				quotesAfter++
				break
			}
		}

		return quotesAfter > 0
	}

	return false
}

// isInEvalAtPos checks if position is inside eval (fallback)
func (p *ShellParser) isInEvalAtPos(pos int) bool {
	before := p.script[:pos]
	lastSep := strings.LastIndexAny(before, "\n;")
	if lastSep == -1 {
		lastSep = 0
	}
	commandPart := before[lastSep:]
	evalPattern := regexp.MustCompile(`\beval\s+`)
	return evalPattern.MatchString(commandPart)
}

// isInShellCommandAtPos checks if position is inside sh -c (fallback)
func (p *ShellParser) isInShellCommandAtPos(pos int) bool {
	before := p.script[:pos]
	lastSep := strings.LastIndexAny(before, "\n;|&")
	if lastSep == -1 {
		lastSep = 0
	}
	commandPart := before[lastSep:]
	shellPattern := regexp.MustCompile(`\b(?:sh|bash|zsh|ksh|dash)\s+-c\s+`)
	return shellPattern.MatchString(commandPart)
}

// isInCmdSubstAtPos checks if position is inside $() or `` (fallback)
func (p *ShellParser) isInCmdSubstAtPos(pos int) bool {
	parenDepth := 0
	dollarParenStart := -1

	for i := 0; i < pos; i++ {
		if i > 0 && p.script[i-1] == '$' && p.script[i] == '(' {
			parenDepth++
			dollarParenStart = i - 1
		} else if p.script[i] == ')' && parenDepth > 0 {
			parenDepth--
		}
	}

	if parenDepth > 0 && dollarParenStart >= 0 {
		return true
	}

	backtickCount := 0
	for i := 0; i < pos; i++ {
		if p.script[i] == '`' {
			escaped := false
			for j := i - 1; j >= 0 && p.script[j] == '\\'; j-- {
				escaped = !escaped
			}
			if !escaped {
				backtickCount++
			}
		}
	}
	return backtickCount%2 == 1
}

// IsUnsafeUsage checks if a variable usage is potentially unsafe
func (u *ShellVarUsage) IsUnsafeUsage() bool {
	if !u.IsQuoted {
		return true
	}

	if u.InEval {
		return true
	}

	if u.InShellCmd {
		return true
	}

	if u.InCmdSubst {
		return true
	}

	return false
}

// HasDangerousPattern checks if the script contains dangerous patterns like eval or sh -c
func (p *ShellParser) HasDangerousPattern() bool {
	// Always check with string matching first for patterns that might be in command arguments
	// (e.g., xargs sh -c, find -exec sh -c)
	for _, pattern := range shellCommandPatterns {
		if pattern.MatchString(p.script) {
			return true
		}
	}

	if p.file != nil {
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
		if found {
			return true
		}
	}

	return false
}

// GetDangerousPatternType returns the type of dangerous pattern found
func (p *ShellParser) GetDangerousPatternType() string {
	// Check string patterns first (for patterns in command arguments like xargs sh -c)
	if regexp.MustCompile(`\beval\s+`).MatchString(p.script) {
		return "eval"
	}

	// Check longer shell names first to avoid "sh -c" matching inside "bash -c"
	shells := []string{"bash", "dash", "zsh", "ksh", "sh"}
	for _, shell := range shells {
		shellPattern := regexp.MustCompile(`\b` + shell + `\s+-c\s+`)
		if shellPattern.MatchString(p.script) {
			return shell + " -c"
		}
	}

	// Also check via AST for direct command calls
	if p.file != nil {
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
		if patternType != "" {
			return patternType
		}
	}

	return ""
}
