package core

import (
	"bytes"
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
}

// NewShellParser creates a new shell parser
func NewShellParser(script string) *ShellParser {
	p := &ShellParser{script: script}

	// Parse the script into AST
	parser := syntax.NewParser(syntax.KeepComments(true), syntax.Variant(syntax.LangBash))
	reader := strings.NewReader(script)
	file, err := parser.Parse(reader, "")
	if err == nil {
		p.file = file
	}

	return p
}

// FindEnvVarUsages finds all usages of the specified environment variable in the script
func (p *ShellParser) FindEnvVarUsages(varName string) []ShellVarUsage {
	if p.file == nil {
		return nil
	}

	var usages []ShellVarUsage

	// Track context during AST walk
	var inEval, inShellCmd, inCmdSubst bool

	syntax.Walk(p.file, func(node syntax.Node) bool {
		switch x := node.(type) {
		case *syntax.CallExpr:
			cmdName := p.getCommandName(x)
			if cmdName == "eval" {
				inEval = true
			} else if p.isShellCommand(x) {
				inShellCmd = true
			}

		case *syntax.CmdSubst:
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

	return usages
}

// isParamExpQuoted checks if a parameter expansion is properly double-quoted
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
				if strings.TrimSpace(buf.String()) == "-c" {
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

// GetDangerousPatternType returns the type of dangerous pattern found
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
