package core

import (
	"regexp"
	"strings"
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

// ShellParser provides utilities for parsing shell scripts
type ShellParser struct {
	script string
}

// NewShellParser creates a new shell parser
func NewShellParser(script string) *ShellParser {
	return &ShellParser{script: script}
}

// shellCommandPatterns matches dangerous shell execution patterns
var shellCommandPatterns = []*regexp.Regexp{
	// eval "..." or eval '...' or eval $...
	regexp.MustCompile(`\beval\s+`),
	// sh -c, bash -c, zsh -c, ksh -c, dash -c
	regexp.MustCompile(`\b(?:sh|bash|zsh|ksh|dash)\s+-c\s+`),
}

// envVarPattern matches environment variable references: $VAR or ${VAR}
var envVarPattern = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)

// FindEnvVarUsages finds all usages of the specified environment variable in the script
func (p *ShellParser) FindEnvVarUsages(varName string) []ShellVarUsage {
	// Find all $VAR and ${VAR} patterns
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
			VarName:  foundVar,
			StartPos: fullStart,
			EndPos:   fullEnd,
		}

		// Check if properly quoted
		usage.IsQuoted = p.isProperlyQuoted(fullStart, fullEnd)

		// Check if in eval
		usage.InEval = p.isInEval(fullStart)

		// Check if in sh -c, bash -c, etc.
		usage.InShellCmd = p.isInShellCommand(fullStart)

		// Check if in command substitution
		usage.InCmdSubst = p.isInCommandSubstitution(fullStart, fullEnd)

		// Get surrounding context (for error messages)
		usage.Context = p.getSurroundingContext(fullStart, fullEnd)

		usages = append(usages, usage)
	}

	return usages
}

// IsUnsafeUsage checks if a variable usage is potentially unsafe
func (u *ShellVarUsage) IsUnsafeUsage() bool {
	// Unquoted usage is unsafe
	if !u.IsQuoted {
		return true
	}

	// Usage inside eval is unsafe even when quoted
	if u.InEval {
		return true
	}

	// Usage inside sh -c is unsafe even when quoted (shell parses again)
	if u.InShellCmd {
		return true
	}

	// Usage inside command substitution is unsafe even when quoted
	if u.InCmdSubst {
		return true
	}

	return false
}

// isProperlyQuoted checks if the variable at the given position is properly double-quoted
func (p *ShellParser) isProperlyQuoted(start, end int) bool {
	// Count unescaped double quotes before the position
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

	// If we're inside an odd number of double quotes, we're quoted
	// If we're inside single quotes, variable expansion doesn't happen (so it's "safe" in a different way)
	isInsideDoubleQuotes := doubleQuotes%2 == 1 && singleQuotes%2 == 0

	// Also need to verify the closing quote exists after the variable
	if isInsideDoubleQuotes {
		// Check there's a closing quote after the variable
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

// isInEval checks if the position is inside an eval command
func (p *ShellParser) isInEval(pos int) bool {
	// Look backward for 'eval' followed by the variable
	before := p.script[:pos]

	// Find the last newline or semicolon (command separator)
	lastSep := strings.LastIndexAny(before, "\n;")
	if lastSep == -1 {
		lastSep = 0
	}

	commandPart := before[lastSep:]

	// Check if 'eval' appears in this command part
	evalPattern := regexp.MustCompile(`\beval\s+`)
	return evalPattern.MatchString(commandPart)
}

// isInShellCommand checks if the position is inside sh -c, bash -c, etc.
func (p *ShellParser) isInShellCommand(pos int) bool {
	before := p.script[:pos]

	// Find the last command separator
	lastSep := strings.LastIndexAny(before, "\n;|&")
	if lastSep == -1 {
		lastSep = 0
	}

	commandPart := before[lastSep:]

	// Check for shell command patterns
	shellPattern := regexp.MustCompile(`\b(?:sh|bash|zsh|ksh|dash)\s+-c\s+`)
	return shellPattern.MatchString(commandPart)
}

// isInCommandSubstitution checks if the position is inside $() or “
func (p *ShellParser) isInCommandSubstitution(start, end int) bool {
	// Check for $() substitution
	parenDepth := 0
	dollarParenStart := -1

	for i := 0; i < start; i++ {
		if i > 0 && p.script[i-1] == '$' && p.script[i] == '(' {
			parenDepth++
			dollarParenStart = i - 1
		} else if p.script[i] == ')' && parenDepth > 0 {
			parenDepth--
		}
	}

	if parenDepth > 0 {
		// Verify there's a closing paren after
		remaining := p.script[end:]
		depth := parenDepth
		for i := 0; i < len(remaining) && depth > 0; i++ {
			if remaining[i] == ')' {
				depth--
			} else if i > 0 && remaining[i-1] == '$' && remaining[i] == '(' {
				depth++
			}
		}
		if dollarParenStart >= 0 && depth == 0 {
			return true
		}
	}

	// Check for backtick substitution
	backtickCount := 0
	for i := 0; i < start; i++ {
		if p.script[i] == '`' {
			// Check if escaped
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

// getSurroundingContext returns the surrounding context for error messages
func (p *ShellParser) getSurroundingContext(start, end int) string {
	// Get surrounding line
	lineStart := strings.LastIndex(p.script[:start], "\n")
	if lineStart == -1 {
		lineStart = 0
	} else {
		lineStart++ // Skip the newline itself
	}

	lineEnd := strings.Index(p.script[end:], "\n")
	if lineEnd == -1 {
		lineEnd = len(p.script)
	} else {
		lineEnd += end
	}

	line := p.script[lineStart:lineEnd]

	// Truncate if too long
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

// HasDangerousPattern checks if the script contains dangerous patterns like eval or sh -c
func (p *ShellParser) HasDangerousPattern() bool {
	for _, pattern := range shellCommandPatterns {
		if pattern.MatchString(p.script) {
			return true
		}
	}
	return false
}

// GetDangerousPatternType returns the type of dangerous pattern found
func (p *ShellParser) GetDangerousPatternType() string {
	before := p.script

	if regexp.MustCompile(`\beval\s+`).MatchString(before) {
		return "eval"
	}

	shellPattern := regexp.MustCompile(`\b(sh|bash|zsh|ksh|dash)\s+-c\s+`)
	match := shellPattern.FindStringSubmatch(before)
	if len(match) > 1 {
		return match[1] + " -c"
	}

	return ""
}
