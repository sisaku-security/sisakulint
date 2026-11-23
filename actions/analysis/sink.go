package analysis

import (
	"encoding/json"
	"errors"
)

// SinkKind is where a value is read as code.
type SinkKind uint8

const (
	SinkRun    SinkKind = iota // a step's run
	SinkScript                 // the script of actions/github-script
)

// sinkKindNames are the values of $defs/sink-kind of the schema of findings
// (actions/rules/schema/findings-v0.json), which the args of findings hold.
var sinkKindNames = [...]string{"run", "github-script"}

func (k SinkKind) String() string { return sinkKindNames[k] }

// MarshalJSON writes k as the schema of findings names it
// (findings-v0.json, $defs/sink-kind).
func (k SinkKind) MarshalJSON() ([]byte, error) { return json.Marshal(k.String()) }

// CodeReading is how bash, or a program bash gives a value to, reads the
// value of a variable of env as code (shell.CodeReading, as the args of
// findings name it).
type CodeReading uint8

const (
	CodeReadingUnset           CodeReading = iota
	CodeReadingCodeArgument                // an argument the command reads as code: an operand of eval, the code of -c
	CodeReadingCommandWord                 // the command word outside quotes, which bash splits into words
	CodeReadingCodeInput                   // what a command that runs its standard input as code reads
	CodeReadingArithmetic                  // arithmetic, whose subscripts run their command substitutions
	CodeReadingPromptExpansion             // ${NAME@P}, which expands the value as a prompt string and runs its command substitutions
)

var codeReadingNames = [...]string{"CodeReadingUnset", "CodeReadingCodeArgument", "CodeReadingCommandWord", "CodeReadingCodeInput", "CodeReadingArithmetic", "CodeReadingPromptExpansion"}

func (r CodeReading) String() string { return codeReadingNames[r] }

// codeReadingArgs are the values of $defs/code-reading of the schema of
// findings (actions/rules/schema/findings-v0.json), which the args of
// findings hold.
var codeReadingArgs = [...]string{"", "code-argument", "command-word", "code-input", "arithmetic", "prompt-expansion"}

// Arg is r as the schema of findings names it.
func (r CodeReading) Arg() string { return codeReadingArgs[r] }

// MarshalJSON writes r as the schema of findings names it;
// CodeReadingUnset has no name there.
func (r CodeReading) MarshalJSON() ([]byte, error) {
	if r == CodeReadingUnset {
		return nil, errors.New("CodeReadingUnset is no reading")
	}
	return json.Marshal(codeReadingArgs[r])
}

// EnvironmentFile is a file of the runner's file commands.
type EnvironmentFile uint8

const (
	EnvironmentFileUnset  EnvironmentFile = iota
	EnvironmentFileEnv                    // $GITHUB_ENV
	EnvironmentFileOutput                 // $GITHUB_OUTPUT
	EnvironmentFilePath                   // $GITHUB_PATH
)

var environmentFileNames = [...]string{"EnvironmentFileUnset", "GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH"}

func (f EnvironmentFile) String() string { return environmentFileNames[f] }

// Side is where a value written to a file command is, as the runner reads
// the file after the step: $GITHUB_ENV and $GITHUB_OUTPUT by lines split at
// \n alone, and each line by its first = or <<;
// $GITHUB_PATH by lines, each whole a directory.
type Side uint8

const (
	SideUnset Side = iota
	SideValue      // after the first = of a line: a line break in it starts another
	SideKey        // before the first = or << of a line, or a line with neither
	SideBody       // in the body of name<<DELIM whose delimiter an attacker can write
	SideLine       // anywhere on a line of $GITHUB_PATH, a directory of the PATH of the steps after
)

var sideNames = [...]string{"SideUnset", "SideValue", "SideKey", "SideBody", "SideLine"}

func (s Side) String() string { return sideNames[s] }
