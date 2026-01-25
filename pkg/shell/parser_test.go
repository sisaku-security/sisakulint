package shell

import (
	"testing"
)

func TestShellParser_FindEnvVarUsages(t *testing.T) {
	tests := []struct {
		name       string
		script     string
		varName    string
		wantCount  int
		wantQuoted []bool
		wantInEval []bool
		wantInCmd  []bool
	}{
		{
			name:       "simple unquoted variable",
			script:     "echo $MY_VAR",
			varName:    "MY_VAR",
			wantCount:  1,
			wantQuoted: []bool{false},
		},
		{
			name:       "double quoted variable",
			script:     `echo "$MY_VAR"`,
			varName:    "MY_VAR",
			wantCount:  1,
			wantQuoted: []bool{true},
		},
		{
			name:       "braced variable",
			script:     "echo ${MY_VAR}",
			varName:    "MY_VAR",
			wantCount:  1,
			wantQuoted: []bool{false},
		},
		{
			name:       "braced quoted variable",
			script:     `echo "${MY_VAR}"`,
			varName:    "MY_VAR",
			wantCount:  1,
			wantQuoted: []bool{true},
		},
		{
			name:       "variable in eval",
			script:     `eval "echo $MY_VAR"`,
			varName:    "MY_VAR",
			wantCount:  1,
			wantQuoted: []bool{true},
			wantInEval: []bool{true},
		},
		{
			name:       "variable in sh -c",
			script:     `sh -c "echo $MY_VAR"`,
			varName:    "MY_VAR",
			wantCount:  1,
			wantQuoted: []bool{true},
			wantInCmd:  []bool{true},
		},
		{
			name:       "variable in bash -c with double quotes",
			script:     `bash -c "echo $MY_VAR"`,
			varName:    "MY_VAR",
			wantCount:  1,
			wantQuoted: []bool{true}, // double-quoted in AST
			wantInCmd:  []bool{true},
		},
		{
			name:       "multiple usages mixed",
			script:     `echo $MY_VAR; echo "$MY_VAR"`,
			varName:    "MY_VAR",
			wantCount:  2,
			wantQuoted: []bool{false, true},
		},
		{
			name:      "variable not found",
			script:    "echo $OTHER_VAR",
			varName:   "MY_VAR",
			wantCount: 0,
		},
		{
			name:       "multiline script with unquoted var",
			script:     "echo \"start\"\necho $TITLE\necho \"end\"",
			varName:    "TITLE",
			wantCount:  1,
			wantQuoted: []bool{false},
		},
		{
			name:       "variable in command substitution",
			script:     `result=$(echo $MY_VAR)`,
			varName:    "MY_VAR",
			wantCount:  1,
			wantQuoted: []bool{false},
		},
		{
			name:       "context reset after eval",
			script:     "eval \"echo $MY_VAR\"\necho $MY_VAR",
			varName:    "MY_VAR",
			wantCount:  2,
			wantQuoted: []bool{true, false},
			wantInEval: []bool{true, false}, // second usage should NOT be in eval
		},
		{
			name:       "context reset after sh -c",
			script:     "sh -c \"echo $MY_VAR\"\necho $MY_VAR",
			varName:    "MY_VAR",
			wantCount:  2,
			wantQuoted: []bool{true, false},
			wantInCmd:  []bool{true, false}, // second usage should NOT be in shell cmd
		},
		{
			name:       "context reset after command substitution",
			script:     "result=$(echo $MY_VAR)\necho $MY_VAR",
			varName:    "MY_VAR",
			wantCount:  2,
			wantQuoted: []bool{false, false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewShellParser(tt.script)
			usages := parser.FindEnvVarUsages(tt.varName)

			if len(usages) != tt.wantCount {
				t.Errorf("got %d usages, want %d", len(usages), tt.wantCount)
				return
			}

			for i, usage := range usages {
				if i < len(tt.wantQuoted) && usage.IsQuoted != tt.wantQuoted[i] {
					t.Errorf("usage[%d].IsQuoted = %v, want %v", i, usage.IsQuoted, tt.wantQuoted[i])
				}

				if tt.wantInEval != nil && i < len(tt.wantInEval) && usage.InEval != tt.wantInEval[i] {
					t.Errorf("usage[%d].InEval = %v, want %v", i, usage.InEval, tt.wantInEval[i])
				}

				if tt.wantInCmd != nil && i < len(tt.wantInCmd) && usage.InShellCmd != tt.wantInCmd[i] {
					t.Errorf("usage[%d].InShellCmd = %v, want %v", i, usage.InShellCmd, tt.wantInCmd[i])
				}
			}
		})
	}
}

func TestShellVarUsage_IsUnsafeUsage(t *testing.T) {
	tests := []struct {
		name   string
		usage  ShellVarUsage
		unsafe bool
	}{
		{
			name: "properly quoted",
			usage: ShellVarUsage{
				IsQuoted:   true,
				InEval:     false,
				InShellCmd: false,
				InCmdSubst: false,
			},
			unsafe: false,
		},
		{
			name: "unquoted",
			usage: ShellVarUsage{
				IsQuoted:   false,
				InEval:     false,
				InShellCmd: false,
				InCmdSubst: false,
			},
			unsafe: true,
		},
		{
			name: "quoted but in eval",
			usage: ShellVarUsage{
				IsQuoted:   true,
				InEval:     true,
				InShellCmd: false,
				InCmdSubst: false,
			},
			unsafe: true,
		},
		{
			name: "quoted but in sh -c",
			usage: ShellVarUsage{
				IsQuoted:   true,
				InEval:     false,
				InShellCmd: true,
				InCmdSubst: false,
			},
			unsafe: true,
		},
		{
			name: "quoted in command substitution - safe",
			usage: ShellVarUsage{
				IsQuoted:   true,
				InEval:     false,
				InShellCmd: false,
				InCmdSubst: true,
			},
			unsafe: false,
		},
		{
			name: "unquoted in command substitution - unsafe",
			usage: ShellVarUsage{
				IsQuoted:   false,
				InEval:     false,
				InShellCmd: false,
				InCmdSubst: true,
			},
			unsafe: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.usage.IsUnsafeUsage(); got != tt.unsafe {
				t.Errorf("IsUnsafeUsage() = %v, want %v", got, tt.unsafe)
			}
		})
	}
}

func TestShellParser_HasDangerousPattern(t *testing.T) {
	tests := []struct {
		name      string
		script    string
		dangerous bool
	}{
		{
			name:      "simple echo",
			script:    "echo hello",
			dangerous: false,
		},
		{
			name:      "eval command",
			script:    "eval $cmd",
			dangerous: true,
		},
		{
			name:      "sh -c command",
			script:    `sh -c "echo hello"`,
			dangerous: true,
		},
		{
			name:      "bash -c command",
			script:    `bash -c "echo hello"`,
			dangerous: true,
		},
		{
			name:      "dash -c command",
			script:    `dash -c "echo hello"`,
			dangerous: true,
		},
		{
			name:      "eval in multiline",
			script:    "echo start\neval \"$cmd\"\necho end",
			dangerous: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewShellParser(tt.script)
			if got := parser.HasDangerousPattern(); got != tt.dangerous {
				t.Errorf("HasDangerousPattern() = %v, want %v", got, tt.dangerous)
			}
		})
	}
}

func TestShellParser_GetDangerousPatternType(t *testing.T) {
	tests := []struct {
		name        string
		script      string
		patternType string
	}{
		{
			name:        "eval command",
			script:      "eval $cmd",
			patternType: "eval",
		},
		{
			name:        "sh -c command",
			script:      `sh -c "echo hello"`,
			patternType: "sh -c",
		},
		{
			name:        "bash -c command",
			script:      `bash -c "echo hello"`,
			patternType: "bash -c",
		},
		{
			name:        "no dangerous pattern",
			script:      "echo hello",
			patternType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewShellParser(tt.script)
			if got := parser.GetDangerousPatternType(); got != tt.patternType {
				t.Errorf("GetDangerousPatternType() = %v, want %v", got, tt.patternType)
			}
		})
	}
}

func TestShellParser_CommandSubstitution(t *testing.T) {
	tests := []struct {
		name       string
		script     string
		varName    string
		inCmdSubst bool
	}{
		{
			name:       "variable in $() substitution",
			script:     `result=$(echo $MY_VAR)`,
			varName:    "MY_VAR",
			inCmdSubst: true,
		},
		{
			name:       "variable in backtick substitution",
			script:     "result=`echo $MY_VAR`",
			varName:    "MY_VAR",
			inCmdSubst: true,
		},
		{
			name:       "variable outside substitution",
			script:     `echo $MY_VAR`,
			varName:    "MY_VAR",
			inCmdSubst: false,
		},
		{
			name:       "nested $() substitution",
			script:     `result=$(echo $(cat $MY_VAR))`,
			varName:    "MY_VAR",
			inCmdSubst: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewShellParser(tt.script)
			usages := parser.FindEnvVarUsages(tt.varName)

			if len(usages) == 0 {
				t.Fatal("expected to find variable usage")
			}

			if usages[0].InCmdSubst != tt.inCmdSubst {
				t.Errorf("InCmdSubst = %v, want %v", usages[0].InCmdSubst, tt.inCmdSubst)
			}
		})
	}
}

// TestShellParser_ComplexShellSyntax tests complex shell constructs using mvdan/sh
func TestShellParser_ComplexShellSyntax(t *testing.T) {
	tests := []struct {
		name       string
		script     string
		varName    string
		wantCount  int
		wantQuoted []bool
	}{
		{
			name: "heredoc with variable",
			script: `cat <<EOF
Hello $MY_VAR
EOF`,
			varName:    "MY_VAR",
			wantCount:  1,
			wantQuoted: []bool{false},
		},
		{
			name:       "array expansion",
			script:     `echo "${MY_VAR[@]}"`,
			varName:    "MY_VAR",
			wantCount:  1,
			wantQuoted: []bool{true},
		},
		{
			name:       "parameter expansion with default",
			script:     `echo ${MY_VAR:-default}`,
			varName:    "MY_VAR",
			wantCount:  1,
			wantQuoted: []bool{false},
		},
		{
			name:       "variable in for loop",
			script:     `for i in $MY_VAR; do echo $i; done`,
			varName:    "MY_VAR",
			wantCount:  1,
			wantQuoted: []bool{false},
		},
		{
			name:       "variable in if condition",
			script:     `if [ -n "$MY_VAR" ]; then echo ok; fi`,
			varName:    "MY_VAR",
			wantCount:  1,
			wantQuoted: []bool{true},
		},
		{
			name:       "variable in case statement",
			script:     `case $MY_VAR in *) echo match;; esac`,
			varName:    "MY_VAR",
			wantCount:  1,
			wantQuoted: []bool{false},
		},
		{
			name: "function with variable",
			script: `myfunc() {
  echo $MY_VAR
}`,
			varName:    "MY_VAR",
			wantCount:  1,
			wantQuoted: []bool{false},
		},
		{
			name:       "process substitution",
			script:     `diff <(echo $MY_VAR) <(echo test)`,
			varName:    "MY_VAR",
			wantCount:  1,
			wantQuoted: []bool{false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewShellParser(tt.script)
			usages := parser.FindEnvVarUsages(tt.varName)

			if len(usages) != tt.wantCount {
				t.Errorf("got %d usages, want %d", len(usages), tt.wantCount)
				return
			}

			for i, usage := range usages {
				if i < len(tt.wantQuoted) && usage.IsQuoted != tt.wantQuoted[i] {
					t.Errorf("usage[%d].IsQuoted = %v, want %v", i, usage.IsQuoted, tt.wantQuoted[i])
				}
			}
		})
	}
}

// TestShellParser_DangerousPatterns tests detection of dangerous shell patterns
func TestShellParser_DangerousPatterns(t *testing.T) {
	tests := []struct {
		name        string
		script      string
		dangerous   bool
		patternType string
	}{
		{
			name:        "direct sh -c command",
			script:      `sh -c 'echo test'`,
			dangerous:   true,
			patternType: "sh -c",
		},
		{
			name:        "eval with command substitution",
			script:      `eval "$(generate_cmd)"`,
			dangerous:   true,
			patternType: "eval",
		},
		{
			name:        "bash -c command",
			script:      `bash -c 'echo test'`,
			dangerous:   true,
			patternType: "bash -c",
		},
		{
			name:        "dash -c command",
			script:      `dash -c 'echo test'`,
			dangerous:   true,
			patternType: "dash -c",
		},
		{
			name:        "eval with variable",
			script:      `eval "$cmd"`,
			dangerous:   true,
			patternType: "eval",
		},
		{
			name:        "safe command",
			script:      `echo "Hello World" | grep "Hello"`,
			dangerous:   false,
			patternType: "",
		},
		{
			name:        "safe pipe",
			script:      `cat file.txt | sort | uniq`,
			dangerous:   false,
			patternType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewShellParser(tt.script)

			if got := parser.HasDangerousPattern(); got != tt.dangerous {
				t.Errorf("HasDangerousPattern() = %v, want %v", got, tt.dangerous)
			}

			if got := parser.GetDangerousPatternType(); got != tt.patternType {
				t.Errorf("GetDangerousPatternType() = %v, want %v", got, tt.patternType)
			}
		})
	}
}
