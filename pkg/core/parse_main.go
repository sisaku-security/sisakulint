package core

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

type parser struct {
	errors []*LintingError
}

func (project *parser) parse(node *yaml.Node) *ast.Workflow {
	workflow := &ast.Workflow{BaseNode: node}

	if node.Line == 0 {
		node.Line = 1
	}
	if node.Column == 0 {
		node.Column = 1
	}

	if len(node.Content) == 0 {
		project.error(node, "empty workflow")
		return workflow
	}

	mappings := project.parseMapping("workflow", node.Content[0], false, true)

	for _, mapping := range mappings {
		key := mapping.key
		valueNode := mapping.val

		switch mapping.id {
		case MainName:
			workflow.Name = project.parseString(valueNode, true)

		case SBOMDescription:
			workflow.Description = project.parseString(valueNode, true)

		//*https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#on
		case "on":
			workflow.On = project.parseEvents(key.Pos, valueNode)

		//*https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#permissions
		case "permissions":
			workflow.Permissions = project.parsePermissions(key.Pos, valueNode)

		//*https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#env
		case AvailableEnv:
			workflow.Env = project.parseEnv(valueNode)

		//*https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#defaults
		case "defaults":
			workflow.Defaults = project.parseDefaults(key.Pos, valueNode)

		//*https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#concurrency
		case "concurrency":
			workflow.Concurrency = project.parseConcurrency(key.Pos, valueNode)

		//*https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobs
		case "jobs":
			workflow.Jobs = project.parseJobs(valueNode)

		//*https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#run-name
		case "run-name":
			workflow.RunName = project.parseString(valueNode, false)
		default:
			allowedKeys := []string{"name", "description", "on", "permissions", "env", "defaults", "concurrency", "jobs", "run-name"}
			project.unexpectedKey(key, "workflow", allowedKeys)
		}
	}
	if workflow.On == nil {
		project.error(node, "section is missing required key \"on\"")
	}
	if workflow.Jobs == nil {
		project.error(node, "section is missing required key \"jobs\"")
	}
	return workflow
}

// handleYamlErrorはyamlのエラーを処理する
// yaml.v3のエラーを返す
func handleYamlError(err error) []*LintingError {
	lineNumberPattern := regexp.MustCompile(`\bline (\d+)\b`)

	//convertToErrorはyaml.v3のエラーをLintingErrorに変換する
	convertToError := func(msg string) *LintingError {
		lineNumber := 0
		if matches := lineNumberPattern.FindStringSubmatch(msg); len(matches) > 1 {
			lineNumber, _ = strconv.Atoi(matches[1])
		}
		msg = fmt.Sprintf("it could not parse as YAML: %s", msg)
		return &LintingError{msg, "", lineNumber, 0, "syntax"}
	}

	var typeError *yaml.TypeError
	if errors.As(err, &typeError) {
		errors := make([]*LintingError, 0, len(typeError.Errors))
		for _, errMsg := range typeError.Errors {
			errors = append(errors, convertToError(errMsg))
		}
		return errors
	}
	return []*LintingError{convertToError(err.Error())}
}

// Parse : byteで与えられたソースをworkflowの構文木に解析する
// 入力を解析しながら検出されたエラーを全部返す:解析を途中でやめない
// parserはエラーがあっても最後まで解析をしてエラーとなる部分をファイルから全部抽出する
func Parse(sourceContent []byte) (*ast.Workflow, []*LintingError) {
	var node yaml.Node
	if err := yaml.Unmarshal(sourceContent, &node); err != nil {
		return nil, handleYamlError(err)
	}

	parserInstance := &parser{}
	workflow := parserInstance.parse(&node)

	return workflow, parserInstance.errors
}
