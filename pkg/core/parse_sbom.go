package core

import (
	"fmt"
	"strconv"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

// https://pkg.go.dev/gopkg.in/yaml.v3#Kind
func nodeKindName(k yaml.Kind) string {
	switch k {
	case yaml.DocumentNode:
		return "document"
	case yaml.SequenceNode:
		return "sequence"
	case yaml.MappingNode:
		return "mapping"
	case yaml.ScalarNode:
		return "scalar"
	case yaml.AliasNode:
		return "alias"
	default:
		panic(fmt.Sprintf("unreachable: unknown YAML kind: %v", k))
	}
}

func (project *parser) error(node *yaml.Node, msg string) {
	project.errors = append(project.errors, &LintingError{msg, "", node.Line, node.Column, "syntax"})
}

func (project *parser) errorAt(position *ast.Position, msg string) {
	project.errors = append(project.errors, &LintingError{msg, "", position.Line, position.Col, "syntax"})
}

func (project *parser) errorf(node *yaml.Node, format string, args ...interface{}) {
	m := fmt.Sprintf(format, args...)
	project.error(node, m)
}

func (project *parser) errorfAt(position *ast.Position, format string, args ...interface{}) {
	m := fmt.Sprintf(format, args...)
	project.errorAt(position, m)
}

func positionAt(node *yaml.Node) *ast.Position {
	return &ast.Position{Line: node.Line, Col: node.Column}
}

// dereferenceAlias returns the target node if the given node is an alias, otherwise returns the node itself
func dereferenceAlias(node *yaml.Node) *yaml.Node {
	if node.Kind == yaml.AliasNode {
		if node.Alias != nil {
			return node.Alias
		}
	}
	return node
}

func isNull(node *yaml.Node) bool {
	return node.Kind == yaml.ScalarNode && node.Tag == SBOMNullTag
}

func newString(node *yaml.Node) *ast.String {
	quoted := node.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0
	literal := node.Style&yaml.LiteralStyle != 0
	return &ast.String{Value: node.Value, Quoted: quoted, Literal: literal, Pos: positionAt(node), BaseNode: node}
}

type workflowKeyValue struct {
	//id はkeyの比較に使用される
	id string
	//key はkeyの値を表す
	key *ast.String
	//val はkeyに対応するvalueを表す
	val *yaml.Node
}

func (project *parser) checkString(node *yaml.Node, allowEmpty bool) bool {
	//do not check node.Tag
	if node.Kind != yaml.ScalarNode {
		project.errorf(node, "expected scalar node for string value but found %s node with %q tag", nodeKindName(node.Kind), node.Tag)
		return false
	}
	if !allowEmpty && node.Value == "" {
		project.error(node, "expected non-empty string")
		return false
	}
	return true
}

func (project *parser) checkNotEmpty(sec string, len int, node *yaml.Node) bool {
	if len == 0 {
		project.errorf(node, "%q section is empty", sec)
		return false
	}
	return true
}

func (project *parser) checkSequence(sec string, node *yaml.Node, allowEmpty bool) bool {
	if node.Kind != yaml.SequenceNode {
		project.errorf(node, "expected sequence node for %q but found %s node with %q tag", sec, nodeKindName(node.Kind), node.Tag)
		return false
	}
	if !allowEmpty && len(node.Content) == 0 {
		project.errorf(node, "expected non-empty sequence for %s", sec)
		return false
	}
	return allowEmpty || project.checkNotEmpty(sec, len(node.Content), node)
}

func (project *parser) parseSectionMapping(sec string, node *yaml.Node, allowEmpty, caseSensitive bool) []workflowKeyValue {
	return project.parseMapping(fmt.Sprintf("%q section", sec), node, allowEmpty, caseSensitive)
}

func (project *parser) parseScheduleEvent(pos *ast.Position, node *yaml.Node) *ast.ScheduledEvent {
	if ok := project.checkSequence("schedule", node, false); !ok {
		return nil
	}

	cron := make([]*ast.String, 0, len(node.Content))
	for _, n := range node.Content {
		m := project.parseMapping("element of \"schedule\" sequence", n, false, true)
		if len(m) != 1 || m[0].id != "cron" {
			project.error(n, "element of \"schedule\" sequence must be mapping with single key \"cron\"")
			continue
		}
		s := project.parseString(m[0].val, false)
		if s != nil {
			cron = append(cron, s)
		}
	}
	return &ast.ScheduledEvent{Cron: cron, Pos: pos}
}

/* func (project *parser) missingExpression(node *yaml.Node, expecting string) {
	project.errorf(node, "expected single ${{...}} or %s but found empty string", expecting)
} */

func (project *parser) parseExpression(node *yaml.Node, _ /* expecting */ string) *ast.String {
	/* if !isExprAssigned(node.Value) {
		project.missingExpression(node, expecting)
		return nil
	} */
	return newString(node)
}

func (project *parser) parseBool(node *yaml.Node) *ast.Bool {
	if node.Kind != yaml.ScalarNode || (node.Tag != "!!bool" && node.Tag != SBOMStrTag) {
		project.errorf(node, "expected bool node but found %s node with %q tag", nodeKindName(node.Kind), node.Tag)
		return nil
	}
	if node.Tag == SBOMStrTag {
		e := project.parseExpression(node, "boolean literal \"true\" or \"false\"")
		return &ast.Bool{
			Expression: e,
			Pos:        positionAt(node),
		}
	}
	return &ast.Bool{
		Value: node.Value == "true",
		Pos:   positionAt(node),
	}
}

func (project *parser) parseInt(node *yaml.Node) *ast.Int {
	if node.Kind != yaml.ScalarNode || (node.Tag != "!!int" && node.Tag != SBOMStrTag) {
		project.errorf(node, "expected int node but found %s node with %q tag", nodeKindName(node.Kind), node.Tag)
		return nil
	}
	if node.Tag == SBOMStrTag {
		e := project.parseExpression(node, "integer literal")
		return &ast.Int{
			Expression: e,
			Pos:        positionAt(node),
		}
	}
	i, err := strconv.Atoi(node.Value)
	if err != nil {
		project.errorf(node, "invalid integer value: %q, stirings %s", node.Value, err.Error())
		return nil
	}
	return &ast.Int{
		Value: i,
		Pos:   positionAt(node),
	}
}

func (project *parser) parseFloat(node *yaml.Node) *ast.Float {
	if node.Kind != yaml.ScalarNode || (node.Tag != SBOMIntTag && node.Tag != SBOMFloatTag && node.Tag != SBOMStrTag) {
		project.errorf(node, "expected float node but found %s node with %q tag", nodeKindName(node.Kind), node.Tag)
		return nil
	}
	if node.Tag == SBOMStrTag {
		e := project.parseExpression(node, "float literal")
		return &ast.Float{
			Expression: e,
			Pos:        positionAt(node),
		}
	}
	f, err := strconv.ParseFloat(node.Value, 64)
	if err != nil {
		project.errorf(node, "invalid float value: %q, strings %s", node.Value, err.Error())
		return nil
	}
	return &ast.Float{
		Value: f,
		Pos:   positionAt(node),
	}
}

// *https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes
func (project *parser) parseTimeoutMinutes(node *yaml.Node) *ast.Float {
	f := project.parseFloat(node)
	if f != nil && f.Expression == nil && f.Value < 0 {
		project.errorf(node, "expected positive number for timeout-minutes but found %v", node.Value)
	}
	return f
}

func (project *parser) parseRawYAMLValue(node *yaml.Node) ast.RawYAMLValue {
	switch node.Kind {
	case yaml.DocumentNode:
		// DocumentNode not supported here
		project.errorf(node, "document node not supported in this context")
		return nil
	case yaml.ScalarNode:
		if node.Tag == "!!null" {
			return nil
		}
		return &ast.RawYAMLString{Value: node.Value, Posi: positionAt(node)}
	case yaml.AliasNode:
		// AliasNode not supported here
		project.errorf(node, "alias node not supported in this context")
		return nil
	case yaml.SequenceNode:
		ret := make([]ast.RawYAMLValue, 0, len(node.Content))
		for _, c := range node.Content {
			if v := project.parseRawYAMLValue(c); v != nil {
				ret = append(ret, v)
			}
		}
		return &ast.RawYAMLArray{Elems: ret, Posi: positionAt(node)}
	case yaml.MappingNode:
		parsed := project.parseMapping("matrix row value", node, true, false)
		m := make(map[string]ast.RawYAMLValue, len(parsed))
		for _, kv := range parsed {
			if v := project.parseRawYAMLValue(kv.val); v != nil {
				m[kv.id] = v
			}
		}
		return &ast.RawYAMLObject{Props: m, Posi: positionAt(node)}
	default:
		project.errorf(node, "expected scalar, sequence or mapping node but found %s node with %q tag", nodeKindName(node.Kind), node.Tag)
		return nil
	}
}

// *https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstrategymatrixinclude
// *https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstrategymatrixexclude
func (project *parser) parseMatrixCombinations(sec string, node *yaml.Node) *ast.MatrixCombinations {
	if node.Kind == yaml.ScalarNode {
		return &ast.MatrixCombinations{
			Expression: project.parseExpression(node, "array value for matrix variations"),
		}
	}
	if ok := project.checkSequence(sec, node, false); !ok {
		return nil
	}
	ret := make([]*ast.MatrixCombination, 0, len(node.Content))
	for _, c := range node.Content {
		if c.Kind == yaml.ScalarNode {
			if e := project.parseExpression(c, "mapping of matrix combinations"); e != nil {
				ret = append(ret, &ast.MatrixCombination{Expression: e})
			}
			continue
		}
		kvs := project.parseMapping(fmt.Sprintf("element of %q sequence", sec), c, false, false)
		assigns := make(map[string]*ast.MatrixAssign, len(kvs))
		for _, kv := range kvs {
			if v := project.parseRawYAMLValue(kv.val); v != nil {
				assigns[kv.id] = &ast.MatrixAssign{Key: kv.key, Value: v}
			}
		}
		ret = append(ret, &ast.MatrixCombination{Assigns: assigns})
	}
	return &ast.MatrixCombinations{Combinations: ret}
}

// parseContainer
// *https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idcontainer
func (project *parser) parseContainer(sec string, pos *ast.Position, node *yaml.Node) *ast.Container {
	ret := &ast.Container{Pos: pos, BaseNode: node}

	if node.Kind == yaml.ScalarNode {
		ret.Image = project.parseString(node, false)
	} else {
		for _, kv := range project.parseSectionMapping(sec, node, false, true) {
			switch kv.id {
			case "image":
				ret.Image = project.parseString(kv.val, false)
			case "credentials":
				cred := &ast.Credentials{Pos: kv.key.Pos, BaseNode: kv.val}
				for _, attr := range project.parseSectionMapping("credentials", kv.val, false, true) {
					switch attr.id {
					case "username":
						cred.Username = project.parseString(attr.val, false)
					case "password":
						cred.Password = project.parseString(attr.val, false)
					default:
						project.unexpectedKey(attr.key, "credentials", []string{"username", "password"})
					}
				}
				if cred.Username == nil || cred.Password == nil {
					project.errorAt(kv.key.Pos, "both \"username\" and \"password\" are required for \"credentials\"")
					continue
				}
				ret.Credentials = cred
			case AvailableEnv:
				ret.Env = project.parseEnv(kv.val)
			case "ports":
				ret.Ports = project.parseStringSequence("ports", kv.val, true, false)
			case "volumes":
				ret.Ports = project.parseStringSequence("volumes", kv.val, true, false)
			case "options":
				ret.Options = project.parseString(kv.val, true)
			default:
				project.unexpectedKey(kv.key, sec, []string{"image", "credentials", "env", "ports", "volumes", "options"})
			}
		}
	}
	return ret
}

// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idstrategymatrix
func (project *parser) parseMatrix(pos *ast.Position, node *yaml.Node) *ast.Matrix {
	if node.Kind == yaml.ScalarNode {
		return &ast.Matrix{Pos: positionAt(node), Expression: project.parseExpression(node, "matrix")}
	}

	ret := &ast.Matrix{Pos: pos, Rows: make(map[string]*ast.MatrixRow)}

	for _, kv := range project.parseSectionMapping("matrix", node, false, true) {
		switch kv.id {
		case "include":
			ret.Include = project.parseMatrixCombinations("include", kv.val)
		case "exclude":
			ret.Exclude = project.parseMatrixCombinations("exclude", kv.val)
		default:
			if kv.val.Kind == yaml.ScalarNode {
				ret.Rows[kv.id] = &ast.MatrixRow{Expression: project.parseExpression(kv.val, "array value for matrix variations")}
				continue
			}
			if ok := project.checkSequence("matrix", kv.val, false); !ok {
				continue
			}
			values := make([]ast.RawYAMLValue, 0, len(kv.val.Content))
			for _, c := range kv.val.Content {
				if v := project.parseRawYAMLValue(c); v != nil {
					values = append(values, v)
				}
			}
			ret.Rows[kv.id] = &ast.MatrixRow{Values: values, Name: kv.key}
		}
	}
	return ret
}

// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idstrategymax-parallel
func (project *parser) parseMaxParallel(node *yaml.Node) *ast.Int {
	i := project.parseInt(node)
	if i == nil {
		return nil
	}
	if i.Expression == nil && i.Value < 0 {
		project.errorf(node, "expected positive integer for max-parallel but found %v", i.Value)
	}
	return i
}

// parseStrategy
// *https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstrategy
func (project *parser) parseStrategy(pos *ast.Position, node *yaml.Node) *ast.Strategy {
	ret := &ast.Strategy{Pos: pos}

	for _, kv := range project.parseSectionMapping("strategy", node, false, true) {
		switch kv.id {
		case "fail-fast":
			ret.FailFast = project.parseBool(kv.val)
		case "matrix":
			ret.Matrix = project.parseMatrix(kv.key.Pos, kv.val)
		case "max-parallel":
			ret.MaxParallel = project.parseMaxParallel(kv.val)
		default:
			project.unexpectedKey(kv.key, "strategy", []string{"fail-fast", "matrix", "max-parallel"})
		}
	}
	return ret
}

//parseContainer
//*https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idcontainer

func (project *parser) parseStringSequence(sec string, node *yaml.Node, allowEmpty bool, caseSensitive bool) []*ast.String {
	if ok := project.checkSequence(sec, node, allowEmpty); !ok {
		return nil
	}
	ret := make([]*ast.String, 0, len(node.Content))
	for _, c := range node.Content {
		s := project.parseString(c, caseSensitive)
		if s != nil {
			ret = append(ret, s)
		}
	}
	return ret
}

func (project *parser) parseSSSequence(sec string, node *yaml.Node, allowEmpty bool, caseSensitive bool) []*ast.String {
	switch node.Kind {
	case yaml.DocumentNode:
		// DocumentNode not supported here
		project.errorf(node, "document node not supported in sequence")
		return []*ast.String{}
	case yaml.ScalarNode:
		if allowEmpty && node.Tag == "!!null" {
			return []*ast.String{}
		}
		return []*ast.String{project.parseString(node, caseSensitive)}
	case yaml.SequenceNode:
		return project.parseStringSequence(sec, node, allowEmpty, caseSensitive)
	case yaml.MappingNode:
		project.errorf(node, "mapping node not supported in string sequence")
		return []*ast.String{}
	case yaml.AliasNode:
		project.errorf(node, "alias node not supported in string sequence")
		return []*ast.String{}
	}
	return []*ast.String{}
}

// *https://docs.github.com/en/actions/learn-github-actions/events-that-trigger-workflows#workflow_dispatch
func (project *parser) parseWorkflowDispatchEvent(pos *ast.Position, node *yaml.Node) *ast.WorkflowDispatchEvent {
	ret := &ast.WorkflowDispatchEvent{Pos: pos}

	for _, kv := range project.parseSectionMapping("workflow_dispatch", node, true, true) {
		if kv.id != "inputs" {
			project.unexpectedKey(kv.key, "workflow_dispatch", []string{"inputs"})
			continue
		}
		inputs := project.parseSectionMapping("inputs", kv.val, true, false)
		ret.Inputs = make(map[string]*ast.DispatchInput, len(inputs))
		for _, input := range inputs {
			name, spec := input.key, input.val
			var description *ast.String
			var required *ast.Bool
			var def *ast.String
			var ty = ast.WorkflowDispatchEventInputTypeNone
			var options []*ast.String

			for _, attract := range project.parseMapping("input setting for \"workflow_dispatch\" event", spec, true, true) {
				switch attract.id {
				case SBOMDescription:
					description = project.parseString(attract.val, true)
				case SBOMRequired:
					required = project.parseBool(attract.val)
				case "default":
					def = project.parseString(attract.val, true)
				case "type":
					if !project.checkString(attract.val, false) {
						continue
					}
					switch attract.val.Value {
					case SBOMString:
						ty = ast.WorkflowDispatchEventInputTypeString
					case SBOMNumber:
						ty = ast.WorkflowDispatchEventInputTypeNumber
					case SBOMBoolean:
						ty = ast.WorkflowDispatchEventInputTypeBoolean
					case "choice":
						ty = ast.WorkflowDispatchEventInputTypeChoice
					case "environment":
						ty = ast.WorkflowDispatchEventInputTypeEnvironment
					default:
						project.errorf(attract.val, "expected one of \"string\", \"number\", \"boolean\", \"choice\", \"environment\" for \"type\" but found %q", attract.val.Value)
					}
				case "options":
					options = project.parseStringSequence("options", attract.val, false, false)
				default:
					project.unexpectedKey(attract.key, "input setting for \"workflow_dispatch\" event", []string{"description", "required", "default", "type", "options"})
				}
			}
			ret.Inputs[input.id] = &ast.DispatchInput{
				Name:        name,
				Description: description,
				Required:    required,
				Default:     def,
				Type:        ty,
				Options:     options,
			}
		}
	}
	return ret
}

// *https://docs.github.com/en/actions/learn-github-actions/events-that-trigger-workflows#repository_dispatch
func (project *parser) parseRepositoryDispatchEvent(pos *ast.Position, node *yaml.Node) *ast.RepositoryDispatchEvent {
	ret := &ast.RepositoryDispatchEvent{Pos: pos}

	for _, kv := range project.parseSectionMapping("repository_dispatch", node, true, true) {
		if kv.id == "types" {
			ret.Types = project.parseSSSequence("types", kv.val, false, false)
		} else {
			project.unexpectedKey(kv.key, "repository_dispatch", []string{"types"})
		}
	}
	return ret
}

// * https://docs.github.com/en/actions/learn-github-actions/events-that-trigger-workflows#workflow-reuse-events
// * https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#onworkflow_callinputs
// * https://docs.github.com/en/actions/learn-github-actions/reusing-workflows
func (project *parser) parseWorkflowCallEvent(pos *ast.Position, node *yaml.Node) *ast.WorkflowCallEvent {
	ret := &ast.WorkflowCallEvent{Pos: pos}

	for _, kv := range project.parseSectionMapping("workflow_call", node, true, true) {
		switch kv.id {
		case "inputs":
			inputs := project.parseSectionMapping("inputs", kv.val, true, false)
			ret.Inputs = make([]*ast.WorkflowCallEventInput, 0, len(inputs))
			for _, kv := range inputs {
				name, spec := kv.key, kv.val
				input := &ast.WorkflowCallEventInput{Name: name, ID: kv.id}
				sawType := false

				for _, attr := range project.parseMapping("input of workflow_call event", spec, true, true) {
					switch attr.id {
					case SBOMDescription:
						input.Description = project.parseString(attr.val, true)
					case "required":
						input.Required = project.parseBool(attr.val)
					case "default":
						input.Default = project.parseString(attr.val, true)
					case "type":
						switch attr.val.Value {
						case "boolean":
							input.Type = ast.WorkflowCallEventInputTypeBoolean
						case "number":
							input.Type = ast.WorkflowCallEventInputTypeNumber
						case "string":
							input.Type = ast.WorkflowCallEventInputTypeString
						default:
							project.errorf(attr.val, "expected one of \"boolean\", \"number\", \"string\" for \"type\" but found %q", attr.val.Value)
						}
						sawType = true
					default:
						project.unexpectedKey(attr.key, "input of workflow_call event", []string{"description", "required", "default", "type"})
					}
				}
				if !sawType {
					project.errorfAt(name.Pos, "input %q of workflow_call event is missing required key \"type\"", name.Value)
				}
				ret.Inputs = append(ret.Inputs, input)
			}
		case ContextSecrets:
			secrets := project.parseSectionMapping("secrets", kv.val, true, false)
			ret.Secrets = make(map[string]*ast.WorkflowCallEventSecret, len(secrets))
			for _, kv := range secrets {
				name, spec := kv.key, kv.val
				secret := &ast.WorkflowCallEventSecret{Name: name}

				for _, attr := range project.parseMapping("secret of workflow_call event", spec, true, true) {
					switch attr.id {
					case "description":
						secret.Description = project.parseString(attr.val, true)
					case "required":
						secret.Required = project.parseBool(attr.val)
					default:
						project.unexpectedKey(attr.key, "secret of workflow_call event", []string{"description", "required"})
					}
				}
				ret.Secrets[kv.id] = secret
			}
		case "outputs":
			outputs := project.parseSectionMapping("outputs", kv.val, true, false)
			ret.Outputs = make(map[string]*ast.WorkflowCallEventOutput, len(outputs))
			for _, kv := range outputs {
				name, spec := kv.key, kv.val
				output := &ast.WorkflowCallEventOutput{Name: name}

				for _, attr := range project.parseMapping("output of workflow_call event", spec, true, true) {
					switch attr.id {
					case "description":
						output.Description = project.parseString(attr.val, true)
					case "value":
						output.Value = project.parseString(attr.val, true)
					default:
						project.unexpectedKey(attr.key, "output of workflow_call event", []string{"description", "value"})
					}
				}
				ret.Outputs[kv.id] = output
			}
		default:
			project.unexpectedKey(kv.key, "workflow_call", []string{"inputs", "secrets", "outputs"})
		}
	}
	return ret
}

// *https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#using-filters
func (project *parser) parseWebhookEventFilter(name *ast.String, node *yaml.Node) *ast.WebhookEventFilter {
	vi := project.parseSSSequence(name.Value, node, false, false)
	return &ast.WebhookEventFilter{Name: name, Values: vi}
}

func (project *parser) parseWebhookEvent(name *ast.String, node *yaml.Node) *ast.WebhookEvent {
	ret := &ast.WebhookEvent{Hook: name, Pos: name.Pos}

	for _, kv := range project.parseSectionMapping(name.Value, node, true, true) {
		switch kv.id {
		case "types":
			ret.Types = project.parseSSSequence(kv.key.Value, kv.val, false, false)
		case "branches":
			ret.Branches = project.parseWebhookEventFilter(kv.key, kv.val)
		case "branches-ignore":
			ret.BranchesIgnore = project.parseWebhookEventFilter(kv.key, kv.val)
		case "tags":
			ret.Tags = project.parseWebhookEventFilter(kv.key, kv.val)
		case "tags-ignore":
			ret.TagsIgnore = project.parseWebhookEventFilter(kv.key, kv.val)
		case "paths":
			ret.Paths = project.parseWebhookEventFilter(kv.key, kv.val)
		case "paths-ignore":
			ret.PathsIgnore = project.parseWebhookEventFilter(kv.key, kv.val)
		case "workflows":
			ret.Workflows = project.parseSSSequence(kv.key.Value, kv.val, false, false)
		default:
			project.unexpectedKey(kv.key, name.Value, []string{"types", "branches", "branches-ignore", "tags", "tags-ignore", "paths", "paths-ignore", "workflows"})
		}
	}
	return ret
}

func (project *parser) maybeParseExpression(node *yaml.Node) *ast.String {
	if node.Tag != "!!str" {
		return nil
	}
	return newString(node)
}

// for parseJob
// parseRunsOn関数
func (project *parser) parseRunsOn(node *yaml.Node) *ast.Runner {
	if expression := project.maybeParseExpression(node); expression != nil {
		return &ast.Runner{Labels: nil, LabelsExpr: expression, Group: nil}
	}
	if node.Kind == yaml.ScalarNode || node.Kind == yaml.SequenceNode {
		return &ast.Runner{Labels: project.parseSSSequence("runs-on", node, false, false), LabelsExpr: nil, Group: nil}
	}
	r := &ast.Runner{}
	for _, keyvalue := range project.parseSectionMapping("runs-on", node, false, true) {
		switch keyvalue.id {
		case "labels":
			if expression := project.maybeParseExpression(keyvalue.val); expression != nil {
				r.LabelsExpr = expression
				continue
			}
			r.Labels = project.parseSSSequence("labels", keyvalue.val, false, false)
		case "group":
			r.Group = project.parseString(keyvalue.val, false)
		default:
			project.unexpectedKey(keyvalue.key, "runs-on", []string{"labels", "group"})
		}
	}
	return r
}

// parseEnvironment
func (project *parser) parseEnvironment(pos *ast.Position, node *yaml.Node) *ast.Environment {
	ret := &ast.Environment{Pos: pos}

	if node.Kind == yaml.ScalarNode {
		ret.Name = project.parseString(node, false)
	} else {
		nameisfound := false
		for _, keyvalue := range project.parseSectionMapping("environment", node, false, true) {
			switch keyvalue.id {
			case MainName:
				ret.Name = project.parseString(keyvalue.val, false)
				nameisfound = true
			case "url":
				ret.URL = project.parseString(keyvalue.val, false)
			default:
				project.unexpectedKey(keyvalue.key, "environment", []string{"name", "url"})
			}
		}
		if !nameisfound {
			project.errorAt(pos, "environment name is required")
		}
	}
	return ret
}

// parseOutputs
func (project *parser) parseOutputs(node *yaml.Node) map[string]*ast.Output {
	outputs := project.parseSectionMapping("outputs", node, false, false)
	ret := make(map[string]*ast.Output, len(outputs))
	for _, output := range outputs {
		ret[output.id] = &ast.Output{
			Name:  output.key,
			Value: project.parseString(output.val, true),
		}
	}
	project.checkNotEmpty("outputs", len(ret), node)
	return ret
}

// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_idsteps
func (project *parser) parseStep(node *yaml.Node) *ast.Step {
	// Dereference alias nodes (e.g., YAML anchors like *checkout)
	node = dereferenceAlias(node)

	ret := &ast.Step{Pos: positionAt(node), BaseNode: node}
	var workDir *ast.String

	for _, kv := range project.parseMapping("element of \"steps\" sequence", node, false, true) {
		switch kv.id {
		case "id":
			ret.ID = project.parseString(kv.val, false)
		case "if":
			ret.If = project.parseString(kv.val, false)
		case "name":
			ret.Name = project.parseString(kv.val, false)
		case "env":
			ret.Env = project.parseEnv(kv.val)
		case "continue-on-error":
			ret.ContinueOnError = project.parseBool(kv.val)
		case "timeout-minutes":
			ret.TimeoutMinutes = project.parseTimeoutMinutes(kv.val)
		case SBOMUses, SBOMWith:
			var exec *ast.ExecAction
			if ret.Exec == nil {
				exec = &ast.ExecAction{}
			} else if e, ok := ret.Exec.(*ast.ExecAction); ok {
				exec = e
			} else {
				project.errorfAt(kv.key.Pos, "this step is for running shell command since it contains at least one of \"run\", \"shell\" keys, but also contains %q key which is used for running action", kv.key.Value)
				continue
			}
			if kv.id == "uses" {
				exec.Uses = project.parseString(kv.val, false)
			} else {
				//kv.key == "with"で
				with := project.parseSectionMapping("with", kv.val, false, false)
				exec.Inputs = make(map[string]*ast.Input, len(with))
				for _, kv := range with {
					switch kv.id {
					case "entrypoint":
						//*https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstepswithentrypoint
						exec.Entrypoint = project.parseString(kv.val, false)
					case "args":
						//*https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstepswithargs
						exec.Args = project.parseString(kv.val, false)
					default:
						exec.Inputs[kv.id] = &ast.Input{Name: kv.key, Value: project.parseString(kv.val, true)}
					}
				}
			}
			ret.Exec = exec
		case SBOMRun, SBOMShell:
			var exec *ast.ExecRun
			if ret.Exec == nil {
				exec = &ast.ExecRun{}
			} else if e, ok := ret.Exec.(*ast.ExecRun); ok {
				exec = e
			} else {
				project.errorfAt(kv.key.Pos, "this step is for running action since it contains at least one of \"uses\", \"with\" keys, but also contains %q key which is used for running shell command", kv.key.Value)
				continue
			}
			switch kv.id {
			case "run":
				exec.Run = project.parseString(kv.val, false)
				exec.RunPos = kv.key.Pos
			case "shell":
				exec.Shell = project.parseString(kv.val, false)
			}
			exec.WorkingDirectory = workDir
			ret.Exec = exec
		case "working-directory":
			workDir = project.parseString(kv.val, false)
			if e, ok := ret.Exec.(*ast.ExecRun); ok {
				e.WorkingDirectory = workDir
			}
		default:
			project.unexpectedKey(kv.key, "element of \"steps\" sequence", []string{"id", "if", "name", "env", "continue-on-error", "timeout-minutes", "uses", "with", "run", "shell", "working-directory"})
		}
	}
	switch e := ret.Exec.(type) {
	case *ast.ExecAction:
		if e.Uses == nil {
			project.error(node, "\"uses\" is required for action step")
		}
		if workDir != nil {
			project.error(node, "\"working-directory\" is not allowed for action step, only available for with \"run\"")
		}
	case *ast.ExecRun:
		if e.Run == nil {
			project.error(node, "\"run\" is required for shell command step")
		}
	default:
		project.error(node, "step must run script with \"uses\" or \"run\"")
	}
	return ret
}

// ret.Steps = project.parseSteps(value)
// parseSteps関数
func (project *parser) parseSteps(node *yaml.Node) []*ast.Step {
	if ok := project.checkSequence("steps", node, false); !ok {
		return nil
	}
	ret := make([]*ast.Step, 0, len(node.Content))

	for _, c := range node.Content {
		if s := project.parseStep(c); s != nil {
			ret = append(ret, s)
		}
	}
	return ret
}
