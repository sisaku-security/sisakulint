package core

import (
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

//todo: parse_main.goで出てくる関数の順番通りに実装する

func (project *parser) parseMapping(sec string, node *yaml.Node, allowEmpty bool, allowDuplicate bool) []workflowKeyValue {
	isNull := isNull(node)

	if !isNull && node.Kind != yaml.MappingNode {
		project.errorf(node, "%s is %s node but mapping node is expected", sec, nodeKindName(node.Kind))
		return nil
	}

	if !allowEmpty && isNull {
		project.errorf(node, "%s is empty", sec)
		return nil
	}

	mappings := make(map[string]*ast.Position, len(node.Content)/2)
	m := make([]workflowKeyValue, 0, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		key := project.parseString(node.Content[i], false)
		if key == nil {
			continue
		}

		id := key.Value
		if !allowDuplicate {
			id = strings.ToLower(id)
		}

		if pos, ok := mappings[id]; ok {
			var note string
			if !allowDuplicate {
				note = fmt.Sprintf(" (duplicate key %q)", id)
			}
			project.errorfAt(key.Pos, "key %q is duplicates in %s. previous key is at %s%s", key.Value, sec, pos.String(), note)
		}
		m = append(m, workflowKeyValue{id, key, node.Content[i+1]})
		mappings[id] = key.Pos
	}

	if !allowEmpty && len(m) == 0 {
		project.errorf(node, "%s is empty", sec)
	}

	return m
}

func (project *parser) parseString(node *yaml.Node, allowEmpty bool) *ast.String {
	if !project.checkString(node, allowEmpty) {
		return &ast.String{Value: "", Quoted: false, Pos: positionAt(node), BaseNode: node}
	}
	return newString(node)
}

// *https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#on
func (project *parser) parseEvents(pos *ast.Position, node *yaml.Node) []ast.Event {
	switch node.Kind {
	case yaml.DocumentNode:
		// DocumentNode not supported in this context
		project.errorAt(pos, "document node not supported in event specification")
		return []ast.Event{}
	case yaml.AliasNode:
		// AliasNode not supported in this context
		project.errorAt(pos, "alias node not supported in event specification")
		return []ast.Event{}
	case yaml.ScalarNode:
		switch node.Value {
		case SubWorkflowDispatch:
			return []ast.Event{
				&ast.WorkflowDispatchEvent{Pos: positionAt(node)},
			}
		case SubRepositoryDispatch:
			return []ast.Event{
				&ast.RepositoryDispatchEvent{Pos: positionAt(node)},
			}
		case SubSchedule:
			project.errorAt(pos, "schedule event is not supported")
			return []ast.Event{}
		case SubWorkflowCall:
			return []ast.Event{
				&ast.WorkflowCallEvent{Pos: positionAt(node)},
			}
		default:
			hi := project.parseString(node, false)
			if hi.Value == "" {
				return []ast.Event{}
			}
			return []ast.Event{
				&ast.WebhookEvent{
					Hook: hi,
					Pos:  positionAt(node),
				},
			}
		}
	case yaml.MappingNode:
		kvs := project.parseSectionMapping("on", node, false, true)
		ret := make([]ast.Event, 0, len(kvs))

		for _, kv := range kvs {
			pos := kv.key.Pos
			switch kv.id {
			//*https://docs.github.com/en/actions/learn-github-actions/events-that-trigger-workflows#schedule
			case "schedule":
				if e := project.parseScheduleEvent(pos, kv.val); e != nil {
					ret = append(ret, e)
				}
			//*https://docs.github.com/en/actions/learn-github-actions/events-that-trigger-workflows#workflow_dispatch
			case "workflow_dispatch":
				ret = append(ret, project.parseWorkflowDispatchEvent(pos, kv.val))

			//*https://docs.github.com/en/actions/learn-github-actions/events-that-trigger-workflows#repository_dispatch
			case "repository_dispatch":
				ret = append(ret, project.parseRepositoryDispatchEvent(pos, kv.val))

			//*https://docs.github.com/en/actions/learn-github-actions/events-that-trigger-workflows#workflow_call
			case SubWorkflowCall:
				ret = append(ret, project.parseWorkflowCallEvent(pos, kv.val))
			default:
				ret = append(ret, project.parseWebhookEvent(kv.key, kv.val))
			}
		}
		return ret
	case yaml.SequenceNode:
		project.checkNotEmpty("on", len(node.Content), node)
		ret := make([]ast.Event, 0, len(node.Content))

		for _, c := range node.Content {
			if s := project.parseString(c, false); s != nil {
				switch s.Value {
				//*https://docs.github.com/en/actions/learn-github-actions/events-that-trigger-workflows#schedule
				//*https://docs.github.com/en/actions/learn-github-actions/events-that-trigger-workflows#repository_dispatch
				case "schedule", "repository_dispatch":
					project.errorf(c, "event %q must be mapping", s.Value)

				//*https://docs.github.com/en/actions/learn-github-actions/events-that-trigger-workflows#workflow_dispatch
				case "workflow_dispatch":
					ret = append(ret, &ast.WorkflowDispatchEvent{Pos: positionAt(c)})

				//*https://docs.github.com/en/actions/learn-github-actions/events-that-trigger-workflows#workflow_call
				case SubWorkflowCall:
					ret = append(ret, &ast.WorkflowCallEvent{Pos: positionAt(c)})
				default:
					ret = append(ret, &ast.WebhookEvent{Hook: s, Pos: positionAt(c)})
				}
			}
		}
		return ret
	default:
		project.errorf(node, "expected scalar, mapping or sequence node for \"on\" but found %s node with %q tag", nodeKindName(node.Kind), node.Tag)
		return nil
	}
}

// *https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#permissions
func (project *parser) parsePermissions(pos *ast.Position, node *yaml.Node) *ast.Permissions {
	ret := &ast.Permissions{Pos: pos}

	if node.Kind == yaml.ScalarNode {
		ret.All = project.parseString(node, false)
	} else {
		msg := project.parseSectionMapping("permissions", node, true, false)
		scopes := make(map[string]*ast.PermissionScope, len(msg))
		for _, kv := range msg {
			scopes[kv.id] = &ast.PermissionScope{
				Name:  kv.key,
				Value: project.parseString(kv.val, false),
			}
		}
		ret.Scopes = scopes
	}
	return ret
}

// *https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#env
func (project *parser) parseEnv(node *yaml.Node) *ast.Env {
	if node.Kind == yaml.ScalarNode {
		return &ast.Env{
			Expression: project.parseExpression(node, "mapping value for env"),
		}
	}

	m := project.parseMapping("env", node, false, false)
	vars := make(map[string]*ast.EnvVar, len(m))

	for _, kv := range m {
		vars[kv.id] = &ast.EnvVar{
			Name:  kv.key,
			Value: project.parseString(kv.val, true),
		}
	}
	return &ast.Env{Vars: vars}
}

// *https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#defaults
func (project *parser) parseDefaults(pos *ast.Position, node *yaml.Node) *ast.Defaults {
	ret := &ast.Defaults{Pos: pos}

	for _, kv := range project.parseSectionMapping("defaults", node, false, true) {
		if kv.id != "run" {
			project.unexpectedKey(kv.key, "defaults", []string{"run"})
			continue
		}
		ret.Run = &ast.DefaultsRun{Pos: kv.key.Pos}

		for _, kv := range project.parseSectionMapping("run", kv.val, false, true) {
			switch kv.id {
			case "shell":
				ret.Run.Shell = project.parseString(kv.val, false)
			case "working-directory":
				ret.Run.WorkingDirectory = project.parseString(kv.val, false)
			default:
				project.unexpectedKey(kv.key, "run", []string{"shell", "working-directory"})
			}
		}
	}
	if ret.Run == nil {
		project.errorAt(pos, "section is missing required key \"run\"")
	}
	return ret
}

// *https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#concurrency
func (project *parser) parseConcurrency(pos *ast.Position, node *yaml.Node) *ast.Concurrency {
	ret := &ast.Concurrency{Pos: pos}

	if node.Kind == yaml.ScalarNode {
		ret.Group = project.parseString(node, false)
	} else {
		groupFound := false
		for _, kv := range project.parseSectionMapping("concurrency", node, false, true) {
			switch kv.id {
			case "group":
				ret.Group = project.parseString(kv.val, false)
				groupFound = true
			case "cancel-in-progress":
				ret.CancelInProgress = project.parseBool(kv.val)
			default:
				project.unexpectedKey(kv.key, "concurrency", []string{"group", "cancel-in-progress"})
			}
		}
		if !groupFound {
			project.errorAt(pos, "section is missing required key \"group\", \"cancel-in-progress\"")
		}
	}
	return ret
}

// *https://docs.github.com/en/actions/learn-github-actions/workflow-syntax-for-github-actions#jobsjob_id
func (project *parser) parseJob(id *ast.String, n *yaml.Node) *ast.Job {
	ret := &ast.Job{ID: id, Pos: id.Pos, BaseNode: n}
	call := &ast.WorkflowCall{}

	// Only below keys are allowed on reusable workflow call
	//*https://docs.github.com/en/actions/learn-github-actions/reusing-workflows#supported-keywords-for-jobs-that-call-a-reusable-workflow
	//   - jobs.<job_id>.name
	//   - jobs.<job_id>.uses
	//   - jobs.<job_id>.with
	//   - jobs.<job_id>.with.<input_id>
	//   - jobs.<job_id>.secrets
	//   - jobs.<job_id>.secrets.<secret_id>
	//   - jobs.<job_id>.needs
	//   - jobs.<job_id>.if
	//   - jobs.<job_id>.permissions

	//*https://docs.github.com/en/actions/using-workflows/reusing-workflows#supported-keywords-for-jobs-that-call-a-reusable-workflow
	var stepsOnlyKey *ast.String
	var callOnlyKey *ast.String

	for _, keyvalue := range project.parseMapping(fmt.Sprintf("%q job", id.Value), n, false, true) {
		key, value := keyvalue.key, keyvalue.val
		switch keyvalue.id {
		case "name":
			ret.Name = project.parseString(value, true)
		case "needs":
			if value.Kind == yaml.ScalarNode {
				// needs: job1
				ret.Needs = []*ast.String{project.parseString(value, false)}
			} else {
				// needs: [job1, job2]
				ret.Needs = project.parseStringSequence("needs", value, false, false)
			}
		case "runs-on":
			ret.RunsOn = project.parseRunsOn(value)
			stepsOnlyKey = key
		case "permissions":
			ret.Permissions = project.parsePermissions(key.Pos, value)
		case "environment":
			ret.Environment = project.parseEnvironment(key.Pos, value)
			stepsOnlyKey = key
		case "concurrency":
			ret.Concurrency = project.parseConcurrency(key.Pos, value)
		case "outputs":
			ret.Outputs = project.parseOutputs(value)
			stepsOnlyKey = key
		case "env":
			ret.Env = project.parseEnv(value)
			stepsOnlyKey = key
		case "defaults":
			ret.Defaults = project.parseDefaults(key.Pos, value)
			stepsOnlyKey = key
		case "if":
			ret.If = project.parseString(value, false)
		case "steps":
			ret.Steps = project.parseSteps(value)
			stepsOnlyKey = key
		case "timeout-minutes":
			ret.TimeoutMinutes = project.parseTimeoutMinutes(value)
			stepsOnlyKey = key
		case "strategy":
			ret.Strategy = project.parseStrategy(key.Pos, value)
		case "continue-on-error":
			ret.ContinueOnError = project.parseBool(value)
			stepsOnlyKey = key
		case "container":
			ret.Container = project.parseContainer("container", key.Pos, value)
			stepsOnlyKey = key
		case "services":
			services := project.parseSectionMapping("services", value, false, false) // XXX: Is the key case-insensitive?
			ret.Services = make(map[string]*ast.Service, len(services))
			for _, s := range services {
				ret.Services[s.id] = &ast.Service{
					Name:      s.key,
					Container: project.parseContainer("services", s.key.Pos, s.val),
				}
			}
		case "uses":
			call.Uses = project.parseString(value, false)
			callOnlyKey = key
		case "with":
			with := project.parseSectionMapping("with", value, false, false)
			call.Inputs = make(map[string]*ast.WorkflowCallInput, len(with))
			for _, i := range with {
				call.Inputs[i.id] = &ast.WorkflowCallInput{
					Name:  i.key,
					Value: project.parseString(i.val, true),
				}
			}
			callOnlyKey = key
		case ContextSecrets:
			if keyvalue.val.Kind == yaml.ScalarNode {
				//*https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#onworkflow_callsecretsinherit
				if keyvalue.val.Value == "inherit" {
					call.InheritSecrets = true
				} else {
					project.errorf(keyvalue.val, "expected mapping node for secrets or \"inherit\" string node but found %q node", keyvalue.val.Value)
				}
			} else {
				secrets := project.parseSectionMapping("secrets", value, false, false)
				call.Secrets = make(map[string]*ast.WorkflowCallSecret, len(secrets))
				for _, s := range secrets {
					call.Secrets[s.id] = &ast.WorkflowCallSecret{
						Name:  s.key,
						Value: project.parseString(s.val, true),
					}
				}
			}
			callOnlyKey = key
		default:
			project.unexpectedKey(keyvalue.key, "job", []string{
				"name",
				"needs",
				"runs-on",
				"permissions",
				"environment",
				"concurrency",
				"outputs",
				"env",
				"defaults",
				"if",
				"steps",
				"timeout-minutes",
				"strategy",
				"continue-on-error",
				"container",
				"services",
				"uses",
				"with",
				"secrets",
			})
		}
	}

	if call.Uses != nil {
		if stepsOnlyKey != nil {
			project.errorfAt(
				stepsOnlyKey.Pos,
				"when a reusable workflow is called with \"uses\", %q is not available. only following keys are allowed: \"name\", \"uses\", \"with\", \"secrets\", \"needs\", \"if\", and \"permissions\" in job %q",
				stepsOnlyKey.Value,
				id.Value,
			)
		} else {
			ret.WorkflowCall = call
		}
	} else {
		// When not a reusable call
		if ret.Steps == nil {
			project.errorfAt(id.Pos, "\"steps\" section is missing in job %q", id.Value)
		}
		if ret.RunsOn == nil {
			project.errorfAt(id.Pos, "\"runs-on\" section is missing in job %q", id.Value)
		}
		if callOnlyKey != nil {
			project.errorfAt(
				callOnlyKey.Pos,
				"%q is only available for a reusable workflow call with \"uses\" but \"uses\" is not found in job %q",
				callOnlyKey.Value,
				id.Value,
			)
		}
	}
	return ret
}

// *https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobs
func (project *parser) parseJobs(node *yaml.Node) map[string]*ast.Job {
	jobs := project.parseSectionMapping("jobs", node, false, false)
	ret := make(map[string]*ast.Job, len(jobs))
	for _, kv := range jobs {
		ret[kv.id] = project.parseJob(kv.key, kv.val)
	}
	return ret
}

func (project *parser) unexpectedKey(str *ast.String, sec string, expected []string) {
	l := len(expected)
	var msg string
	if l == 1 {
		msg = fmt.Sprintf("expected %q key for %q section but got %q", expected[0], sec, str.Value)
	} else if l > 1 {
		msg = fmt.Sprintf("unexpected key %q for %q section. expected one of ", str.Value, sec)
	} else {
		msg = fmt.Sprintf("unexpected key %q for %q section", str.Value, sec)
	}
	project.errorAt(str.Pos, msg)
}
