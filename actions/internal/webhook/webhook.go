// Package webhook reads GitHub's webhooks from their OpenAPI description
// (@octokit/openapi-webhooks): the schema of each webhook's payload and the
// actions it takes. The generators of actions/workflow (schemagen, the
// activity types) and actions/taint (tablegen, the payloads) use it, so
// that both read the actions the same way.
package webhook

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"slices"
	"strings"
)

// Spec is the part of the OpenAPI description the generators read.
type Spec struct {
	Webhooks   map[string]Webhook `json:"webhooks"`
	Components struct {
		Schemas map[string]json.RawMessage `json:"schemas"`
	} `json:"components"`
}

// Webhook is one webhook of the description: an event with one action, or
// with none.
type Webhook struct {
	Post struct {
		XGitHub struct {
			Subcategory string `json:"subcategory"`
		} `json:"x-github"`
		RequestBody struct {
			Content map[string]struct {
				Schema json.RawMessage `json:"schema"`
			} `json:"content"`
		} `json:"requestBody"`
	} `json:"post"`
}

// Subcategory is the event of w, by the webhook's name of it.
func (w Webhook) Subcategory() string { return w.Post.XGitHub.Subcategory }

// Body is the schema of w's JSON payload.
func (w Webhook) Body() (json.RawMessage, bool) {
	c, ok := w.Post.RequestBody.Content["application/json"]
	return c.Schema, ok
}

// Read reads the gzipped description at path.
func Read(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	z, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(z)
}

// Parse decodes the description src.
func Parse(src []byte) (Spec, error) {
	var s Spec
	err := json.Unmarshal(src, &s)
	return s, err
}

// Subcategory is the webhook's name of the workflow's event: the payload of
// pull_request_target is that of pull_request.
func Subcategory(event string) string {
	if event == "pull_request_target" {
		return "pull_request"
	}
	return event
}

// Actions are the actions of the webhooks of the workflow's event, by name;
// nil when it has none, or no webhook.
func (s Spec) Actions(event string) []string {
	var out []string
	for _, w := range s.Webhooks {
		if w.Subcategory() != Subcategory(event) {
			continue
		}
		body, ok := w.Body()
		if !ok {
			continue
		}
		for _, a := range ActionsOf(s.Components.Schemas, body) {
			if a != "" && !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	slices.Sort(out)
	return out
}

type schema struct {
	Ref        string                     `json:"$ref"`
	Properties map[string]json.RawMessage `json:"properties"`
	AnyOf      []json.RawMessage          `json:"anyOf"`
	OneOf      []json.RawMessage          `json:"oneOf"`
	AllOf      []json.RawMessage          `json:"allOf"`
}

// ActionsOf are the values of the property action of a webhook's schema,
// also in the branches of its oneOf, anyOf and allOf; "" when it has none.
func ActionsOf(schemas map[string]json.RawMessage, raw json.RawMessage) []string {
	var out []string
	var walk func(raw json.RawMessage, depth int)
	walk = func(raw json.RawMessage, depth int) {
		var s schema
		if depth > 8 || json.Unmarshal(raw, &s) != nil {
			return
		}
		if s.Ref != "" {
			walk(schemas[s.Ref[strings.LastIndexByte(s.Ref, '/')+1:]], depth+1)
			return
		}
		var a struct {
			Const *string           `json:"const"`
			Enum  []json.RawMessage `json:"enum"`
		}
		if json.Unmarshal(s.Properties["action"], &a) == nil {
			if a.Const != nil && !slices.Contains(out, *a.Const) {
				out = append(out, *a.Const)
			}
			for _, e := range a.Enum {
				var v string
				if json.Unmarshal(e, &v) == nil && !slices.Contains(out, v) {
					out = append(out, v)
				}
			}
		}
		for _, sub := range slices.Concat(s.OneOf, s.AnyOf, s.AllOf) {
			walk(sub, depth+1)
		}
	}
	walk(raw, 0)
	if len(out) == 0 {
		return []string{""}
	}
	return out
}
