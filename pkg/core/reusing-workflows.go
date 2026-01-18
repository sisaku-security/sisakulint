package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/expressions"
	"gopkg.in/yaml.v3"
)

func expectedMapping(where string, node *yaml.Node) error {
	return fmt.Errorf(
		"yaml: %s area must mapping node but %s node was found at line:%d, column:%d", where, nodeKindName(node.Kind), node.Line, node.Column,
	)
}

// ReusableWorkflowMetadataInput は、ローカルで再利用可能なワークフローファイルを検証するための入力メタデータです。
type ReusableWorkflowMetadataInput struct {
	// Name は、再利用可能なワークフローで定義された入力の名前です。
	Name string
	// Required は、入力の 'required' フィールドが true に設定され、デフォルト値が設定されていない場合に true です。
	Required bool
	Type     expressions.ExprType
}

// UnmarshalYAML implements yaml.Unmarshaler interface.
func (input *ReusableWorkflowMetadataInput) UnmarshalYAML(node *yaml.Node) error {
	type metadata struct {
		Required bool    `yaml:"required"`
		Default  *string `yaml:"default"`
		Type     string  `yaml:"type"`
	}
	var m metadata
	if err := node.Decode(&m); err != nil {
		return err
	}

	input.Required = m.Required && m.Default == nil
	var exprType expressions.ExprType
	switch m.Type {
	case "boolean":
		// input.Type = ExprBoolean
		exprType = expressions.BoolType{}
	case "number":
		// input.Type = ExprNumber
		exprType = expressions.NumberType{}
	case "string":
		// input.Type = ExprString
		exprType = expressions.StringType{}
	default:
		exprType = expressions.UnknownType{}
	}
	input.Type = exprType
	return nil
}

// ReusableWorkflowMetadataInputs is  map from input name to input metadata.
type ReusableWorkflowMetadataInputs map[string]*ReusableWorkflowMetadataInput

// UnmarshalYAML implements yaml.Unmarshaler
func (inputs *ReusableWorkflowMetadataInputs) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return expectedMapping("on.workflow_call.inputs", node)
	}
	m := make(ReusableWorkflowMetadataInputs, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		var mage ReusableWorkflowMetadataInput
		if err := value.Decode(&mage); err != nil {
			return err
		}
		mage.Name = key.Value
		if mage.Type == nil {
			var exprType expressions.ExprType
			mage.Type = exprType
		}
		m[strings.ToLower(key.Value)] = &mage
	}
	*inputs = m
	return nil
}

// ReusableWorkflowMetadataSecretは、ローカルの再利用可能なワークフローファイルの検証のためのsecret metadata
type ReusableWorkflowMetadataSecret struct {
	// Nameは、再利用可能なワークフロー内の秘密の名前です。
	Name string
	// Requiredは、その再利用可能なワークフローによってこの秘密が必要かどうかを示します。この値が trueの場合、ワークフローの呼び出しは、秘密が継承されない限り、この秘密を設定する必要があります。
	Required bool `yaml:"required"`
}

// ReusableWorkflowMetadataSecretsは、秘密の名前から再利用可能なワークフローの秘密のメタデータへのマップです。
// キーは小文字であり、ワークフローの呼び出しの秘密の名前は大文字/小文字を区別しないためです。
type ReusableWorkflowMetadataSecrets map[string]*ReusableWorkflowMetadataSecret

// UnmarshalYAMLは、yaml.Unmarshalerインターフェイスを実装します。
func (secrets *ReusableWorkflowMetadataSecrets) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return expectedMapping("on.workflow_call.secrets", node)
	}
	m := make(ReusableWorkflowMetadataSecrets, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		var secret ReusableWorkflowMetadataSecret
		if err := value.Decode(&secret); err != nil {
			return err
		}
		secret.Name = key.Value
		m[strings.ToLower(key.Value)] = &secret
	}
	*secrets = m
	return nil
}

// ReusableWorkflowMetadataOutputは、ローカルの再利用可能なワークフローファイルの検証のための出力メタデータです。
type ReusableWorkflowMetadataOutput struct {
	// Nameは、再利用可能なワークフロー内の出力の名前です。
	Name string
}

// ReusableWorkflowMetadataOutputsは、出力名から再利用可能なワークフローの出力メタデータへのマップです。
// キーは小文字であり、ワークフローの呼び出しの出力名は大文字/小文字を区別しないためです。
type ReusableWorkflowMetadataOutputs map[string]*ReusableWorkflowMetadataOutput

// UnmarshalYAMLは、yaml.Unmarshalerインターフェイスを実装します。
func (outputs *ReusableWorkflowMetadataOutputs) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return expectedMapping("on.workflow_call.outputs", node)
	}
	m := make(ReusableWorkflowMetadataOutputs, len(node.Content)/2)
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		var output ReusableWorkflowMetadataOutput
		if err := value.Decode(&output); err != nil {
			return err
		}
		output.Name = key.Value
		m[strings.ToLower(key.Value)] = &output
	}
	*outputs = m
	return nil
}

// ReusableWorkflowMetadataは、ローカルの再利用可能なワークフローを検証するためのメタデータ
// この構造体はYAMLファイルからのすべてのメタデータを含んでいません。
// 再利用可能なワークフローファイルの検証に必要なメタデータのみ
type ReusableWorkflowMetadata struct {
	Inputs  ReusableWorkflowMetadataInputs  `yaml:"inputs"`
	Outputs ReusableWorkflowMetadataOutputs `yaml:"outputs"`
	Secrets ReusableWorkflowMetadataSecrets `yaml:"secrets"`
}

// LocalReusableWorkflowCacheは、ローカルの再利用可能なワークフローメタデータファイルのキャッシュです。ローカルの再利用可能な
// ワークフローのYAMLファイルの検索/読み取り/解析を回避します。このキャッシュは、'proj'フィールドのみに関連です。
// 1つのプロジェクトごとに1つのLocalReusableWorkflowCacheインスタンスを作成する必要があります。
type LocalReusableWorkflowCache struct {
	mu    sync.RWMutex
	proj  *Project
	cache map[string]*ReusableWorkflowMetadata
	cwd   string
	dbg   io.Writer
}

func (c *LocalReusableWorkflowCache) debugf(format string, args ...any) {
	if c.dbg == nil {
		return
	}
	format = "[local reusable workflow cache] " + format + "\n"
	fmt.Fprintf(c.dbg, format, args...)
}

// readCacheは、キャッシュから再利用可能なワークフローメタデータを読み取ります。
func (c *LocalReusableWorkflowCache) readCache(key string) (*ReusableWorkflowMetadata, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	m, ok := c.cache[key]
	return m, ok
}

// writeCacheは、キャッシュに再利用可能なワークフローメタデータを書き込みます。
func (c *LocalReusableWorkflowCache) writeCache(key string, m *ReusableWorkflowMetadata) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = m
}

// FindMetadataは、'spec'引数で指定された位置にあるreusable workflow metadataを検索して解析
//'proj'フィールドにプロジェクトが設定されていない、またはspecが"./"で始まらない場合、このメソッドはnilを返します。
//todo:エラーはキャッシュされません
//最初の検索で、このメソッドがreusable workflowが無効であるためにエラーを返した場合、同じspecで後でこのメソッドを呼び出しても、エラーは返されないです。
//単にnilが返されます。この挙動は、同じエラーを複数の場所から繰り返し報告することを防ぎます。

func (c *LocalReusableWorkflowCache) FindMetadata(spec string) (*ReusableWorkflowMetadata, error) {
	if !strings.HasPrefix(spec, "./") {
		return nil, nil
	}
	// Check cache first
	if m, ok := c.readCache(spec); ok {
		c.debugf("cache hit: %s , : %v", spec, m)
		return m, nil
	}
	if c.proj == nil {
		return nil, nil
	}
	file := filepath.Join(c.proj.RootDirectory(), filepath.FromSlash(spec))
	file = filepath.Clean(file)

	// Prevent path traversal attacks
	rootDir := filepath.Clean(c.proj.RootDirectory())
	if !strings.HasPrefix(file, rootDir+string(filepath.Separator)) && file != rootDir {
		c.writeCache(spec, nil)
		return nil, fmt.Errorf("path traversal detected in workflow spec %q", spec)
	}

	src, err := os.ReadFile(file)
	if err != nil {
		c.writeCache(spec, nil) //このworkflowは無効
		return nil, fmt.Errorf("failed to read reusable workflow metadata file %q: %w", spec, err)
	}

	m, err := parseReusableWorkflowMetadata(src)
	if err != nil {
		c.writeCache(spec, nil) //このworkflowは無効
		msg := strings.ReplaceAll(err.Error(), "\n", " ")
		return nil, fmt.Errorf("failed to parse reusable workflow metadata file %q: %s", spec, msg)
	}

	c.debugf("new reusable workflow metadata at %s: %v", file, src)
	c.writeCache(spec, m)
	return m, nil
}

// pathToWorkflowSpecification
func (c *LocalReusableWorkflowCache) pathToWorkflowSpecification(spec string) (string, bool) {
	if c.proj == nil {
		return "", false
	}
	if !filepath.IsAbs(spec) {
		spec = filepath.Join(c.cwd, spec)
	}
	r := c.proj.RootDirectory()
	if !strings.HasPrefix(spec, r) {
		return "", false
	}
	p, err := filepath.Rel(r, spec)
	if err != nil {
		return "", false //unreachable
	}
	p = filepath.ToSlash(p)
	if !strings.HasPrefix(p, "./") {
		p = "./" + p
	}
	return p, true
}

// WriteWorkflowCallEventは、WorkflowCallEvent AST node からreusable workflow metadata を書き込む
// 'wpath'は、ASTのworkflowファイルのパス
//プロジェクトのrootディレクトリ相対か、絶対パス
// 以下の状況では、このメソッドは実行されない
//todo: (1) プロジェクトが未設定
//todo: (2) workflow pathをworkflow call specに変換できない
//todo: (3) 既に該当workflowのキャッシュが存在する場合
// このメソッドの呼び出しはthread-safeで

func (c *LocalReusableWorkflowCache) WriteWorkflowCallEvent(wpath string, event *ast.WorkflowCallEvent) {
	spec, ok := c.pathToWorkflowSpecification(wpath)
	if !ok {
		return
	}
	if _, ok := c.readCache(spec); ok {
		return
	}
	c.debugf("workflow call spec from workflow path %s: %s", wpath, spec)
	c.mu.RLock()
	_, ok = c.cache[spec]
	c.mu.RUnlock()
	if ok {
		return
	}
	m := &ReusableWorkflowMetadata{
		Inputs:  ReusableWorkflowMetadataInputs{},
		Outputs: ReusableWorkflowMetadataOutputs{},
		Secrets: ReusableWorkflowMetadataSecrets{},
	}
	for _, i := range event.Inputs {
		var ExprType expressions.ExprType
		switch i.Type {
		case ast.WorkflowCallEventInputTypeInvalid:
			ExprType = expressions.UnknownType{}
		case ast.WorkflowCallEventInputTypeBoolean:
			ExprType = expressions.BoolType{}
		case ast.WorkflowCallEventInputTypeNumber:
			ExprType = expressions.NumberType{}
		case ast.WorkflowCallEventInputTypeString:
			ExprType = expressions.StringType{}
		}
		m.Inputs[i.ID] = &ReusableWorkflowMetadataInput{
			Type:     ExprType,
			Required: i.Required != nil && i.Required.Value && i.Default == nil,
			Name:     i.Name.Value,
		}
	}
	for n, o := range event.Outputs {
		m.Outputs[n] = &ReusableWorkflowMetadataOutput{
			Name: o.Name.Value,
		}
	}

	for n, s := range event.Secrets {
		r := s.Required != nil && s.Required.Value
		m.Secrets[n] = &ReusableWorkflowMetadataSecret{
			Required: r,
			Name:     s.Name.Value,
		}
	}
	c.mu.Lock()
	c.cache[spec] = m
	c.mu.Unlock()
	c.debugf("Workflow call metadata from workflow path %s: %v", wpath, m)
}

func parseReusableWorkflowMetadata(src []byte) (*ReusableWorkflowMetadata, error) {
	type workflow struct {
		On yaml.Node `yaml:"on"`
	}
	var w workflow
	if err := yaml.Unmarshal(src, &w); err != nil {
		return nil, err
	}
	node := &w.On
	if node.Line == 0 && node.Column == 0 {
		return nil, fmt.Errorf("yaml: on.workflow_call is required")
	}
	switch node.Kind {
	case yaml.DocumentNode:
		// DocumentNode is not expected here
		return nil, fmt.Errorf("yaml: unexpected document node in on.workflow_call")
	case yaml.ScalarNode:
		// ScalarNode is not expected here
		return nil, fmt.Errorf("yaml: unexpected scalar node in on.workflow_call")
	case yaml.SequenceNode:
		// SequenceNode is not expected here
		return nil, fmt.Errorf("yaml: unexpected sequence node in on.workflow_call")
	case yaml.AliasNode:
		// AliasNode is not expected here
		return nil, fmt.Errorf("yaml: unexpected alias node in on.workflow_call")
	case yaml.MappingNode:
		// on:-workflow_call: ...
		for i := 0; i < len(node.Content); i += 2 {
			k := strings.ToLower(node.Content[i].Value)
			if k == SubWorkflowCall {
				var m ReusableWorkflowMetadata
				if err := node.Content[i+1].Decode(&m); err != nil {
					return nil, err
				}
				return &m, nil
			}
		}
		// Fallback for sequence nodes that were previously in a duplicate case
		if len(node.Content) > 0 {
			for _, c := range node.Content {
				if c.Kind == yaml.ScalarNode {
					e := strings.ToLower(c.Value)
					if e == "workflow_call" {
						return &ReusableWorkflowMetadata{}, nil
					}
				}
			}
		}
	}
	return nil, fmt.Errorf(
		"\"workflow_call\" event trigger is not found in \"on:\" at line:%d, column:%d", node.Line, node.Column,
	)
}

// NewLocalReusableWorkflowCache は指定されたプロジェクトのための新しいLocalReusableWorkflowCacheインスタンスを作成
// 'cwd'は絶対ファイルパスとしての現在の作業ディレクトリ
// 'Local'はキャッシュインスタンスがプロジェクト固有であることを意味
// 複数のプロジェクト間で利用することはできません。
func NewLocalReusableWorkflowCache(proj *Project, cwd string, dbg io.Writer) *LocalReusableWorkflowCache {
	return &LocalReusableWorkflowCache{
		proj:  proj,
		cache: map[string]*ReusableWorkflowMetadata{},
		cwd:   cwd,
		dbg:   dbg,
	}
}

func newNullLocalReusableWorkflowCache(dbg io.Writer) *LocalReusableWorkflowCache {
	// Nullキャッシュ, プロジェクトが見つからない場合,またはworkflow pathをworkflow call specに変換できない場合、このキャッシュはnilを返します。
	return &LocalReusableWorkflowCache{dbg: dbg}
}

// LocalReusableWorkflowCacheFactory は、プロジェクトごとにLocalReusableWorkflowCacheインスタンスを作成するためのファクトリオブジェクト
type LocalReusableWorkflowCacheFactory struct {
	caches map[string]*LocalReusableWorkflowCache
	cwd    string
	dbg    io.Writer
}

// NewLocalReusableWorkflowCacheFactory は新しいLocalReusableWorkflowCacheFactoryインスタンスを作成します。
func NewLocalReusableWorkflowCacheFactory(cwd string, dbg io.Writer) *LocalReusableWorkflowCacheFactory {
	return &LocalReusableWorkflowCacheFactory{map[string]*LocalReusableWorkflowCache{}, cwd, dbg}
}

// GetCache はプロジェクトごとに新しい、または既存のLocalReusableWorkflowCacheインスタンスを返します。
// インスタンスが既にプロジェクトのために作成されていた場合、このメソッドは既存のインスタンスを返します。
// それ以外の場合は、新しいインスタンスを作成して返します。
func (f *LocalReusableWorkflowCacheFactory) GetCache(proj *Project) *LocalReusableWorkflowCache {
	if proj == nil {
		return newNullLocalReusableWorkflowCache(f.dbg)
	}

	if c, ok := f.caches[proj.RootDirectory()]; ok {
		return c
	}
	c := NewLocalReusableWorkflowCache(proj, f.cwd, f.dbg)
	f.caches[proj.RootDirectory()] = c
	return c
}
