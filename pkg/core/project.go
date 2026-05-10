package core

//search for ".github/workflow" in the file

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ProjectはGithubプロジェクト- 1つのリポジトリに対応
type Project struct {
	root   string
	config *Config
	boiler *Boiler
}

func getAbsolutePath(path string) string {
	if p, err := filepath.Abs(path); err == nil {
		path = p
	}
	return path
}

func isPathInsideRoot(root, target string) bool {
	root = filepath.Clean(getAbsolutePath(root))
	target = filepath.Clean(getAbsolutePath(target))
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	return rel == "." || (!filepath.IsAbs(rel) && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func validatePathInsideRoot(root, target string) error {
	root = filepath.Clean(getAbsolutePath(root))
	target = filepath.Clean(getAbsolutePath(target))
	if !isPathInsideRoot(root, target) {
		return fmt.Errorf("path traversal detected: %q escapes %q", target, root)
	}

	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(target); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	realTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		return err
	}
	if !isPathInsideRoot(realRoot, realTarget) {
		return fmt.Errorf("path traversal detected: %q escapes %q", realTarget, realRoot)
	}
	return nil
}

// ぷろじぇくとの探索して指定されたパスが所属するプロジェクトを見つけることで新しいProjectインスタンスを作成する
func locateProject(path string) (*Project, error) {
	destinations := getAbsolutePath(path)
	for {
		if s, err := os.Stat(filepath.Join(destinations, ".github", "workflows")); err == nil && s.IsDir() {
			if _, err := os.Stat(filepath.Join(destinations, ".git")); err == nil {
				return NewProject(destinations)
			}
		}
		pos := filepath.Dir(destinations)
		if pos == destinations {
			return nil, fmt.Errorf("not found")
		}
		destinations = pos
	}
}

// 新しいインスタンスを作成するリポジトリのrootdirへのfilepathを再利用
func NewProject(root string) (*Project, error) {
	c, err := loadRepoConfig(root)
	if err != nil {
		return nil, err
	}
	d, err := loadBoiler(root)
	if err != nil {
		return nil, err
	}
	return &Project{root: root, config: c, boiler: d}, nil
}

// githubプロジェクトのルートディレクトリを返す
func (project *Project) RootDirectory() string {
	return project.root
}

// githubプロジェクトの"/.github/workflows"ディレクトリを返す
func (project *Project) WorkflowDirectory() string {
	return filepath.Join(project.root, ".github", "workflows")
}

// プロジェクトが指定されたファイルを知っている場合はtrueを返す
func (project *Project) IsKnown(path string) bool {
	return strings.HasPrefix(getAbsolutePath(path), project.root)
}

// githubプロジェクトのconfigオブジェクトを返す
func (project *Project) ProjectConfig() *Config {
	return project.config
}

// Projectsはプロジェクトのset , 前に作られたprojectインスタンスをキャッシュして再利用
type Projects struct {
	known []*Project
}

// 新しいProjectsインスタンスを作成する
func NewProjects() *Projects {
	return &Projects{}
}

// パスが所属数rProjectインスタンスを返す. パスが見つからない場合はnilを返す
func (projects *Projects) GetProjectForPath(path string) (*Project, error) {
	for _, p := range projects.known {
		if p.IsKnown(path) {
			return p, nil
		}
	}
	pro, err := locateProject(path)
	if err != nil {
		return nil, err
	}
	if projects != nil {
		projects.known = append(projects.known, pro)
	}
	return pro, nil
}
