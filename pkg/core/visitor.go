package core

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// TreeVisitorはworkflowのsyntax'streeをトラバースするためのinterface
type TreeVisitor interface {
	VisitStep(node *ast.Step) error
	VisitJobPre(node *ast.Job) error
	VisitJobPost(node *ast.Job) error
	VisitWorkflowPre(node *ast.Workflow) error
	VisitWorkflowPost(node *ast.Workflow) error
}

// SyntaxTreeVisitorはworkflowのsyntax'streeをトラバースするためのinterface
type SyntaxTreeVisitor struct {
	passes []TreeVisitor
	debugW io.Writer
}

// NewSyntaxTreeVisitorはSyntaxTreeVisitorを生成する
func NewSyntaxTreeVisitor() *SyntaxTreeVisitor {
	return &SyntaxTreeVisitor{}
}

// AddVisitorはvisitorを追加する
func (s *SyntaxTreeVisitor) AddVisitor(visitor TreeVisitor) {
	s.passes = append(s.passes, visitor)
}

// EnableDebugOutputはdebug出力を有効にする
func (s *SyntaxTreeVisitor) EnableDebugOutput(writer io.Writer) {
	s.debugW = writer
}

// logElapsedTimeは経過時間を出力する
func (s *SyntaxTreeVisitor) logreportElapsedTime(task string, startTime time.Time) {
	if s.debugW != nil {
		duration := time.Since(startTime).Milliseconds()
		fmt.Fprintf(s.debugW, "[SyntaxTreeVisitor] %s took %v ms\n", task, duration)
	}
}

// visits given syntax tree in depth-first order
func (s *SyntaxTreeVisitor) VisitTree(node *ast.Workflow) error {
	var startTime time.Time
	if s.debugW != nil {
		startTime = time.Now()
	}

	for _, p := range s.passes {
		if err := p.VisitWorkflowPre(node); err != nil {
			return err
		}
	}

	if s.debugW != nil {
		defer s.logreportElapsedTime("VisitWorkflowPre", startTime)
		startTime = time.Now()
	}

	for _, job := range orderedWorkflowJobs(node) {
		if err := s.visitJob(job); err != nil {
			return err
		}
	}

	if s.debugW != nil {
		msg := fmt.Sprintf("VisitJob was taking %d jobs", len(node.Jobs))
		defer s.logreportElapsedTime(msg, startTime)
		startTime = time.Now()
	}

	for _, p := range s.passes {
		if err := p.VisitWorkflowPost(node); err != nil {
			return err
		}
	}

	if s.debugW != nil {
		defer s.logreportElapsedTime("VisitWorkflowPost", startTime)
	}

	return nil
}

// orderedWorkflowJobs returns a deterministic job visit order: source order
// among currently runnable jobs, with declared needs visited before dependents.
func orderedWorkflowJobs(node *ast.Workflow) []*ast.Job {
	if node == nil || len(node.Jobs) == 0 {
		return nil
	}

	jobs := make([]*ast.Job, 0, len(node.Jobs))
	byID := make(map[string]*ast.Job, len(node.Jobs))
	for id, job := range node.Jobs {
		if job == nil {
			continue
		}
		jobs = append(jobs, job)
		if normalizedID := normalizeJobID(id); normalizedID != "" {
			byID[normalizedID] = job
		}
		if job.ID != nil {
			if normalizedID := normalizeJobID(job.ID.Value); normalizedID != "" {
				byID[normalizedID] = job
			}
		}
	}

	sort.SliceStable(jobs, func(i, j int) bool {
		return jobSourceLess(jobs[i], jobs[j])
	})

	indegree := make(map[*ast.Job]int, len(jobs))
	dependents := make(map[*ast.Job][]*ast.Job, len(jobs))
	for _, job := range jobs {
		indegree[job] = 0
	}
	for _, job := range jobs {
		seenDeps := make(map[*ast.Job]bool)
		for _, need := range job.Needs {
			if need == nil {
				continue
			}
			dep := byID[normalizeJobID(need.Value)]
			if dep == nil || seenDeps[dep] {
				continue
			}
			seenDeps[dep] = true
			indegree[job]++
			dependents[dep] = append(dependents[dep], job)
		}
	}

	queued := make(map[*ast.Job]bool, len(jobs))
	ready := make([]*ast.Job, 0, len(jobs))
	for _, job := range jobs {
		if indegree[job] == 0 {
			ready = append(ready, job)
			queued[job] = true
		}
	}

	var ordered []*ast.Job
	emitted := make(map[*ast.Job]bool, len(jobs))
	for len(ordered) < len(jobs) {
		if len(ready) == 0 {
			// Cycles and invalid self-dependencies are reported elsewhere. Keep
			// traversal total by falling back to source order for remaining jobs.
			for _, job := range jobs {
				if !emitted[job] {
					ready = append(ready, job)
					queued[job] = true
					break
				}
			}
		}

		sort.SliceStable(ready, func(i, j int) bool {
			return jobSourceLess(ready[i], ready[j])
		})

		job := ready[0]
		ready = ready[1:]
		queued[job] = false
		if emitted[job] {
			continue
		}

		emitted[job] = true
		ordered = append(ordered, job)
		for _, dependent := range dependents[job] {
			if emitted[dependent] {
				continue
			}
			if indegree[dependent] > 0 {
				indegree[dependent]--
			}
			if indegree[dependent] == 0 && !queued[dependent] {
				ready = append(ready, dependent)
				queued[dependent] = true
			}
		}
	}

	return ordered
}

func normalizeJobID(id string) string {
	return strings.ToLower(id)
}

func jobSourceLess(a, b *ast.Job) bool {
	aPos := jobPosition(a)
	bPos := jobPosition(b)
	if aPos != nil && bPos != nil {
		if aPos.Line != bPos.Line {
			return aPos.Line < bPos.Line
		}
		if aPos.Col != bPos.Col {
			return aPos.Col < bPos.Col
		}
	}
	if aPos != nil && bPos == nil {
		return true
	}
	if aPos == nil && bPos != nil {
		return false
	}
	return jobSortID(a) < jobSortID(b)
}

func jobPosition(job *ast.Job) *ast.Position {
	if job == nil {
		return nil
	}
	return job.Pos
}

func jobSortID(job *ast.Job) string {
	if job == nil || job.ID == nil {
		return ""
	}
	return job.ID.Value
}

// visitJobはjobを訪問する
func (s *SyntaxTreeVisitor) visitJob(node *ast.Job) error {
	var startTime time.Time
	if s.debugW != nil {
		startTime = time.Now()
	}

	for _, p := range s.passes {
		if err := p.VisitJobPre(node); err != nil {
			return err
		}
	}

	if s.debugW != nil {
		defer s.logreportElapsedTime("VisitJobPre", startTime)
		startTime = time.Now()
	}

	for _, step := range node.Steps {
		if err := s.visitStep(step); err != nil {
			return err
		}
	}

	if s.debugW != nil {
		msg := fmt.Sprintf("VisitStep was taking %d steps", len(node.Steps))
		defer s.logreportElapsedTime(msg, startTime)
		startTime = time.Now()
	}

	for _, p := range s.passes {
		if err := p.VisitJobPost(node); err != nil {
			return err
		}
	}

	if s.debugW != nil {
		jobID := "<nil>"
		if node.ID != nil {
			jobID = node.ID.Value
		}
		msg := fmt.Sprintf("VisitJobPost was taking %d steps, at job %q", len(node.Steps), jobID)
		defer s.logreportElapsedTime(msg, startTime)
	}

	return nil
}

// visitStepはstepを訪問する
func (s *SyntaxTreeVisitor) visitStep(node *ast.Step) error {
	var startTime time.Time
	if s.debugW != nil {
		startTime = time.Now()
	}

	for _, p := range s.passes {
		if err := p.VisitStep(node); err != nil {
			return err
		}
	}

	if s.debugW != nil {
		stepName := "<unnamed>"
		if node.Name != nil && node.Name.Value != "" {
			stepName = node.Name.Value
		} else if node.ID != nil && node.ID.Value != "" {
			stepName = node.ID.Value
		}
		msg := fmt.Sprintf("VisitStep at %s, step %q", node.Pos, stepName)
		defer s.logreportElapsedTime(msg, startTime)
	}

	return nil
}
