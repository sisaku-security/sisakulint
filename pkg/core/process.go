package core

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"sync"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/execabs"
)

// ConcurrentExecutorは同時に実行されるプロセスの数を制限するための構造体
type ConcurrentExecutor struct {
	ctx  context.Context
	sema *semaphore.Weighted
	wg   sync.WaitGroup
}

// NewConcurrentExecutorはConcurrentExecutorを生成する
func NewConcurrentExecutor(par int) *ConcurrentExecutor {
	return &ConcurrentExecutor{
		ctx:  context.Background(),
		sema: semaphore.NewWeighted(int64(par)),
	}
}

func executeWithStdin(exe string, args []string, stdin string) ([]byte, error) {
	cmd := exec.CommandContext(context.Background(), exe, args...) //nolint:gosec
	cmd.Stderr = nil
	p, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf(" %s failed to get stdin pipe: %w", exe, err)
	}
	if _, err := io.WriteString(p, stdin); err != nil {
		return nil, fmt.Errorf(" %s failed to write stdin: %w", exe, err)
	}
	p.Close()
	return cmd.Output()
}

func (ce *ConcurrentExecutor) execute(eg *errgroup.Group, exe string, args []string, stdin string, callback func([]byte, error) error) {
	if err := ce.sema.Acquire(ce.ctx, 1); err != nil {
		eg.Go(func() error {
			return fmt.Errorf("failed to acquire semaphore: %w", err)
		})
		return
	}
	ce.wg.Add(1)
	eg.Go(func() error {
		defer ce.wg.Done()
		output, err := executeWithStdin(exe, args, stdin)
		ce.sema.Release(1)
		return callback(output, err)
	})
}

// Waitはgoroutineの終了を待つ
func (ce *ConcurrentExecutor) Wait() {
	ce.wg.Wait()
}

// CommandRunnerは指定された実行ファイル用の外部コマンドランナーを作成
func (ce *ConcurrentExecutor) CommandRunner(exe string) (*ExternalCommandRunner, error) {
	p, err := execabs.LookPath(exe)
	if err != nil {
		return nil, err
	}
	return &ExternalCommandRunner{
		ce:  ce,
		exe: p,
	}, nil
}

// ExternalCommandRunnerは外部コマンドを実行するための構造体
type ExternalCommandRunner struct {
	ce  *ConcurrentExecutor
	eg  errgroup.Group
	exe string
}

// Executeは指定された引数とstdinでコマンドを実行
func (ecr *ExternalCommandRunner) Execute(args []string, stdin string, callback func([]byte, error) error) {
	ecr.ce.execute(&ecr.eg, ecr.exe, args, stdin, callback)
}

// Waitはgoroutineの終了を待つ
func (ecr *ExternalCommandRunner) Wait() error {
	return ecr.eg.Wait()
}
