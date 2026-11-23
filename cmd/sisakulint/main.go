// Command sisakulint checks the workflows and action.yml files of a
// repository; see package actions/cli.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/gh-intel/sisakulint/actions/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	st, err := os.Stdout.Stat()
	terminal := err == nil && st.Mode()&os.ModeCharDevice != 0
	code := cli.Main(ctx, cli.Env{Args: os.Args[1:], Getenv: os.Getenv, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Terminal: terminal})
	stop()
	os.Exit(code)
}
