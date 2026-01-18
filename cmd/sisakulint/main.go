//go:build !js || !wasm

package main

import (
	"os"

	"github.com/sisaku-security/sisakulint/pkg/core"
)

func main() {
	cmd := core.Command{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
	os.Exit(cmd.Main(os.Args))
}
