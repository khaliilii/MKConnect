package main

import (
	"fmt"
	"os"

	"github.com/khaliilii/MKConnect/internal/cli"
)

func main() {
	if err := cli.NewRoot().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		os.Exit(1)
	}
}
