// Command mkconnect-gui is the desktop app of MKConnect.
package main

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/khaliilii/MKConnect/internal/elevate"
	"github.com/khaliilii/MKConnect/internal/gui"
)

//go:embed Icon.png
var icon []byte

func main() {
	// Started by the app itself, with administrator rights, to run TUN mode.
	if len(os.Args) == 3 && os.Args[1] == elevate.HelperFlag {
		if err := elevate.Serve(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	gui.Run(icon)
}
