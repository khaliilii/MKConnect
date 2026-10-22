// Command mkconnect-gui is the desktop app of MKConnect.
package main

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/khaliilii/MKConnect/internal/elevate"
	"github.com/khaliilii/MKConnect/internal/engine"
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
	// Started by the app, with administrator rights, to put back a DNS
	// setting an interrupted TUN connection left (macOS).
	if len(os.Args) == 2 && os.Args[1] == gui.RepairDNSFlag {
		cleaned, err := engine.RepairTunnelDNS()
		for _, c := range cleaned {
			fmt.Println("restored:", c)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	gui.Run(icon)
}
