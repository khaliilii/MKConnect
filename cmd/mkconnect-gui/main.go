// Command mkconnect-gui is the desktop app of MKConnect.
package main

import (
	_ "embed"

	"github.com/khaliilii/MKConnect/internal/gui"
)

//go:embed Icon.png
var icon []byte

func main() {
	gui.Run(icon)
}
