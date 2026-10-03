//go:build tools

package mkmobile

// gomobile bind needs golang.org/x/mobile/bind in the module.
import _ "golang.org/x/mobile/bind"
