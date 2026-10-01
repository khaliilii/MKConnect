//go:build freebsd || netbsd || openbsd

package main

// go-gl/glfw v3.4 compiles glfw/src/null_joystick.c twice on the BSDs (from
// c_glfw.go and c_glfw_bsd.go), so its null joystick functions are defined
// twice. Both copies are the same code; let the linker keep one.

// #cgo LDFLAGS: -Wl,--allow-multiple-definition
import "C"
