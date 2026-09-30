//go:build android

package main

// Fyne's Android driver and sing-box's certificate store (common/jni) both
// define JNI_OnLoad. Each only checks or records the JavaVM and returns
// JNI_VERSION_1_6, so letting the linker keep one definition is safe; if
// sing-box's copy is dropped it falls back to Go's system certificate pool.

// #cgo LDFLAGS: -Wl,--allow-multiple-definition
import "C"
