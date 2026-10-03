//go:build !linux

package mkmobile

import "errors"

// The VPN bridge only runs on Android; other systems use the desktop app.
func tunnelName(int32) (string, error) { return "", errors.New("TUN bridge is only for Android") }

func dup(int) (int, error) { return 0, errors.New("TUN bridge is only for Android") }
