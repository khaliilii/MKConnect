//go:build !darwin

package gateway

import "context"

// FollowInternetSharing is for macOS, whose Internet Sharing bypasses routes.
func FollowInternetSharing(context.Context, string, string) {}

// StopFollowingInternetSharing does nothing here.
func StopFollowingInternetSharing() {}
