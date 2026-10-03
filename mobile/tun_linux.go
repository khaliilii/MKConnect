package mkmobile

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// tunnelName asks the kernel for the name of the TUN behind fd.
func tunnelName(fd int32) (string, error) {
	var ifr [unix.IFNAMSIZ + 64]byte
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNGETIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return "", fmt.Errorf("query TUN name: %w", errno)
	}
	return unix.ByteSliceToString(ifr[:]), nil
}

func dup(fd int) (int, error) { return syscall.Dup(fd) }
