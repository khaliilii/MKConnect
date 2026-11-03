//go:build !darwin && !linux && !windows

package killswitch

import (
	"os"
	"path/filepath"
)

func defaultStateDir() string { return filepath.Join(os.TempDir(), "mkconnect") }

func engageRules(string) error { return ErrUnsupported }

func releaseRules() error { return nil }
