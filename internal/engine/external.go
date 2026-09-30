package engine

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

// externalEngine runs a user-supplied sing-box or xray binary with a generated
// config. Both accept `run -c <file>`.
type externalEngine struct {
	cmd      *exec.Cmd
	confPath string
	done     chan error
	exited   chan struct{}
	once     sync.Once
}

func startExternal(binary string, cfg obj) (Engine, error) {
	data, err := marshal(cfg)
	if err != nil {
		return nil, err
	}
	f, err := os.CreateTemp("", "mkconnect-*.json") // created 0600
	if err != nil {
		return nil, err
	}
	confPath := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(confPath)
		return nil, err
	}
	f.Close()

	cmd := exec.Command(binary, "run", "-c", confPath)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		os.Remove(confPath)
		return nil, fmt.Errorf("start %s: %w", binary, err)
	}
	e := &externalEngine{cmd: cmd, confPath: confPath, done: make(chan error, 1), exited: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		close(e.exited)
		if err == nil {
			err = fmt.Errorf("%s exited", binary)
		}
		e.done <- err
	}()
	return e, nil
}

func (e *externalEngine) Done() <-chan error { return e.done }

func (e *externalEngine) Close() error {
	e.once.Do(func() {
		defer os.Remove(e.confPath)
		select {
		case <-e.exited:
			return
		default:
		}
		// Windows can't deliver SIGINT to another process, so kill directly there.
		if runtime.GOOS == "windows" {
			e.cmd.Process.Kill()
		} else {
			e.cmd.Process.Signal(os.Interrupt)
		}
		select {
		case <-e.exited:
		case <-time.After(5 * time.Second):
			e.cmd.Process.Kill()
			<-e.exited
		}
	})
	return nil
}
