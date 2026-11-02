package elevate

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// The elevated process supervises the helper rather than being it: a crash
// of the helper (a panic in a core takes the whole process down) would
// otherwise end the connection, and starting a new helper asks for the
// administrator password again. The supervisor already has the rights, so it
// starts the helper again at once with the connection it was running.
//
// workerEnv marks the helper process the supervisor starts; resumeEnv tells it
// to run the connection its crashed predecessor was running.
const (
	workerEnv = "MKCONNECT_HELPER_WORKER"
	resumeEnv = "MKCONNECT_HELPER_RESUME"
)

// A helper that crashes maxCrashes times within crashWindow is given up on:
// the app is told, instead of a connection that keeps falling over.
const (
	maxCrashes  = 3
	crashWindow = time.Minute
)

// runWorker runs one helper process and waits for it; replaced in tests.
// Its output goes to logFile, a crash report included: Go writes that to
// file descriptor 2, which the app never sees otherwise.
var runWorker = func(dir string, resume bool, logFile *os.File) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, HelperFlag, dir)
	cmd.Env = append(os.Environ(), workerEnv+"=1")
	if resume {
		cmd.Env = append(cmd.Env, resumeEnv+"=1")
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	return cmd.Run()
}

// Supervise is what the elevated process runs (HelperFlag): it keeps the
// helper (Serve) running as its child until the helper ends on its own, the
// app quits or the helper keeps crashing. Started by the supervisor, the same
// executable is the helper itself.
func Supervise(dir string) error {
	if os.Getenv(workerEnv) != "" {
		return serve(dir, os.Getenv(resumeEnv) != "")
	}
	if err := checkDir(dir); err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(dir, "helper.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	var crashes []time.Time
	for resume := false; ; resume = true {
		err := runWorker(dir, resume, logFile)
		if err == nil || appGone(dir) {
			return nil
		}
		now := time.Now()
		recent := crashes[:0]
		for _, c := range crashes {
			if now.Sub(c) < crashWindow {
				recent = append(recent, c)
			}
		}
		crashes = append(recent, now)
		if len(crashes) >= maxCrashes {
			cause := fmt.Errorf("the TUN helper crashed %d times in a minute (%v); see its log", len(crashes), err)
			seq := 0
			if req, rerr := readRequest(dir); rerr == nil {
				seq = req.Seq
			}
			return (&statusWriter{dir: dir, pid: os.Getpid()}).fail(seq, cause)
		}
		log.Printf("💥 the TUN helper crashed (%v); starting it again with the same connection", err)
		time.Sleep(time.Second)
	}
}

// appGone reports whether the helper isn't wanted any more: the app asked it
// to quit, or the app isn't running.
func appGone(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "quit")); err == nil {
		return true
	}
	req, err := readRequest(dir)
	return err == nil && req.ParentPID > 0 && !processAlive(req.ParentPID)
}
