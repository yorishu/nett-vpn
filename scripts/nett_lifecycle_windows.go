// Nett lifecycle extension to Amnezia Box, GPL-3.0-or-later.
package main

import (
    "encoding/json"
    "os"
    "syscall"
    "time"
    "golang.org/x/sys/windows"
)

var nettStopFile, nettReadyFile string

func init() {
    commandRun.Flags().StringVar(&nettStopFile, "nett-stop-file", "", "Nett graceful shutdown request file")
    commandRun.Flags().StringVar(&nettReadyFile, "nett-ready-file", "", "Nett process identity file")
}

func nettWatch(signals chan<- os.Signal) func() {
    done := make(chan struct{})
    if nettStopFile != "" {
        go func() {
            ticker := time.NewTicker(150 * time.Millisecond)
            defer ticker.Stop()
            for {
                select {
                case <-done: return
                case <-ticker.C:
                    if _, err := os.Stat(nettStopFile); err == nil {
                        select { case signals <- syscall.SIGTERM: case <-done: }
                        return
                    }
                }
            }
        }()
    }
    return func() { close(done) }
}

func nettMarkReady() error {
    if nettReadyFile == "" { return nil }
    var created, exited, kernel, user windows.Filetime
    if err := windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &kernel, &user); err != nil { return err }
    data, err := json.Marshal(struct { PID uint32 `json:"pid"`; Created uint64 `json:"created"` }{
        uint32(os.Getpid()), uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime),
    })
    if err != nil { return err }
    if err = os.WriteFile(nettReadyFile+".new", data, 0600); err != nil { return err }
    return os.Rename(nettReadyFile+".new", nettReadyFile)
}

func nettCleanup() {
    if nettReadyFile != "" { _ = os.Remove(nettReadyFile) }
}
