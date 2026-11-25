//go:build unix

package internal

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// A monotonic epoch records resize events even if dimensions return to their
// original values between polls. poll also drains signals not yet scheduled on
// the watcher goroutine before a keyboard activation or cursor operation.
func watchInlineResize(bump func()) (poll func(), stop func()) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGWINCH)
	end, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-signals:
				bump()
			case <-end:
				return
			}
		}
	}()
	poll = func() {
		for {
			select {
			case <-signals:
				bump()
			default:
				return
			}
		}
	}
	var once sync.Once
	stop = func() { once.Do(func() { signal.Stop(signals); close(end); <-done; poll() }) }
	return
}
