//go:build unix

package internal

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// Poll in bounded intervals rather than blocking a terminal read across SIGINT.
// No extra reader goroutine and no modifications to the caller's descriptor.
func readFileByte(ctx context.Context, file *os.File, dest []byte) (int, error) {
	for {
		if e := ctx.Err(); e != nil {
			return 0, e
		}
		descriptors := []unix.PollFd{{Fd: int32(file.Fd()), Events: unix.POLLIN}}
		n, e := unix.Poll(descriptors, 50)
		if errors.Is(e, unix.EINTR) {
			continue
		}
		if e != nil {
			return 0, e
		}
		if n == 0 {
			continue
		}
		if e = ctx.Err(); e != nil {
			return 0, e
		}
		return file.Read(dest)
	}
}
