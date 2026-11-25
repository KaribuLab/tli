//go:build !unix

package internal

import (
	"context"
	"os"
)

// Closing the CLI-owned input on cancellation unblocks the platform read.
func readFileByte(ctx context.Context, file *os.File, dest []byte) (int, error) {
	type result struct {
		data byte
		n    int
		err  error
	}
	done := make(chan result, 1)
	go func() { var b [1]byte; n, e := file.Read(b[:]); done <- result{b[0], n, e} }()
	select {
	case r := <-done:
		if r.n > 0 {
			dest[0] = r.data
		}
		return r.n, r.err
	case <-ctx.Done():
		file.Close()
		return 0, ctx.Err()
	}
}
