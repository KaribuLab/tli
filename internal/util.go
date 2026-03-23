package internal

import "os"

func isTrace() bool {
	return os.Getenv("TLI_LOG_LEVEL") == "trace"
}
