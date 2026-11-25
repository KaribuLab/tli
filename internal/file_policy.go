package internal

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

func DefaultLimits() Limits {
	return Limits{MaxFileBytes: 1 << 20, MaxTotalBytes: 50 << 20, MaxFiles: 10000}
}
func ValidateLimits(l Limits) error {
	if l.MaxFileBytes <= 0 || l.MaxTotalBytes <= 0 || l.MaxFiles <= 0 {
		return fmt.Errorf("los límites deben ser positivos")
	}
	return nil
}
func pathPolicy(path, mode string) string {
	if mode == "120000" {
		return "symlink"
	}
	if mode == "160000" {
		return "submodule"
	}
	base := strings.ToLower(filepath.Base(path))
	if base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") || base == "id_rsa" || base == "id_ed25519" {
		return "sensitive"
	}
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		switch part {
		case "node_modules", "vendor", "dist", "build", ".next", ".venv", "venv", "__pycache__":
			return "generated"
		}
	}
	return ""
}
func binaryContent(data []byte) bool { return bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) }
