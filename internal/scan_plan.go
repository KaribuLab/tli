package internal

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Planner struct{ Git GitSource }
type gitEntry struct{ path, mode, oid string }

func digest(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }
func (g GitSource) ReadBlob(ctx context.Context, root, oid string, maxBytes int64) ([]byte, error) {
	if len(oid) != 40 && len(oid) != 64 {
		return nil, fmt.Errorf("objeto Git no válido")
	}
	for _, c := range oid {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return nil, fmt.Errorf("objeto Git no válido")
		}
	}
	size, e := g.run(ctx, root, "cat-file", "-s", oid)
	if e != nil {
		return nil, e
	}
	n, e := strconv.ParseInt(strings.TrimSpace(string(size)), 10, 64)
	if e != nil || n < 0 || n > maxBytes {
		return nil, fmt.Errorf("archivo excede presupuesto")
	}
	return g.run(ctx, root, "cat-file", "blob", oid)
}
func readWorking(root, path string, max int64) ([]byte, error) {
	if path == "" || filepath.IsAbs(path) || filepath.Clean(path) != path || strings.Contains(path, "\\") || strings.HasPrefix(path, "../") {
		return nil, fmt.Errorf("ruta no segura")
	}
	r, e := os.OpenRoot(root)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := range parts {
		info, e := r.Lstat(strings.Join(parts[:i+1], "/"))
		if e != nil {
			return nil, e
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("enlace no permitido")
		}
	}
	before, e := r.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !before.Mode().IsRegular() || before.Size() > max {
		return nil, fmt.Errorf("archivo inválido o excede presupuesto")
	}
	f, e := r.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !os.SameFile(before, actual) {
		return nil, fmt.Errorf("archivo cambió durante lectura")
	}
	data, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil {
		return nil, e
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("archivo excede presupuesto")
	}
	return data, nil
}
func (p Planner) Plan(ctx context.Context, o ScanOptions) (ScanPlan, error) {
	var plan ScanPlan
	if e := ValidateLimits(o.Limits); e != nil {
		return plan, e
	}
	if o.Scope != ScopeFull && o.Scope != ScopeCommit && o.Scope != ScopeStaged {
		return plan, fmt.Errorf("alcance inválido")
	}
	id, e := p.Git.Identity(ctx, o)
	if e != nil {
		return plan, e
	}
	plan.Repository = id
	plan.Scope = o.Scope
	plan.Files = []PlannedFile{}
	plan.Excluded = []ExcludedFile{}
	entries := map[string]gitEntry{}
	selected := map[string]bool{}
	if o.Scope == ScopeCommit {
		raw, e := p.Git.run(ctx, id.Root, "ls-tree", "-r", "-z", id.Commit)
		if e != nil {
			return plan, e
		}
		for _, line := range strings.Split(string(raw), "\x00") {
			if line == "" {
				continue
			}
			meta, path, ok := strings.Cut(line, "\t")
			fields := strings.Fields(meta)
			if !ok || len(fields) != 3 {
				return plan, fmt.Errorf("árbol Git no válido")
			}
			entries[path] = gitEntry{path, fields[0], fields[2]}
		}
		parents, e := p.Git.run(ctx, id.Root, "rev-list", "--parents", "-n", "1", id.Commit)
		if e != nil {
			return plan, e
		}
		parts := strings.Fields(string(parents))
		if len(parts) == 1 {
			for name := range entries {
				selected[name] = true
			}
		} else {
			raw, e = p.Git.run(ctx, id.Root, "diff", "--name-only", "--no-renames", "-z", parts[1], id.Commit, "--")
			if e != nil {
				return plan, e
			}
			for _, n := range strings.Split(string(raw), "\x00") {
				if n != "" {
					selected[n] = true
				}
			}
		}
	} else if o.Scope == ScopeStaged {
		// A single raw diff yields each selected path, mode and immutable blob OID.
		// Reading ls-files separately can mix different versions of a changing index.
		raw, e := p.Git.run(ctx, id.Root, "diff", "--cached", "--raw", "--no-abbrev", "--no-renames", "-z", "--")
		if e != nil {
			return plan, e
		}
		records := strings.Split(string(raw), "\x00")
		for i := 0; i < len(records) && records[i] != ""; i += 2 {
			if i+1 >= len(records) {
				return plan, fmt.Errorf("diff de índice no válido")
			}
			fields := strings.Fields(records[i])
			if len(fields) != 5 || !strings.HasPrefix(fields[0], ":") {
				return plan, fmt.Errorf("diff de índice no válido")
			}
			name := records[i+1]
			selected[name] = true
			if fields[4] == "U" {
				return plan, fmt.Errorf("índice con conflictos sin resolver")
			}
			if fields[4] != "D" {
				entries[name] = gitEntry{name, fields[1], fields[3]}
			}
		}
	} else {
		raw, e := p.Git.run(ctx, id.Root, "ls-files", "--stage", "-z")
		if e != nil {
			return plan, e
		}
		for _, line := range strings.Split(string(raw), "\x00") {
			if line == "" {
				continue
			}
			meta, path, ok := strings.Cut(line, "\t")
			fields := strings.Fields(meta)
			if !ok || len(fields) != 3 {
				return plan, fmt.Errorf("índice Git no válido")
			}
			if fields[2] != "0" {
				return plan, fmt.Errorf("índice con conflictos sin resolver")
			}
			entries[path] = gitEntry{path, fields[0], fields[1]}
		}
		for name := range entries {
			selected[name] = true
		}
	}
	paths := make([]string, 0, len(selected))
	for n := range selected {
		paths = append(paths, n)
	}
	sort.Strings(paths)
	for _, name := range paths {
		if e := ctx.Err(); e != nil {
			return plan, e
		}
		entry, exists := entries[name]
		if !exists {
			plan.Excluded = append(plan.Excluded, ExcludedFile{name, "deleted"})
			continue
		}
		mode := entry.mode
		if o.Scope == ScopeFull && mode != "160000" {
			info, e := os.Lstat(filepath.Join(id.Root, name))
			if e != nil {
				return plan, fmt.Errorf("no se pudo leer archivo seleccionado %q", name)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				mode = "120000"
			}
		}
		if reason := pathPolicy(name, mode); reason != "" {
			plan.Excluded = append(plan.Excluded, ExcludedFile{name, reason})
			continue
		}
		oid := entry.oid
		var data []byte
		if o.Scope == ScopeFull {
			oid = ""
			data, e = readWorking(id.Root, name, o.Limits.MaxFileBytes)
		} else {
			data, e = p.Git.ReadBlob(ctx, id.Root, oid, o.Limits.MaxFileBytes)
		}
		if e != nil {
			return plan, fmt.Errorf("no se pudo preparar %q: %w", name, e)
		}
		if binaryContent(data) {
			plan.Excluded = append(plan.Excluded, ExcludedFile{name, "binary"})
			continue
		}
		if len(plan.Files) >= o.Limits.MaxFiles || int64(len(data)) > o.Limits.MaxTotalBytes-plan.TotalBytes {
			return plan, fmt.Errorf("snapshot excede presupuesto total")
		}
		plan.TotalBytes += int64(len(data))
		plan.Files = append(plan.Files, PlannedFile{Path: name, BlobOID: oid, SHA256: digest(data), Size: int64(len(data))})
	}
	encoded, e := json.Marshal(struct {
		Plan   ScanPlan
		Limits Limits
	}{plan, o.Limits})
	if e != nil {
		return plan, e
	}
	plan.Fingerprint = digest(encoded)
	return plan, nil
}
