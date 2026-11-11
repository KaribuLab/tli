package internal

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Snapshot struct {
	Directory, ArchivePath string
	Plan                   ScanPlan
}

func (s *Snapshot) Close() error {
	if s == nil {
		return nil
	}
	return os.RemoveAll(s.Directory)
}

type SnapshotBuilder struct {
	Git      GitSource
	TempRoot string
}

func validArchivePath(path string) bool {
	return path != "" && !filepath.IsAbs(path) && filepath.Clean(path) == path && path != ".." && !strings.HasPrefix(path, "../") && !strings.ContainsAny(path, "\\\x00")
}
func writeSnapshotArchive(ctx context.Context, dest io.Writer, plan ScanPlan, read func(PlannedFile) ([]byte, error)) error {
	gz := gzip.NewWriter(dest)
	tw := tar.NewWriter(gz)
	defer gz.Close()
	defer tw.Close()
	var total int64
	for _, file := range plan.Files {
		if e := ctx.Err(); e != nil {
			return e
		}
		if !validArchivePath(file.Path) || file.Size < 0 {
			return fmt.Errorf("ruta/tamaño no válido")
		}
		data, e := read(file)
		if e != nil {
			return e
		}
		if int64(len(data)) != file.Size || digest(data) != file.SHA256 {
			return &ScanError{Kind: "plan-changed", Err: fmt.Errorf("el contenido cambió; revisa el preview")}
		}
		if file.Size > plan.TotalBytes-total {
			return fmt.Errorf("snapshot excede presupuesto")
		}
		total += file.Size
		if e = tw.WriteHeader(&tar.Header{Name: file.Path, Mode: 0600, Size: file.Size, Typeflag: tar.TypeReg}); e != nil {
			return e
		}
		if _, e = tw.Write(data); e != nil {
			return e
		}
	}
	if total != plan.TotalBytes {
		return fmt.Errorf("tamaño del plan no válido")
	}
	if e := tw.Close(); e != nil {
		return e
	}
	return gz.Close()
}
func (b SnapshotBuilder) Build(ctx context.Context, plan ScanPlan) (snapshot *Snapshot, err error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	dir, e := os.MkdirTemp(b.TempRoot, "tli-snapshot-")
	if e != nil {
		return nil, e
	}
	s := &Snapshot{Directory: dir, ArchivePath: filepath.Join(dir, "snapshot.tar.gz"), Plan: plan}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	f, e := os.OpenFile(s.ArchivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	e = writeSnapshotArchive(ctx, f, plan, func(p PlannedFile) ([]byte, error) {
		if p.BlobOID != "" {
			return b.Git.ReadBlob(ctx, plan.Repository.Root, p.BlobOID, p.Size)
		}
		return readWorking(plan.Repository.Root, p.Path, p.Size)
	})
	if e != nil {
		return nil, e
	}
	if e = f.Close(); e != nil {
		return nil, e
	}
	return s, nil
}
