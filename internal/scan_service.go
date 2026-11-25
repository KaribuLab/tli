package internal

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

type ScanService struct {
	Planner   Planner
	Snapshots SnapshotBuilder
	API       *APIClient
	Wait      Waiter
}

func (s ScanService) Preview(ctx context.Context, o ScanOptions) (ScanPlan, error) {
	return s.Planner.Plan(ctx, o)
}
func (s ScanService) Scan(ctx context.Context, o ScanOptions, confirmed string, progress ProgressSink) (StatusResult, error) {
	var result StatusResult
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = time.Hour
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	plan, e := s.Preview(ctx, o)
	if e != nil {
		return result, e
	}
	if confirmed != "" && plan.Fingerprint != confirmed {
		return result, &ScanError{Kind: "plan-changed", Err: fmt.Errorf("los archivos cambiaron; confirma un nuevo preview")}
	}
	if len(plan.Files) == 0 {
		return result, fmt.Errorf("no hay archivos de texto incluidos para analizar")
	}
	emit := func(phase, id string) {
		if progress != nil {
			progress(ProgressEvent{Phase: phase, ScanID: id, Files: len(plan.Files), Bytes: plan.TotalBytes})
		}
	}
	emit("preparing", "")
	snapshot, e := s.Snapshots.Build(ctx, plan)
	if e != nil {
		return result, e
	}
	defer snapshot.Close()
	manifest, e := MarshalScanManifest(plan)
	if e != nil {
		return result, e
	}
	manifestPath := filepath.Join(snapshot.Directory, ScanManifestName)
	if e = os.WriteFile(manifestPath, manifest, 0600); e != nil {
		return result, e
	}
	client := s.API
	if client == nil {
		config, e := getAPIConfig()
		if e != nil {
			return result, e
		}
		client = &APIClient{Config: *config}
	}
	emit("uploading", "")
	batch := uuid.NewString()
	names := make([]string, 0, len(plan.Files))
	for _, f := range plan.Files {
		names = append(names, f.Path)
	}
	urls, e := client.Presign(ctx, batch, []PresignUpload{
		{Name: "snapshot.tar.gz", ContentType: "application/x-tar+gzip"},
		{Name: ScanManifestName, ContentType: "application/json"},
	}, names)
	if e != nil {
		return result, e
	}
	if e = client.Upload(ctx, urls["snapshot.tar.gz"], snapshot.ArchivePath); e != nil {
		return result, e
	}
	if e = client.Upload(ctx, urls[ScanManifestName], manifestPath); e != nil {
		return result, e
	}
	id, e := client.Start(ctx, RunScanInput{BatchId: batch, RepositoryURL: plan.Repository.URL, Branch: plan.Repository.Branch})
	if e != nil {
		return result, e
	}
	emit("analyzing", id)
	waiter := s.Wait
	if waiter.Client == nil {
		waiter.Client = client
	}
	result, e = waiter.Wait(ctx, id, progress)
	if e == nil {
		emit("completed", id)
	}
	return result, e
}
