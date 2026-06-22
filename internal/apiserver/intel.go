package apiserver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/authz"
	"github.com/detailtech/oss-ngfw/internal/contentpkg"
	"github.com/detailtech/oss-ngfw/internal/intel"
	"github.com/detailtech/oss-ngfw/internal/store"
)

// IntelServer implements openngfw.v1.IntelService.
type IntelServer struct {
	openngfwv1.UnimplementedIntelServiceServer

	Store   *store.Store
	Updater *intel.Updater
	// ContentDir contains package manifests under app-id/, threat-id/,
	// and intel-feeds/. It defaults to <data-dir>/content in controld.
	ContentDir string
	// ContentImportDir is the only server-local directory from which API
	// operators may promote content packages. Relative source paths are
	// resolved inside this directory.
	ContentImportDir string
}

var appendContentPackageAudit = func(st *store.Store, entry store.AuditEntry) error {
	return st.AppendAudit(entry)
}

// ListFeeds returns the registry plus enablement state from the running
// policy, and any custom feeds it defines.
func (s *IntelServer) ListFeeds(_ context.Context, _ *openngfwv1.ListFeedsRequest) (*openngfwv1.ListFeedsResponse, error) {
	pol, _, err := s.Store.GetRunning()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read running policy: %v", err)
	}
	enabled := map[string]bool{}
	for _, fe := range pol.GetIntel().GetFeeds() {
		enabled[fe.GetName()] = fe.GetEnabled()
	}

	resp := &openngfwv1.ListFeedsResponse{}
	for _, f := range intel.Builtins() {
		resp.Feeds = append(resp.Feeds, &openngfwv1.FeedInfo{
			Name: f.Name, Description: f.Description, Url: f.URL,
			License:              f.License,
			AllowsCommercialUse:  f.AllowCommercial,
			AllowsRedistribution: f.AllowRedistribution,
			Attribution:          f.Attribution,
			Enabled:              enabled[f.Name],
		})
	}
	for _, cf := range pol.GetIntel().GetCustomFeeds() {
		resp.Feeds = append(resp.Feeds, &openngfwv1.FeedInfo{
			Name: cf.GetName(), Description: cf.GetDescription(), Url: cf.GetUrl(),
			License: "operator-provided", AllowsCommercialUse: true,
			Enabled: true, Custom: true,
		})
	}
	return resp, nil
}

// ListContentPackages returns local content package verification posture.
func (s *IntelServer) ListContentPackages(_ context.Context, _ *openngfwv1.ListContentPackagesRequest) (*openngfwv1.ListContentPackagesResponse, error) {
	statuses, err := contentpkg.Statuses(s.ContentDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read content packages: %v", err)
	}
	resp := &openngfwv1.ListContentPackagesResponse{}
	for _, st := range statuses {
		resp.Packages = append(resp.Packages, contentPackageInfo(st))
	}
	return resp, nil
}

// GetContentEvidence returns one bounded package-local JSON evidence artifact.
func (s *IntelServer) GetContentEvidence(_ context.Context, req *openngfwv1.GetContentEvidenceRequest) (*openngfwv1.GetContentEvidenceResponse, error) {
	evidence, err := contentpkg.ReadEvidence(s.ContentDir, req.GetKind(), req.GetEvidenceType())
	if err != nil {
		return nil, contentPackageEvidenceAPIError("read content evidence", err)
	}
	return &openngfwv1.GetContentEvidenceResponse{
		Kind:           evidence.Kind,
		PackageState:   evidence.PackageState,
		PackageVersion: evidence.PackageVersion,
		ManifestSha256: evidence.ManifestSHA256,
		Evidence: &openngfwv1.ContentEvidenceRef{
			Type:        evidence.Evidence.Type,
			Artifact:    evidence.Evidence.Artifact,
			Sha256:      evidence.Evidence.SHA256,
			GeneratedAt: evidence.Evidence.GeneratedAt,
		},
		ContentJson: string(evidence.ContentJSON),
		Bytes:       uint32(len(evidence.ContentJSON)),
	}, nil
}

// GetContentCorpus returns typed regression corpus rows from package evidence.
func (s *IntelServer) GetContentCorpus(_ context.Context, req *openngfwv1.GetContentCorpusRequest) (*openngfwv1.GetContentCorpusResponse, error) {
	corpus, err := contentpkg.ReadRegressionCorpus(s.ContentDir, req.GetKind(), req.GetEvidenceType())
	if err != nil {
		return nil, contentPackageEvidenceAPIError("read content corpus", err)
	}
	corpus.Samples = filterContentCorpusSamples(corpus.Samples, req.GetQuery(), req.GetVerdict(), req.GetLimit())
	return contentCorpusResponse(corpus), nil
}

// PreviewContentPackage verifies a server-local source directory without
// promoting files. Source paths are still constrained to the content import
// directory because path probing is an admin-only appliance operation.
func (s *IntelServer) PreviewContentPackage(_ context.Context, req *openngfwv1.PreviewContentPackageRequest) (*openngfwv1.PreviewContentPackageResponse, error) {
	sourcePath, err := s.resolveContentPackageSource(req.GetSourcePath())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "preview content package: source path must be under configured content import directory")
	}
	st, err := contentpkg.Preview(s.ContentDir, req.GetKind(), sourcePath)
	if err != nil {
		return nil, contentPackageAPIError("preview content package", err)
	}
	detail := fmt.Sprintf("%s package source is %s", st.Kind, st.State)
	if st.State == "verified" {
		detail = fmt.Sprintf("%s package source verified for audited install", st.Kind)
	}
	return &openngfwv1.PreviewContentPackageResponse{
		Package: contentPackageInfo(st),
		Detail:  detail,
	}, nil
}

// CompareContentPackage verifies a server-local source directory and returns
// installed-vs-candidate package and corpus evidence comparison.
func (s *IntelServer) CompareContentPackage(_ context.Context, req *openngfwv1.CompareContentPackageRequest) (*openngfwv1.CompareContentPackageResponse, error) {
	sourcePath, err := s.resolveContentPackageSource(req.GetSourcePath())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "compare content package: source path must be under configured content import directory")
	}
	preview, err := contentpkg.Preview(s.ContentDir, req.GetKind(), sourcePath)
	if err != nil {
		return nil, contentPackageAPIError("compare content package", err)
	}
	var current contentpkg.Status
	statuses, err := contentpkg.Statuses(s.ContentDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read installed content package: %v", err)
	}
	for _, st := range statuses {
		if st.Kind == preview.Kind {
			current = st
			break
		}
	}
	comparison, err := contentpkg.CompareRegressionCorpus(s.ContentDir, req.GetKind(), sourcePath, req.GetEvidenceType())
	if err != nil {
		return nil, contentPackageEvidenceAPIError("compare content corpus", err)
	}
	return &openngfwv1.CompareContentPackageResponse{
		CurrentPackage: contentPackageInfo(current),
		PreviewPackage: contentPackageInfo(preview),
		CorpusDiff:     contentCorpusDiff(comparison),
		Detail:         fmt.Sprintf("%s package source compared without promotion", preview.Kind),
	}, nil
}

// InstallContentPackage verifies a server-local content package directory
// before promoting it into the appliance content store.
func (s *IntelServer) InstallContentPackage(ctx context.Context, req *openngfwv1.InstallContentPackageRequest) (*openngfwv1.InstallContentPackageResponse, error) {
	if req == nil {
		req = &openngfwv1.InstallContentPackageRequest{}
	}
	if err := authz.RequireStepUp(ctx, "content-package-install", req.GetStepUpToken()); err != nil {
		return nil, err
	}
	if s.Store == nil {
		return nil, status.Error(codes.Internal, "audit store is required for content package install")
	}
	sourcePath, sourceErr := s.resolveContentPackageSource(req.GetSourcePath())
	auditSourcePath := sourcePath
	if sourceErr != nil {
		auditSourcePath = "rejected"
	}
	if err := s.auditContentPackage(ctx, "content-package-install-intent", contentPackageAuditDetail(req.GetKind(), auditSourcePath, "", false, "", "")); err != nil {
		return nil, status.Errorf(codes.Internal, "content package install intent audit failed: %v", err)
	}
	if sourceErr != nil {
		if auditErr := s.auditContentPackage(ctx, "content-package-install-failed", contentPackageAuditDetail(req.GetKind(), "rejected", "", false, "", "source path rejected")); auditErr != nil {
			return nil, status.Errorf(codes.Internal, "content package install rejected but audit write failed: %v", auditErr)
		}
		return nil, status.Error(codes.InvalidArgument, "install content package: source path must be under configured content import directory")
	}
	result, err := contentpkg.Install(s.ContentDir, req.GetKind(), sourcePath)
	if err != nil {
		if auditErr := s.auditContentPackage(ctx, "content-package-install-failed", contentPackageAuditDetail(req.GetKind(), sourcePath, "", false, "", err.Error())); auditErr != nil {
			return nil, status.Errorf(codes.Internal, "content package install rejected but audit write failed: %v", auditErr)
		}
		return nil, contentPackageAPIError("install content package", err)
	}
	if err := s.auditContentPackage(ctx, "content-package-install", contentPackageAuditDetail(result.Status.Kind, sourcePath, result.Status.Version, result.RollbackCreated, result.RollbackPath, "")); err != nil {
		if revertErr := s.revertFailedContentPackageInstall(result); revertErr != nil {
			return nil, status.Errorf(codes.Internal, "content package installed but audit write failed: %v; automatic revert failed: %v", err, revertErr)
		}
		return nil, status.Errorf(codes.Internal, "content package installed but audit write failed and installation was reverted: %v", err)
	}
	return &openngfwv1.InstallContentPackageResponse{
		Package:         contentPackageInfo(result.Status),
		RollbackCreated: result.RollbackCreated,
		RollbackPath:    result.RollbackPath,
		Detail:          result.Detail,
	}, nil
}

func (s *IntelServer) resolveContentPackageSource(sourcePath string) (string, error) {
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return "", errors.New("source path is required")
	}
	importDir := strings.TrimSpace(s.ContentImportDir)
	if importDir == "" && strings.TrimSpace(s.ContentDir) != "" {
		importDir = filepath.Join(s.ContentDir, ".imports")
	}
	if importDir == "" {
		return "", errors.New("content import directory is not configured")
	}
	importAbs, err := filepath.Abs(importDir)
	if err != nil {
		return "", fmt.Errorf("resolve content import directory: %w", err)
	}
	var sourceAbs string
	if filepath.IsAbs(sourcePath) {
		sourceAbs = filepath.Clean(sourcePath)
	} else {
		sourceAbs = filepath.Join(importAbs, sourcePath)
	}
	if !pathWithin(importAbs, sourceAbs) {
		return "", errors.New("source path escapes content import directory")
	}
	importResolved, err := filepath.EvalSymlinks(importAbs)
	if err != nil {
		return "", fmt.Errorf("resolve content import directory: %w", err)
	}
	sourceResolved, err := filepath.EvalSymlinks(sourceAbs)
	if err != nil {
		return "", fmt.Errorf("resolve content package source: %w", err)
	}
	if !pathWithin(importResolved, sourceResolved) {
		return "", errors.New("source path symlink escapes content import directory")
	}
	return sourceResolved, nil
}

func pathWithin(base, path string) bool {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// RollbackContentPackage restores the latest verified rollback backup for a
// content package kind.
func (s *IntelServer) RollbackContentPackage(ctx context.Context, req *openngfwv1.RollbackContentPackageRequest) (*openngfwv1.RollbackContentPackageResponse, error) {
	if req == nil {
		req = &openngfwv1.RollbackContentPackageRequest{}
	}
	if err := authz.RequireStepUp(ctx, "content-package-rollback", req.GetStepUpToken()); err != nil {
		return nil, err
	}
	if s.Store == nil {
		return nil, status.Error(codes.Internal, "audit store is required for content package rollback")
	}
	if err := s.auditContentPackage(ctx, "content-package-rollback-intent", contentPackageAuditDetail(req.GetKind(), "", "", false, "", "")); err != nil {
		return nil, status.Errorf(codes.Internal, "content package rollback intent audit failed: %v", err)
	}
	if !req.GetAckRollback() {
		if auditErr := s.auditContentPackage(ctx, "content-package-rollback-failed", contentPackageAuditDetail(req.GetKind(), "", "", false, "", "ack_rollback required")); auditErr != nil {
			return nil, status.Errorf(codes.Internal, "content package rollback rejected but audit write failed: %v", auditErr)
		}
		return nil, status.Error(codes.InvalidArgument, "ack_rollback is required to restore a previous content package")
	}
	result, err := contentpkg.RollbackPackage(s.ContentDir, req.GetKind())
	if err != nil {
		if auditErr := s.auditContentPackage(ctx, "content-package-rollback-failed", contentPackageAuditDetail(req.GetKind(), "", "", false, "", err.Error())); auditErr != nil {
			return nil, status.Errorf(codes.Internal, "content package rollback rejected but audit write failed: %v", auditErr)
		}
		return nil, contentPackageAPIError("rollback content package", err)
	}
	if err := s.auditContentPackage(ctx, "content-package-rollback", contentPackageRollbackAuditDetail(result.Status.Kind, result.Status.Version, result.RollbackCreated, result.RollbackPath, result.RestoredRollbackPath, "")); err != nil {
		if revertErr := s.revertFailedContentPackageRollback(result); revertErr != nil {
			return nil, status.Errorf(codes.Internal, "content package rolled back but audit write failed: %v; automatic restore failed: %v", err, revertErr)
		}
		return nil, status.Errorf(codes.Internal, "content package rolled back but audit write failed and rollback was restored: %v", err)
	}
	return &openngfwv1.RollbackContentPackageResponse{
		Package:              contentPackageInfo(result.Status),
		RollbackCreated:      result.RollbackCreated,
		RollbackPath:         result.RollbackPath,
		RestoredRollbackPath: result.RestoredRollbackPath,
		Detail:               result.Detail,
	}, nil
}

// RefreshFeeds triggers an immediate fetch-and-program cycle.
func (s *IntelServer) RefreshFeeds(ctx context.Context, _ *openngfwv1.RefreshFeedsRequest) (*openngfwv1.RefreshFeedsResponse, error) {
	n, err := s.Updater.Refresh(ctx)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "refresh: %v", err)
	}
	_, at := s.Updater.Status()
	return &openngfwv1.RefreshFeedsResponse{Entries: uint32(n), RefreshedAt: timestamppb.New(at)}, nil
}

func contentPackageAPIError(op string, err error) error {
	code := codes.Internal
	switch {
	case errors.Is(err, contentpkg.ErrInvalidKind), errors.Is(err, contentpkg.ErrInvalidPackage):
		code = codes.InvalidArgument
	case errors.Is(err, contentpkg.ErrNoRollback):
		code = codes.FailedPrecondition
	}
	return status.Errorf(code, "%s: %v", op, err)
}

func contentPackageEvidenceAPIError(op string, err error) error {
	code := codes.Internal
	switch {
	case errors.Is(err, contentpkg.ErrInvalidKind), errors.Is(err, contentpkg.ErrInvalidEvidenceRequest):
		code = codes.InvalidArgument
	case errors.Is(err, contentpkg.ErrEvidenceNotFound):
		code = codes.NotFound
	case errors.Is(err, contentpkg.ErrInvalidPackage):
		code = codes.FailedPrecondition
	}
	return status.Errorf(code, "%s: %v", op, err)
}

func (s *IntelServer) auditContentPackage(ctx context.Context, action, detail string) error {
	identity := auditIdentity(ctx)
	return appendContentPackageAudit(s.Store, store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role,
		AuthSource: identity.AuthSource,
		Action:     action,
		Detail:     detail,
	})
}

func (s *IntelServer) revertFailedContentPackageInstall(result contentpkg.ActionResult) error {
	kind := strings.TrimSpace(result.Status.Kind)
	if kind == "" {
		return errors.New("installed package kind is empty")
	}
	if result.RollbackCreated {
		_, err := contentpkg.RollbackPackage(s.ContentDir, kind)
		return err
	}
	if _, ok := expectedContentPackageKind(kind); !ok {
		return fmt.Errorf("%w: %s", contentpkg.ErrInvalidKind, kind)
	}
	return os.RemoveAll(filepath.Join(s.ContentDir, kind))
}

func (s *IntelServer) revertFailedContentPackageRollback(result contentpkg.ActionResult) error {
	kind := strings.TrimSpace(result.Status.Kind)
	if kind == "" {
		return errors.New("rolled back package kind is empty")
	}
	if !result.RollbackCreated || strings.TrimSpace(result.RollbackPath) == "" {
		return errors.New("no verified pre-rollback backup was created")
	}
	_, err := contentpkg.Install(s.ContentDir, kind, result.RollbackPath)
	return err
}

func expectedContentPackageKind(kind string) (contentpkg.ExpectedPackage, bool) {
	for _, exp := range contentpkg.ExpectedPackages() {
		if exp.Kind == kind {
			return exp, true
		}
	}
	return contentpkg.ExpectedPackage{}, false
}

func contentPackageAuditDetail(kind, sourcePath, version string, rollbackCreated bool, rollbackPath, errDetail string) string {
	parts := []string{"kind=" + compactAuditField(kind)}
	if sourcePath != "" {
		parts = append(parts, fmt.Sprintf("source='%s'", compactAuditField(sourcePath)))
	}
	if version != "" {
		parts = append(parts, "version="+compactAuditField(version))
	}
	parts = append(parts, fmt.Sprintf("rollback_created=%t", rollbackCreated))
	if rollbackPath != "" {
		parts = append(parts, fmt.Sprintf("rollback_path='%s'", compactAuditField(rollbackPath)))
	}
	if errDetail != "" {
		parts = append(parts, fmt.Sprintf("error='%s'", compactAuditField(errDetail)))
	}
	return strings.Join(parts, " ")
}

func contentPackageRollbackAuditDetail(kind, version string, rollbackCreated bool, rollbackPath, restoredRollbackPath, errDetail string) string {
	detail := contentPackageAuditDetail(kind, "", version, rollbackCreated, rollbackPath, errDetail)
	if restoredRollbackPath == "" {
		return detail
	}
	return detail + fmt.Sprintf(" restored_rollback_path='%s'", compactAuditField(restoredRollbackPath))
}

func contentPackageInfo(st contentpkg.Status) *openngfwv1.ContentPackageInfo {
	info := &openngfwv1.ContentPackageInfo{
		Kind:              st.Kind,
		Name:              st.Name,
		State:             st.State,
		Version:           st.Version,
		Source:            st.Source,
		ManifestSha256:    st.ManifestSHA256,
		SignatureStatus:   st.SignatureStatus,
		RegressionStatus:  st.RegressionStatus,
		RolloutState:      st.RolloutState,
		RollbackAvailable: st.RollbackAvailable,
		Blockers:          append([]string(nil), st.Blockers...),
		Detail:            st.Detail,
		ContentReadiness:  contentReadinessInfo(st.ContentReadiness),
	}
	if !st.InstalledAt.IsZero() {
		info.InstalledAt = timestamppb.New(st.InstalledAt)
	}
	for _, p := range st.Provenance {
		info.Provenance = append(info.Provenance, &openngfwv1.ContentProvenance{
			Name:    p.Name,
			Url:     p.URL,
			License: p.License,
		})
	}
	return info
}

func contentReadinessInfo(st contentpkg.ContentReadinessStatus) *openngfwv1.ContentReadinessInfo {
	info := &openngfwv1.ContentReadinessInfo{
		Scope:                      st.Scope,
		ProductionContent:          st.ProductionContent,
		ProductionReady:            st.ProductionReady,
		EvidenceStatus:             st.EvidenceStatus,
		RequiredProductionEvidence: append([]string(nil), st.RequiredProductionEvidence...),
		Blockers:                   append([]string(nil), st.Blockers...),
		ReadinessLabel:             st.ReadinessLabel,
		ReadinessDetail:            st.ReadinessDetail,
	}
	for _, evidence := range st.Evidence {
		info.Evidence = append(info.Evidence, &openngfwv1.ContentEvidenceRef{
			Type:        evidence.Type,
			Artifact:    evidence.Artifact,
			Sha256:      evidence.SHA256,
			GeneratedAt: evidence.GeneratedAt,
		})
	}
	return info
}

func contentCorpusResponse(corpus contentpkg.RegressionCorpus) *openngfwv1.GetContentCorpusResponse {
	return &openngfwv1.GetContentCorpusResponse{
		Kind:           corpus.Kind,
		PackageState:   corpus.PackageState,
		PackageVersion: corpus.PackageVersion,
		ManifestSha256: corpus.ManifestSHA256,
		Evidence:       contentEvidenceRef(corpus.Evidence),
		EvidenceType:   corpus.EvidenceType,
		Status:         corpus.Status,
		SampleCount:    corpus.SampleCount,
		FailedSamples:  corpus.FailedSamples,
		Verdicts:       append([]string(nil), corpus.Verdicts...),
		Samples:        contentCorpusSamples(corpus.Samples),
		Summary:        corpus.Summary,
	}
}

func contentCorpusDiff(comparison contentpkg.CorpusComparison) *openngfwv1.ContentCorpusDiff {
	out := &openngfwv1.ContentCorpusDiff{
		Kind:                  comparison.Kind,
		EvidenceType:          comparison.EvidenceType,
		CurrentPackageVersion: comparison.Current.PackageVersion,
		PreviewPackageVersion: comparison.Preview.PackageVersion,
		CurrentSampleCount:    comparison.Current.SampleCount,
		PreviewSampleCount:    comparison.Preview.SampleCount,
		CurrentFailedSamples:  comparison.Current.FailedSamples,
		PreviewFailedSamples:  comparison.Preview.FailedSamples,
		Added:                 comparison.Added,
		Removed:               comparison.Removed,
		Changed:               comparison.Changed,
		FailedDelta:           comparison.FailedDelta,
		Summary:               comparison.Summary,
	}
	for _, diff := range comparison.SampleDiffs {
		out.SampleDiffs = append(out.SampleDiffs, &openngfwv1.ContentCorpusSampleDiff{
			Id:      diff.ID,
			Change:  diff.Change,
			Current: contentCorpusSample(diff.Current),
			Preview: contentCorpusSample(diff.Preview),
		})
	}
	return out
}

func contentEvidenceRef(ref contentpkg.EvidenceRef) *openngfwv1.ContentEvidenceRef {
	if strings.TrimSpace(ref.Type) == "" && strings.TrimSpace(ref.Artifact) == "" && strings.TrimSpace(ref.SHA256) == "" {
		return nil
	}
	return &openngfwv1.ContentEvidenceRef{
		Type:        ref.Type,
		Artifact:    ref.Artifact,
		Sha256:      ref.SHA256,
		GeneratedAt: ref.GeneratedAt,
	}
}

func contentCorpusSamples(samples []contentpkg.CorpusSample) []*openngfwv1.ContentCorpusSample {
	out := make([]*openngfwv1.ContentCorpusSample, 0, len(samples))
	for _, sample := range samples {
		out = append(out, contentCorpusSample(sample))
	}
	return out
}

func contentCorpusSample(sample contentpkg.CorpusSample) *openngfwv1.ContentCorpusSample {
	if sample.ID == "" && sample.PCAPSHA256 == "" && sample.Expected == "" && sample.Observed == "" && sample.Verdict == "" {
		return nil
	}
	return &openngfwv1.ContentCorpusSample{
		Id:          sample.ID,
		PcapSha256:  sample.PCAPSHA256,
		Expected:    sample.Expected,
		Observed:    sample.Observed,
		ExpectedApp: sample.ExpectedApp,
		ObservedApp: sample.ObservedApp,
		SignatureId: sample.SignatureID,
		Verdict:     sample.Verdict,
		Detail:      sample.Detail,
	}
}

func filterContentCorpusSamples(samples []contentpkg.CorpusSample, query, verdict string, limit uint32) []contentpkg.CorpusSample {
	query = strings.ToLower(strings.TrimSpace(query))
	verdict = strings.ToLower(strings.TrimSpace(verdict))
	if limit == 0 || limit > 500 {
		limit = 500
	}
	out := make([]contentpkg.CorpusSample, 0, len(samples))
	for _, sample := range samples {
		if verdict != "" && sample.Verdict != verdict {
			continue
		}
		if query != "" && !contentCorpusSampleMatches(sample, query) {
			continue
		}
		out = append(out, sample)
		if uint32(len(out)) >= limit {
			break
		}
	}
	return out
}

func contentCorpusSampleMatches(sample contentpkg.CorpusSample, query string) bool {
	fields := []string{
		sample.ID,
		sample.PCAPSHA256,
		sample.Expected,
		sample.Observed,
		sample.ExpectedApp,
		sample.ObservedApp,
		sample.SignatureID,
		sample.Verdict,
		sample.Detail,
	}
	for _, field := range fields {
		if strings.Contains(strings.ToLower(field), query) {
			return true
		}
	}
	return false
}
