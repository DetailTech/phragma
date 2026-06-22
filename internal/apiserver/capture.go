package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/genproto/googleapis/api/httpbody"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/store"
)

const (
	defaultCaptureInterface = "any"
	defaultCaptureDuration  = 20
	minCaptureDuration      = 1
	maxCaptureDuration      = 60
	defaultCapturePackets   = 500
	minCapturePackets       = 1
	maxCapturePackets       = 10000
	defaultCaptureSnaplen   = 256
	minCaptureSnaplen       = 96
	maxCaptureSnaplen       = 4096
	defaultCaptureDir       = "/var/log/openngfw/pcap"
	defaultCaptureListLimit = 25
	maxCaptureListLimit     = 100
	captureMediaType        = "application/vnd.tcpdump.pcap"
)

var (
	captureInterfaceRE       = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	captureLabelRE           = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,48}$`)
	captureFlowIDRE          = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	captureArtifactRE        = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	captureRetentionCaseIDRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	safeShellWordRE          = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)
)

// PlanPacketCapture validates capture scope and returns the exact bounded
// capture plan without mutating host state.
func (s *SystemService) PlanPacketCapture(_ context.Context, req *openngfwv1.PlanPacketCaptureRequest) (*openngfwv1.PlanPacketCaptureResponse, error) {
	plan, err := s.packetCapturePlan(planCaptureInput(req))
	if err != nil {
		return nil, err
	}
	return &openngfwv1.PlanPacketCaptureResponse{Plan: plan}, nil
}

// ListPacketCaptures returns recent capture artifacts from the capture output
// directory. It indexes only regular .pcap files and returns newest artifacts
// first so operators can retrieve evidence from prior bounded captures.
func (s *SystemService) ListPacketCaptures(_ context.Context, req *openngfwv1.ListPacketCapturesRequest) (*openngfwv1.ListPacketCapturesResponse, error) {
	return listPacketCapturesFromDir(s.captureOutputDir(), req)
}

func listPacketCapturesFromDir(captureDir string, req *openngfwv1.ListPacketCapturesRequest) (*openngfwv1.ListPacketCapturesResponse, error) {
	if req == nil {
		req = &openngfwv1.ListPacketCapturesRequest{}
	}
	limit := normalizeCaptureListLimit(req.GetLimit())
	flowID, err := normalizeCaptureFlowID(req.GetFlowId())
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(captureDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &openngfwv1.ListPacketCapturesResponse{CaptureDir: captureDir}, nil
		}
		if os.IsPermission(err) {
			return nil, grpcstatus.Errorf(codes.PermissionDenied, "list packet captures: %v", err)
		}
		return nil, grpcstatus.Errorf(codes.Internal, "list packet captures: %v", err)
	}

	files := make([]captureArtifactFile, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		artifactID := captureArtifactIDFromFilename(entry.Name())
		if artifactID == "" {
			continue
		}
		files = append(files, captureArtifactFile{
			name:       entry.Name(),
			path:       filepath.Join(captureDir, entry.Name()),
			artifactID: artifactID,
			size:       info.Size(),
			modTime:    info.ModTime().UTC(),
		})
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].modTime.Equal(files[j].modTime) {
			return files[i].name > files[j].name
		}
		return files[i].modTime.After(files[j].modTime)
	})

	captures := make([]*openngfwv1.PacketCaptureJob, 0, min(limit, len(files)))
	for _, file := range files {
		job := packetCaptureJobFromArtifact(file)
		if !packetCaptureMatchesListFilter(job, flowID) {
			continue
		}
		captures = append(captures, job)
		if len(captures) >= limit {
			break
		}
	}
	return &openngfwv1.ListPacketCapturesResponse{
		Captures:   captures,
		CaptureDir: captureDir,
	}, nil
}

func packetCaptureMatchesListFilter(job *openngfwv1.PacketCaptureJob, flowID string) bool {
	if flowID == "" {
		return true
	}
	return job != nil && strings.TrimSpace(job.GetPlan().GetFlowId()) == flowID
}

// StartPacketCapture runs one bounded packet capture through the canonical API.
// It is intentionally synchronous for the bounded v1 diagnostic path: callers
// receive the completed job record and the audit log records the result.
func (s *SystemService) StartPacketCapture(ctx context.Context, req *openngfwv1.StartPacketCaptureRequest) (*openngfwv1.StartPacketCaptureResponse, error) {
	plan, err := s.packetCapturePlan(startCaptureInput(req))
	if err != nil {
		if auditErr := s.auditPacketCaptureFailure(ctx, nil, "plan", err.Error()); auditErr != nil {
			return nil, grpcstatus.Errorf(codes.Internal, "packet capture rejected but audit write failed: %v", auditErr)
		}
		return nil, err
	}
	if !req.GetAckCapture() {
		msg := "ack_capture is required to start a packet capture"
		if auditErr := s.auditPacketCaptureFailure(ctx, plan, "acknowledgement", msg); auditErr != nil {
			return nil, grpcstatus.Errorf(codes.Internal, "packet capture rejected but audit write failed: %v", auditErr)
		}
		return nil, grpcstatus.Error(codes.FailedPrecondition, msg)
	}
	if s.Status.DryRun {
		msg := "packet capture cannot start while controld is running in dry-run mode"
		if auditErr := s.auditPacketCaptureFailure(ctx, plan, "dry-run", msg); auditErr != nil {
			return nil, grpcstatus.Errorf(codes.Internal, "packet capture rejected but audit write failed: %v", auditErr)
		}
		return nil, grpcstatus.Error(codes.FailedPrecondition, msg)
	}
	if plan.GetSrcIp() == "" || plan.GetDestIp() == "" {
		msg := "packet capture start requires source and destination IPs; use plan mode for broad manual commands"
		if auditErr := s.auditPacketCaptureFailure(ctx, plan, "scope", msg); auditErr != nil {
			return nil, grpcstatus.Errorf(codes.Internal, "packet capture rejected but audit write failed: %v", auditErr)
		}
		return nil, grpcstatus.Error(codes.FailedPrecondition, msg)
	}

	start := time.Now().UTC()
	job := &openngfwv1.PacketCaptureJob{
		Id:        "pcap-" + start.Format("20060102T150405.000000000Z"),
		State:     "running",
		Detail:    "packet capture started",
		Plan:      plan,
		StartedAt: start.Format(time.RFC3339Nano),
	}
	attachPacketCaptureArtifact(job, plan.GetOutputPath())
	if err := os.MkdirAll(filepath.Dir(plan.GetOutputPath()), 0o750); err != nil {
		job.State = "failed"
		job.Detail = "create capture directory failed"
		job.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
		job.Stderr = err.Error()
		if auditErr := s.auditPacketCaptureFailure(ctx, plan, "mkdir", err.Error()); auditErr != nil {
			return nil, grpcstatus.Errorf(codes.Internal, "packet capture failed before execution and audit write failed: %v", auditErr)
		}
		if os.IsPermission(err) {
			return nil, grpcstatus.Errorf(codes.PermissionDenied, "create capture directory: %v", err)
		}
		return nil, grpcstatus.Errorf(codes.Internal, "create capture directory: %v", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	args := append([]string(nil), plan.GetCommandArgv()[1:]...)
	out, durationLimit, err := runPacketCapture(runCtx, s.Status, time.Duration(plan.GetDurationSeconds())*time.Second, args)
	job.CompletedAt = time.Now().UTC().Format(time.RFC3339Nano)
	job.Stderr = strings.TrimSpace(string(out))
	if st, statErr := os.Stat(plan.GetOutputPath()); statErr == nil {
		job.BytesWritten = uint64(st.Size())
		if sum, hashErr := fileSHA256(plan.GetOutputPath()); hashErr == nil {
			job.Sha256 = sum
		} else {
			job.Stderr = strings.TrimSpace(strings.Join([]string{job.GetStderr(), fmt.Sprintf("hash capture output: %v", hashErr)}, "\n"))
		}
	}
	if err != nil && !durationLimit {
		job.State = "failed"
		job.Detail = trimCommandError(out, err)
		job.ExitCode = int32(captureExitCode(err))
		if auditErr := s.auditPacketCaptureFailure(ctx, plan, "tcpdump", job.Detail); auditErr != nil {
			return nil, grpcstatus.Errorf(codes.Internal, "packet capture failed and audit write failed: %v", auditErr)
		}
		return &openngfwv1.StartPacketCaptureResponse{Job: job}, grpcstatus.Errorf(codes.FailedPrecondition, "packet capture failed: %s", job.Detail)
	}
	job.State = "completed"
	if durationLimit {
		job.Detail = "packet capture completed at duration limit"
	} else {
		job.Detail = "packet capture completed"
	}
	detail := fmt.Sprintf("%d bytes written", job.GetBytesWritten())
	if job.GetSha256() != "" {
		detail += " sha256=" + job.GetSha256()
	}
	if err := writePacketCaptureMetadata(job); err != nil {
		job.Stderr = strings.TrimSpace(strings.Join([]string{job.GetStderr(), fmt.Sprintf("write capture metadata: %v", err)}, "\n"))
	}
	if err := s.auditPacketCapture(ctx, "packet-capture", captureAuditDetail(plan, "completed", detail)); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "packet capture completed but audit write failed: %v", err)
	}
	return &openngfwv1.StartPacketCaptureResponse{Job: job}, nil
}

// DownloadPacketCapture returns the pcap bytes for a safe artifact id.
func (s *SystemService) DownloadPacketCapture(_ context.Context, req *openngfwv1.DownloadPacketCaptureRequest) (*httpbody.HttpBody, error) {
	path, err := s.captureArtifactPath(req.GetId())
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, grpcstatus.Errorf(codes.NotFound, "packet capture artifact not found: %s", req.GetId())
		}
		if os.IsPermission(err) {
			return nil, grpcstatus.Errorf(codes.PermissionDenied, "read packet capture artifact: %v", err)
		}
		return nil, grpcstatus.Errorf(codes.Internal, "read packet capture artifact: %v", err)
	}
	return &httpbody.HttpBody{
		ContentType: captureMediaType,
		Data:        data,
	}, nil
}

// SetPacketCaptureRetention records non-destructive evidence metadata in the
// existing pcap sidecar. It does not delete, prune, move, or rewrite pcap bytes.
func (s *SystemService) SetPacketCaptureRetention(ctx context.Context, req *openngfwv1.SetPacketCaptureRetentionRequest) (*openngfwv1.SetPacketCaptureRetentionResponse, error) {
	if req == nil {
		req = &openngfwv1.SetPacketCaptureRetentionRequest{}
	}
	if s.Store == nil {
		return nil, grpcstatus.Error(codes.Internal, "packet capture retention requires an audit store")
	}
	if !req.GetAckRetentionChange() {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "ack_retention_change is required to update packet capture retention metadata")
	}
	state, err := normalizeCaptureRetentionState(req.GetState())
	if err != nil {
		return nil, err
	}
	reason, err := normalizeCaptureRetentionReason(req.GetRetentionReason())
	if err != nil {
		return nil, err
	}
	caseID, err := normalizeCaptureRetentionCaseID(req.GetCaseId())
	if err != nil {
		return nil, err
	}
	retainUntil, err := normalizeCaptureRetainUntil(req.GetRetainUntil(), state)
	if err != nil {
		return nil, err
	}
	path, err := s.captureArtifactPath(req.GetId())
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, grpcstatus.Errorf(codes.NotFound, "packet capture artifact not found: %s", req.GetId())
		}
		if os.IsPermission(err) {
			return nil, grpcstatus.Errorf(codes.PermissionDenied, "stat packet capture artifact: %v", err)
		}
		return nil, grpcstatus.Errorf(codes.Internal, "stat packet capture artifact: %v", err)
	}
	if !info.Mode().IsRegular() {
		return nil, grpcstatus.Error(codes.FailedPrecondition, "packet capture artifact must be a regular file")
	}
	file := captureArtifactFile{
		name:       filepath.Base(path),
		path:       path,
		artifactID: captureArtifactIDFromFilename(filepath.Base(path)),
		size:       info.Size(),
		modTime:    info.ModTime().UTC(),
	}
	job, err := packetCaptureJobFromArtifactStrict(file)
	if err != nil {
		return nil, err
	}

	identity := auditIdentity(ctx)
	job.Retention = &openngfwv1.PacketCaptureRetention{
		State:           state,
		RetainUntil:     retainUntil,
		RetentionReason: reason,
		CaseId:          caseID,
		UpdatedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		UpdatedBy:       compactAuditField(identity.Name),
	}
	if state == openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RELEASED {
		job.Retention.RetainUntil = ""
	}

	metadataPath := packetCaptureMetadataPath(path)
	previous, readErr := os.ReadFile(metadataPath)
	previousExists := readErr == nil
	if readErr != nil && !os.IsNotExist(readErr) {
		if os.IsPermission(readErr) {
			return nil, grpcstatus.Errorf(codes.PermissionDenied, "read packet capture metadata: %v", readErr)
		}
		return nil, grpcstatus.Errorf(codes.FailedPrecondition, "read packet capture metadata: %v", readErr)
	}
	if err := writePacketCaptureMetadata(job); err != nil {
		return nil, grpcstatus.Errorf(codes.Internal, "write packet capture metadata: %v", err)
	}
	if err := s.auditPacketCapture(ctx, "packet-capture-retention", captureRetentionAuditDetail(job)); err != nil {
		if previousExists {
			_ = os.WriteFile(metadataPath, previous, 0o640)
		} else {
			_ = os.Remove(metadataPath)
		}
		return nil, grpcstatus.Errorf(codes.Internal, "packet capture retention metadata reverted because audit write failed: %v", err)
	}
	return &openngfwv1.SetPacketCaptureRetentionResponse{Job: job}, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type captureArtifactFile struct {
	name       string
	path       string
	artifactID string
	size       int64
	modTime    time.Time
}

func normalizeCaptureListLimit(v uint32) int {
	if v == 0 {
		return defaultCaptureListLimit
	}
	if v > maxCaptureListLimit {
		return maxCaptureListLimit
	}
	return int(v)
}

func packetCaptureJobFromArtifact(file captureArtifactFile) *openngfwv1.PacketCaptureJob {
	job := &openngfwv1.PacketCaptureJob{
		Id:          file.artifactID,
		State:       "completed",
		Detail:      "capture artifact indexed from capture directory",
		Plan:        &openngfwv1.PacketCapturePlan{OutputPath: file.path},
		CompletedAt: file.modTime.Format(time.RFC3339Nano),
		BytesWritten: func() uint64 {
			if file.size < 0 {
				return 0
			}
			return uint64(file.size)
		}(),
	}
	if metadata, err := readPacketCaptureMetadata(file.path); err == nil && metadata != nil {
		overlayPacketCaptureMetadata(job, metadata, file.path)
	}
	attachPacketCaptureArtifact(job, file.path)
	if sum, err := fileSHA256(file.path); err == nil {
		job.Sha256 = sum
	} else {
		job.State = "unavailable"
		job.Detail = "capture artifact metadata available but hash failed"
		job.Stderr = err.Error()
	}
	return job
}

func packetCaptureJobFromArtifactStrict(file captureArtifactFile) (*openngfwv1.PacketCaptureJob, error) {
	job := &openngfwv1.PacketCaptureJob{
		Id:          file.artifactID,
		State:       "completed",
		Detail:      "capture artifact indexed from capture directory",
		Plan:        &openngfwv1.PacketCapturePlan{OutputPath: file.path},
		CompletedAt: file.modTime.Format(time.RFC3339Nano),
		BytesWritten: func() uint64 {
			if file.size < 0 {
				return 0
			}
			return uint64(file.size)
		}(),
	}
	metadata, err := readPacketCaptureMetadata(file.path)
	if err != nil && !os.IsNotExist(err) {
		if os.IsPermission(err) {
			return nil, grpcstatus.Errorf(codes.PermissionDenied, "read packet capture metadata: %v", err)
		}
		return nil, grpcstatus.Errorf(codes.FailedPrecondition, "packet capture metadata is not safe to update: %v", err)
	}
	if metadata != nil {
		overlayPacketCaptureMetadata(job, metadata, file.path)
	}
	attachPacketCaptureArtifact(job, file.path)
	if sum, err := fileSHA256(file.path); err == nil {
		job.Sha256 = sum
	} else {
		return nil, grpcstatus.Errorf(codes.FailedPrecondition, "hash packet capture artifact before retention update: %v", err)
	}
	return job, nil
}

func overlayPacketCaptureMetadata(job *openngfwv1.PacketCaptureJob, metadata *openngfwv1.PacketCaptureJob, artifactPath string) {
	if job == nil || metadata == nil {
		return
	}
	if metadata.GetId() != "" {
		job.Id = metadata.GetId()
	}
	if metadata.GetState() != "" {
		job.State = metadata.GetState()
	}
	if metadata.GetDetail() != "" {
		job.Detail = metadata.GetDetail()
	}
	if metadata.GetPlan() != nil {
		job.Plan = clonePacketCapturePlan(metadata.GetPlan())
		job.Plan.OutputPath = artifactPath
	}
	if metadata.GetStartedAt() != "" {
		job.StartedAt = metadata.GetStartedAt()
	}
	if metadata.GetCompletedAt() != "" {
		job.CompletedAt = metadata.GetCompletedAt()
	}
	if metadata.GetStderr() != "" {
		job.Stderr = metadata.GetStderr()
	}
	if metadata.GetRetention() != nil {
		job.Retention = clonePacketCaptureRetention(metadata.GetRetention())
	}
}

func writePacketCaptureMetadata(job *openngfwv1.PacketCaptureJob) error {
	if job == nil || job.GetPlan().GetOutputPath() == "" {
		return nil
	}
	path := packetCaptureMetadataPath(job.GetPlan().GetOutputPath())
	data, err := (protojson.MarshalOptions{EmitUnpopulated: false}).Marshal(job)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o640)
}

func readPacketCaptureMetadata(capturePath string) (*openngfwv1.PacketCaptureJob, error) {
	data, err := os.ReadFile(packetCaptureMetadataPath(capturePath))
	if err != nil {
		return nil, err
	}
	job := &openngfwv1.PacketCaptureJob{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, job); err != nil {
		return nil, err
	}
	if job.GetPlan().GetOutputPath() != "" && filepath.Base(job.GetPlan().GetOutputPath()) != filepath.Base(capturePath) {
		return nil, fmt.Errorf("capture metadata output path does not match artifact")
	}
	return job, nil
}

func packetCaptureMetadataPath(capturePath string) string {
	return capturePath + ".json"
}

func clonePacketCapturePlan(plan *openngfwv1.PacketCapturePlan) *openngfwv1.PacketCapturePlan {
	if plan == nil {
		return nil
	}
	return &openngfwv1.PacketCapturePlan{
		Interface:       plan.GetInterface(),
		Protocol:        plan.GetProtocol(),
		SrcIp:           plan.GetSrcIp(),
		SrcPort:         plan.GetSrcPort(),
		DestIp:          plan.GetDestIp(),
		DestPort:        plan.GetDestPort(),
		DurationSeconds: plan.GetDurationSeconds(),
		PacketCount:     plan.GetPacketCount(),
		SnaplenBytes:    plan.GetSnaplenBytes(),
		FlowId:          plan.GetFlowId(),
		OutputPath:      plan.GetOutputPath(),
		BpfFilter:       plan.GetBpfFilter(),
		Command:         plan.GetCommand(),
		CommandArgv:     append([]string(nil), plan.GetCommandArgv()...),
		Warnings:        append([]string(nil), plan.GetWarnings()...),
	}
}

func clonePacketCaptureRetention(retention *openngfwv1.PacketCaptureRetention) *openngfwv1.PacketCaptureRetention {
	if retention == nil {
		return nil
	}
	return &openngfwv1.PacketCaptureRetention{
		State:           retention.GetState(),
		RetainUntil:     retention.GetRetainUntil(),
		RetentionReason: retention.GetRetentionReason(),
		CaseId:          retention.GetCaseId(),
		UpdatedAt:       retention.GetUpdatedAt(),
		UpdatedBy:       retention.GetUpdatedBy(),
	}
}

func attachPacketCaptureArtifact(job *openngfwv1.PacketCaptureJob, outputPath string) {
	if job == nil {
		return
	}
	filename := filepath.Base(outputPath)
	artifactID := captureArtifactIDFromFilename(filename)
	if artifactID == "" {
		return
	}
	job.ArtifactId = artifactID
	job.Filename = filename
	job.DownloadPath = captureDownloadPath(artifactID)
	job.MediaType = captureMediaType
}

func captureDownloadPath(artifactID string) string {
	return "/v1/system/packet-captures/" + artifactID + "/download"
}

func captureArtifactIDFromFilename(filename string) string {
	base := filepath.Base(filename)
	if filepath.Ext(base) != ".pcap" {
		return ""
	}
	id := strings.TrimSuffix(base, ".pcap")
	if !validCaptureArtifactID(id) {
		return ""
	}
	return id
}

func validCaptureArtifactID(id string) bool {
	if id == "" || strings.HasPrefix(id, ".") || strings.Contains(id, "..") {
		return false
	}
	return captureArtifactRE.MatchString(id)
}

func (s *SystemService) captureArtifactPath(id string) (string, error) {
	if !validCaptureArtifactID(id) {
		return "", grpcstatus.Error(codes.InvalidArgument, "packet capture artifact id is invalid")
	}
	captureDir := filepath.Clean(s.captureOutputDir())
	path := filepath.Clean(filepath.Join(captureDir, id+".pcap"))
	rel, err := filepath.Rel(captureDir, path)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", grpcstatus.Error(codes.InvalidArgument, "packet capture artifact id escapes capture directory")
	}
	return path, nil
}

type captureInput struct {
	iface           string
	protocol        openngfwv1.Protocol
	srcIP, destIP   string
	srcPort         uint32
	destPort        uint32
	durationSeconds uint32
	packetCount     uint32
	snaplenBytes    uint32
	label           string
	flowID          string
}

func planCaptureInput(req *openngfwv1.PlanPacketCaptureRequest) captureInput {
	if req == nil {
		req = &openngfwv1.PlanPacketCaptureRequest{}
	}
	return captureInput{
		iface:           req.GetInterface(),
		protocol:        req.GetProtocol(),
		srcIP:           req.GetSrcIp(),
		srcPort:         req.GetSrcPort(),
		destIP:          req.GetDestIp(),
		destPort:        req.GetDestPort(),
		durationSeconds: req.GetDurationSeconds(),
		packetCount:     req.GetPacketCount(),
		snaplenBytes:    req.GetSnaplenBytes(),
		label:           req.GetLabel(),
		flowID:          req.GetFlowId(),
	}
}

func startCaptureInput(req *openngfwv1.StartPacketCaptureRequest) captureInput {
	if req == nil {
		req = &openngfwv1.StartPacketCaptureRequest{}
	}
	return captureInput{
		iface:           req.GetInterface(),
		protocol:        req.GetProtocol(),
		srcIP:           req.GetSrcIp(),
		srcPort:         req.GetSrcPort(),
		destIP:          req.GetDestIp(),
		destPort:        req.GetDestPort(),
		durationSeconds: req.GetDurationSeconds(),
		packetCount:     req.GetPacketCount(),
		snaplenBytes:    req.GetSnaplenBytes(),
		label:           req.GetLabel(),
		flowID:          req.GetFlowId(),
	}
}

func (s *SystemService) packetCapturePlan(in captureInput) (*openngfwv1.PacketCapturePlan, error) {
	warnings := []string{}
	iface, err := normalizeCaptureInterface(in.iface)
	if err != nil {
		return nil, err
	}
	if iface == defaultCaptureInterface {
		warnings = append(warnings, "Interface is set to any; prefer the ingress or egress interface when known.")
	}
	proto := normalizeCaptureProtocol(in.protocol)
	srcIP, err := normalizeCaptureAddr(in.srcIP, "src_ip")
	if err != nil {
		return nil, err
	}
	destIP, err := normalizeCaptureAddr(in.destIP, "dest_ip")
	if err != nil {
		return nil, err
	}
	srcPort, err := normalizeCapturePort(in.srcPort, "src_port")
	if err != nil {
		return nil, err
	}
	destPort, err := normalizeCapturePort(in.destPort, "dest_port")
	if err != nil {
		return nil, err
	}
	if srcIP == "" || destIP == "" {
		warnings = append(warnings, "Capture filter is not fully flow-scoped because source or destination IP is missing.")
	}
	if (proto == openngfwv1.Protocol_PROTOCOL_TCP || proto == openngfwv1.Protocol_PROTOCOL_UDP) && (srcPort == 0 || destPort == 0) {
		warnings = append(warnings, "TCP/UDP capture has a host filter but not both ports; expect more packets.")
	}
	duration := clampCapture(in.durationSeconds, minCaptureDuration, maxCaptureDuration, defaultCaptureDuration)
	packets := clampCapture(in.packetCount, minCapturePackets, maxCapturePackets, defaultCapturePackets)
	snaplen := clampCapture(in.snaplenBytes, minCaptureSnaplen, maxCaptureSnaplen, defaultCaptureSnaplen)
	flowID, err := normalizeCaptureFlowID(in.flowID)
	if err != nil {
		return nil, err
	}
	label := normalizeCaptureLabel(in.label)
	outputPath := filepath.Join(s.captureOutputDir(), fmt.Sprintf("phragma-%s-%s.pcap", label, time.Now().UTC().Format("20060102T150405Z")))
	filter, filterArgv := captureFilter(proto, srcIP, srcPort, destIP, destPort)
	argv := append([]string{"tcpdump", "-i", iface, "-nn", "-s", strconv.Itoa(int(snaplen)), "-c", strconv.Itoa(int(packets)), "-w", outputPath}, filterArgv...)
	manualArgv := []string{"timeout", fmt.Sprintf("%ds", duration), "tcpdump", "-i", iface, "-nn", "-s", strconv.Itoa(int(snaplen)), "-c", strconv.Itoa(int(packets)), "-w", outputPath, filter}
	return &openngfwv1.PacketCapturePlan{
		Interface:       iface,
		Protocol:        proto,
		SrcIp:           srcIP,
		SrcPort:         srcPort,
		DestIp:          destIP,
		DestPort:        destPort,
		DurationSeconds: duration,
		PacketCount:     packets,
		SnaplenBytes:    snaplen,
		FlowId:          flowID,
		OutputPath:      outputPath,
		BpfFilter:       filter,
		Command:         "sudo " + shellJoin(manualArgv),
		CommandArgv:     argv,
		Warnings:        warnings,
	}, nil
}

func (s *SystemService) captureOutputDir() string {
	if s.Status.LogDir == "" {
		return defaultCaptureDir
	}
	return filepath.Join(s.Status.LogDir, "pcap")
}

func normalizeCaptureInterface(v string) (string, error) {
	iface := strings.TrimSpace(v)
	if iface == "" {
		return defaultCaptureInterface, nil
	}
	if !captureInterfaceRE.MatchString(iface) {
		return "", grpcstatus.Error(codes.InvalidArgument, "interface contains unsupported characters")
	}
	return iface, nil
}

func normalizeCaptureProtocol(p openngfwv1.Protocol) openngfwv1.Protocol {
	switch p {
	case openngfwv1.Protocol_PROTOCOL_TCP, openngfwv1.Protocol_PROTOCOL_UDP, openngfwv1.Protocol_PROTOCOL_ICMP, openngfwv1.Protocol_PROTOCOL_ANY:
		return p
	default:
		return openngfwv1.Protocol_PROTOCOL_ANY
	}
}

func normalizeCaptureAddr(v, field string) (string, error) {
	addr := strings.TrimSpace(v)
	if addr == "" {
		return "", nil
	}
	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return "", grpcstatus.Errorf(codes.InvalidArgument, "%s must be an IP address", field)
	}
	return parsed.String(), nil
}

func normalizeCapturePort(v uint32, field string) (uint32, error) {
	if v > 65535 {
		return 0, grpcstatus.Errorf(codes.InvalidArgument, "%s must be 0-65535", field)
	}
	return v, nil
}

func normalizeCaptureLabel(v string) string {
	label := strings.TrimSpace(v)
	label = regexp.MustCompile(`[^A-Za-z0-9_.-]+`).ReplaceAllString(label, "-")
	label = strings.Trim(label, "-")
	if captureLabelRE.MatchString(label) {
		return label
	}
	return "flow"
}

func normalizeCaptureFlowID(v string) (string, error) {
	flowID := strings.TrimSpace(v)
	if flowID == "" {
		return "", nil
	}
	if !captureFlowIDRE.MatchString(flowID) {
		return "", grpcstatus.Error(codes.InvalidArgument, "flow_id contains unsupported characters")
	}
	return flowID, nil
}

func normalizeCaptureRetentionState(state openngfwv1.PacketCaptureRetentionState) (openngfwv1.PacketCaptureRetentionState, error) {
	switch state {
	case openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RETAINED,
		openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RELEASED:
		return state, nil
	default:
		return openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_UNSPECIFIED,
			grpcstatus.Error(codes.InvalidArgument, "retention state must be retained or released")
	}
}

func normalizeCaptureRetainUntil(v string, state openngfwv1.PacketCaptureRetentionState) (string, error) {
	value := strings.TrimSpace(v)
	if state == openngfwv1.PacketCaptureRetentionState_PACKET_CAPTURE_RETENTION_STATE_RELEASED {
		if value != "" {
			return "", grpcstatus.Error(codes.InvalidArgument, "retain_until must be empty when releasing packet capture retention")
		}
		return "", nil
	}
	if value == "" {
		return "", grpcstatus.Error(codes.InvalidArgument, "retain_until is required when retaining packet capture evidence")
	}
	if !strings.HasSuffix(strings.ToUpper(value), "Z") {
		return "", grpcstatus.Error(codes.InvalidArgument, "retain_until must be a UTC RFC3339 timestamp ending in Z")
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return "", grpcstatus.Error(codes.InvalidArgument, "retain_until must be a UTC RFC3339 timestamp")
	}
	if !parsed.After(time.Now().UTC()) {
		return "", grpcstatus.Error(codes.InvalidArgument, "retain_until must be in the future")
	}
	return parsed.UTC().Format(time.RFC3339Nano), nil
}

func normalizeCaptureRetentionReason(v string) (string, error) {
	if unsafeCaptureRetentionText(v) {
		return "", grpcstatus.Error(codes.InvalidArgument, "retention_reason contains unsupported or sensitive-looking content")
	}
	reason := strings.Join(strings.Fields(strings.TrimSpace(v)), " ")
	if reason == "" {
		return "", grpcstatus.Error(codes.InvalidArgument, "retention_reason is required")
	}
	if len(reason) > 256 {
		return "", grpcstatus.Error(codes.InvalidArgument, "retention_reason must be at most 256 characters")
	}
	return reason, nil
}

func normalizeCaptureRetentionCaseID(v string) (string, error) {
	caseID := strings.TrimSpace(v)
	if caseID == "" {
		return "", nil
	}
	if !captureRetentionCaseIDRE.MatchString(caseID) || unsafeCaptureRetentionText(caseID) {
		return "", grpcstatus.Error(codes.InvalidArgument, "case_id contains unsupported or sensitive-looking content")
	}
	return caseID, nil
}

func unsafeCaptureRetentionText(v string) bool {
	lower := strings.ToLower(v)
	if strings.ContainsAny(v, "/\\") ||
		strings.Contains(lower, "://") ||
		strings.Contains(lower, "bearer ") ||
		strings.Contains(lower, "authorization:") ||
		strings.Contains(lower, "access_token=") ||
		strings.Contains(lower, "api_key=") ||
		strings.Contains(lower, "token=") ||
		strings.Contains(lower, "password=") ||
		strings.Contains(lower, "secret=") {
		return true
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func clampCapture(v, minValue, maxValue, fallback uint32) uint32 {
	if v == 0 {
		return fallback
	}
	if v < minValue {
		return minValue
	}
	if v > maxValue {
		return maxValue
	}
	return v
}

func captureFilter(proto openngfwv1.Protocol, srcIP string, srcPort uint32, destIP string, destPort uint32) (string, []string) {
	parts := []string{}
	if protoName := captureProtoName(proto); protoName != "" {
		parts = append(parts, protoName)
	}
	if srcIP != "" && destIP != "" && (proto == openngfwv1.Protocol_PROTOCOL_TCP || proto == openngfwv1.Protocol_PROTOCOL_UDP) && srcPort > 0 && destPort > 0 {
		filter := fmt.Sprintf("%s and ((src host %s and src port %d and dst host %s and dst port %d) or (src host %s and src port %d and dst host %s and dst port %d))",
			captureProtoName(proto), srcIP, srcPort, destIP, destPort, destIP, destPort, srcIP, srcPort)
		return filter, strings.Fields(filter)
	}
	if srcIP != "" && destIP != "" {
		parts = append(parts, fmt.Sprintf("((src host %s and dst host %s) or (src host %s and dst host %s))", srcIP, destIP, destIP, srcIP))
	} else if srcIP != "" {
		parts = append(parts, "host "+srcIP)
	} else if destIP != "" {
		parts = append(parts, "host "+destIP)
	}
	if (proto == openngfwv1.Protocol_PROTOCOL_TCP || proto == openngfwv1.Protocol_PROTOCOL_UDP) && srcPort > 0 {
		parts = append(parts, "port "+strconv.Itoa(int(srcPort)))
	}
	if (proto == openngfwv1.Protocol_PROTOCOL_TCP || proto == openngfwv1.Protocol_PROTOCOL_UDP) && destPort > 0 && destPort != srcPort {
		parts = append(parts, "port "+strconv.Itoa(int(destPort)))
	}
	if len(parts) == 0 {
		parts = append(parts, "ip")
	}
	filter := strings.Join(parts, " and ")
	return filter, strings.Fields(filter)
}

func runPacketCapture(ctx context.Context, cfg SystemStatusConfig, limit time.Duration, args []string) ([]byte, bool, error) {
	if cfg.CommandRun != nil {
		out, err := cfg.CommandRun(ctx, "tcpdump", args...)
		return out, false, err
	}
	return runTimedCommand(ctx, limit, "tcpdump", args...)
}

func runTimedCommand(ctx context.Context, limit time.Duration, name string, args ...string) ([]byte, bool, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		return out.Bytes(), false, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case err := <-done:
		return out.Bytes(), false, err
	case <-ctx.Done():
		err := <-done
		if err != nil {
			return out.Bytes(), false, err
		}
		return out.Bytes(), false, ctx.Err()
	case <-timer.C:
		if cmd.Process != nil {
			_ = cmd.Process.Signal(os.Interrupt)
		}
		select {
		case err := <-done:
			return out.Bytes(), true, err
		case <-time.After(5 * time.Second):
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			return out.Bytes(), true, <-done
		}
	}
}

func captureProtoName(proto openngfwv1.Protocol) string {
	switch proto {
	case openngfwv1.Protocol_PROTOCOL_TCP:
		return "tcp"
	case openngfwv1.Protocol_PROTOCOL_UDP:
		return "udp"
	case openngfwv1.Protocol_PROTOCOL_ICMP:
		return "icmp"
	default:
		return ""
	}
}

func shellJoin(argv []string) string {
	quoted := make([]string, 0, len(argv))
	for _, arg := range argv {
		if safeShellWordRE.MatchString(arg) {
			quoted = append(quoted, arg)
			continue
		}
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

func shellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}

func captureExitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return 1
}

func captureAuditDetail(plan *openngfwv1.PacketCapturePlan, stage, detail string) string {
	if plan == nil {
		return fmt.Sprintf("%s: %s", stage, detail)
	}
	return fmt.Sprintf("%s: iface=%s proto=%s flow_id=%s src=%s:%d dst=%s:%d output=%s filter=%q detail=%s",
		stage, plan.GetInterface(), plan.GetProtocol().String(), plan.GetFlowId(), plan.GetSrcIp(), plan.GetSrcPort(), plan.GetDestIp(), plan.GetDestPort(), plan.GetOutputPath(), plan.GetBpfFilter(), detail)
}

func captureRetentionAuditDetail(job *openngfwv1.PacketCaptureJob) string {
	retention := job.GetRetention()
	parts := []string{
		"artifact_id=" + compactAuditField(job.GetArtifactId()),
		"state=" + compactAuditField(retention.GetState().String()),
		"reason=" + compactAuditField(retention.GetRetentionReason()),
	}
	if job.GetPlan().GetFlowId() != "" {
		parts = append(parts, "flow_id="+compactAuditField(job.GetPlan().GetFlowId()))
	}
	if retention.GetRetainUntil() != "" {
		parts = append(parts, "retain_until="+compactAuditField(retention.GetRetainUntil()))
	}
	if retention.GetCaseId() != "" {
		parts = append(parts, "case_id="+compactAuditField(retention.GetCaseId()))
	}
	if job.GetSha256() != "" {
		parts = append(parts, "sha256="+job.GetSha256())
	}
	return strings.Join(parts, " ")
}

func (s *SystemService) auditPacketCaptureFailure(ctx context.Context, plan *openngfwv1.PacketCapturePlan, stage, detail string) error {
	return s.auditPacketCapture(ctx, "packet-capture-failed", captureAuditDetail(plan, stage, detail))
}

func (s *SystemService) auditPacketCapture(ctx context.Context, action string, detail string) error {
	if s.Store == nil {
		return nil
	}
	identity := auditIdentity(ctx)
	return s.Store.AppendAudit(store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role,
		AuthSource: identity.AuthSource,
		Action:     action,
		Detail:     detail,
	})
}
