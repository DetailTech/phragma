package apiserver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/appid"
	"github.com/detailtech/oss-ngfw/internal/contentpkg"
	"github.com/detailtech/oss-ngfw/internal/store"
	"github.com/detailtech/oss-ngfw/internal/telemetry"
)

const (
	defaultAppIDObservationLimit     = 100
	defaultAppIDObservationFlowLimit = 1000
)

// AppIDServer implements first-party Phragma App-ID review workflows.
type AppIDServer struct {
	openngfwv1.UnimplementedAppIdServiceServer

	EvePath    string
	Store      *store.Store
	ContentDir string
	Policy     *PolicyServer
}

//nolint:revive // Method name is fixed by the generated gRPC service interface.
func (s *AppIDServer) ListAppIdObservations(_ context.Context, req *openngfwv1.ListAppIdObservationsRequest) (*openngfwv1.ListAppIdObservationsResponse, error) {
	since, err := optionalTimestamp(req.GetSince(), "since")
	if err != nil {
		return nil, err
	}
	until, err := optionalTimestamp(req.GetUntil(), "until")
	if err != nil {
		return nil, err
	}
	if !since.IsZero() && !until.IsZero() && since.After(until) {
		return nil, status.Error(codes.InvalidArgument, "since must be at or before until")
	}
	offset, err := pageOffset(req.GetPageCursor())
	if err != nil {
		return nil, err
	}
	running, runningVersion, err := runningPolicySnapshot(s.Store)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read running policy context: %v", err)
	}
	flowLimit := int(req.GetFlowLimit())
	if flowLimit <= 0 {
		flowLimit = defaultAppIDObservationFlowLimit
	}
	threshold := req.GetConfidenceThreshold()
	if threshold == 0 {
		threshold = appid.DefaultObservationConfidenceThreshold
	}
	appDefs, err := appDefinitionsForClassification(running, s.ContentDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read App-ID taxonomy: %v", err)
	}
	flows, err := telemetry.ReadFlowsFilteredWithAppDefinitions(s.EvePath, telemetry.FlowFilter{
		Limit: flowLimit,
		Since: since,
		Until: until,
	}, appDefs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read flows: %v", err)
	}
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = defaultAppIDObservationLimit
	}
	observations := appid.BuildObservations(observedFlows(flows), appid.ObservationOptions{
		ConfidenceThreshold: threshold,
	})
	appPackage, err := appIDPackageSnapshot(s.ContentDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read App-ID content package: %v", err)
	}
	resp := &openngfwv1.ListAppIdObservationsResponse{
		RunningPolicyVersion:       runningVersion,
		PolicyContext:              telemetryPolicyContext(s.Store, runningVersion),
		ScannedFlows:               uint32(len(flows)),
		ConfidenceThreshold:        threshold,
		AppIdPackageVersion:        appPackage.Version,
		AppIdPackageManifestSha256: appPackage.ManifestSHA256,
	}
	totalMatches := 0
	for _, obs := range observations {
		if !observationMatchesRequest(obs, req) {
			continue
		}
		totalMatches++
		if totalMatches <= offset {
			continue
		}
		if len(resp.Observations) == limit {
			continue
		}
		resp.Observations = append(resp.Observations, protoObservation(obs))
	}
	resp.TotalMatches = uint32(totalMatches)
	next := offset + len(resp.Observations)
	resp.HasMore = next < totalMatches
	if resp.HasMore {
		resp.NextCursor = fmt.Sprintf("%d", next)
	}
	return resp, nil
}

// StageAppIdObservation stages an App-ID definition, and optionally a top
// deny rule, into the candidate policy. It does not apply runtime state.
//
//nolint:revive // Method name is fixed by the generated gRPC service interface.
func (s *AppIDServer) StageAppIdObservation(ctx context.Context, req *openngfwv1.StageAppIdObservationRequest) (*openngfwv1.StageAppIdObservationResponse, error) {
	if s.Policy == nil {
		return nil, status.Error(codes.Internal, "policy service is required for App-ID promotion")
	}
	reason := strings.TrimSpace(req.GetReason())
	if reason == "" {
		return nil, status.Error(codes.InvalidArgument, "reason is required")
	}
	queueID := strings.TrimSpace(req.GetQueueId())
	if queueID == "" {
		return nil, status.Error(codes.InvalidArgument, "queue_id is required")
	}
	mode, err := appIDStageMode(req.GetMode())
	if err != nil {
		return nil, err
	}
	if mode == openngfwv1.AppIdObservationStageMode_APP_ID_OBSERVATION_STAGE_MODE_DEFINE_AND_DROP && !req.GetConfirmDrop() {
		return nil, status.Error(codes.InvalidArgument, "confirm_drop is required for define-and-drop App-ID promotion")
	}

	obs, err := s.findAppIDObservationForStage(req)
	if err != nil {
		return nil, err
	}
	if obs.Kind == appid.ObservationKindConflictingEvidence {
		return nil, status.Error(codes.FailedPrecondition, "conflicting App-ID observations require investigation before promotion")
	}
	app, err := appIDPromotionApplication(obs, req.GetApplicationOverride())
	if err != nil {
		return nil, err
	}
	if mode == openngfwv1.AppIdObservationStageMode_APP_ID_OBSERVATION_STAGE_MODE_DEFINE_AND_DROP && !appMatchesObservationPort(app, obs) {
		return nil, status.Error(codes.FailedPrecondition, "define-and-drop requires a TCP/UDP port hint matching the observation")
	}

	s.Policy.mu.Lock()
	defer s.Policy.mu.Unlock()

	stage, err := s.stageAppIDObservationCandidate(obs, app, mode, reason)
	if err != nil {
		return nil, err
	}
	validation, err := s.Policy.Validate(ctx, &openngfwv1.ValidateRequest{Policy: stage.policy})
	if err != nil {
		return nil, err
	}
	if !validation.GetValid() {
		return &openngfwv1.StageAppIdObservationResponse{
			Observation:       protoObservation(obs),
			Application:       stage.application,
			ApplicationReused: stage.applicationReused,
			Rule:              stage.rule,
			Validation:        validation,
		}, nil
	}
	identity := auditIdentity(ctx)
	if err := s.Policy.store.SetCandidateWithAudit(stage.policy, store.AuditEntry{
		Actor:      identity.Name,
		ActorRole:  identity.Role,
		AuthSource: identity.AuthSource,
		Action:     "stage-app-id-observation",
		Detail:     appIDPromotionAuditDetail(obs, stage.application, stage.rule, mode, reason, stage.applicationReused),
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "store candidate with audit: %v", err)
	}
	statusResp, err := s.Policy.GetCandidateStatus(ctx, &openngfwv1.GetCandidateStatusRequest{})
	if err != nil {
		return nil, err
	}
	diff, err := s.Policy.DiffPolicy(ctx, &openngfwv1.DiffPolicyRequest{
		FromSource: openngfwv1.PolicySource_POLICY_SOURCE_RUNNING,
		ToSource:   openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE,
	})
	if err != nil {
		return nil, err
	}
	return &openngfwv1.StageAppIdObservationResponse{
		Observation:       protoObservation(obs),
		Application:       stage.application,
		ApplicationReused: stage.applicationReused,
		Rule:              stage.rule,
		CandidateStatus:   statusResp,
		Validation:        validation,
		Diff:              diff,
	}, nil
}

// StageAppIdRegressionSample appends a reviewed observation to the draft App-ID
// regression corpus. The artifact is package-builder input, not installed
// production content.
//
//nolint:revive // Method name is fixed by the generated gRPC service interface.
func (s *AppIDServer) StageAppIdRegressionSample(ctx context.Context, req *openngfwv1.StageAppIdRegressionSampleRequest) (*openngfwv1.StageAppIdRegressionSampleResponse, error) {
	reason := strings.TrimSpace(req.GetReason())
	if reason == "" {
		return nil, status.Error(codes.InvalidArgument, "reason is required")
	}
	queueID := strings.TrimSpace(req.GetQueueId())
	if queueID == "" {
		return nil, status.Error(codes.InvalidArgument, "queue_id is required")
	}
	if strings.TrimSpace(s.ContentDir) == "" {
		return nil, status.Error(codes.FailedPrecondition, "content directory is required for App-ID regression corpus staging")
	}
	obs, err := s.findAppIDObservationForRegressionSample(req)
	if err != nil {
		return nil, err
	}
	appPackage, err := appIDPackageSnapshot(s.ContentDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read App-ID content package: %v", err)
	}
	sample, err := appid.RegressionSampleFromObservation(obs, appid.RegressionSampleOptions{
		Reason:                     reason,
		PCAPSHA256:                 req.GetPcapSha256(),
		ExpectedApp:                req.GetExpectedApp(),
		ObservedApp:                req.GetObservedApp(),
		AppIDPackageVersion:        appPackage.Version,
		AppIDPackageManifestSHA256: appPackage.ManifestSHA256,
	})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	result, err := appid.AppendRegressionSample(s.ContentDir, sample)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "append App-ID regression sample: %v", err)
	}
	if s.Store != nil {
		identity := auditIdentity(ctx)
		if err := s.Store.AppendAudit(store.AuditEntry{
			Actor:      identity.Name,
			ActorRole:  identity.Role,
			AuthSource: identity.AuthSource,
			Action:     "stage-app-id-regression-sample",
			Detail:     appIDRegressionSampleAuditDetail(obs, sample, result),
		}); err != nil {
			return nil, status.Errorf(codes.Internal, "append audit: %v", err)
		}
	}
	return &openngfwv1.StageAppIdRegressionSampleResponse{
		Observation:                protoObservation(obs),
		Sample:                     protoRegressionSample(sample),
		DraftArtifact:              result.Artifact,
		SampleCount:                result.SampleCount,
		AppIdPackageVersion:        appPackage.Version,
		AppIdPackageManifestSha256: appPackage.ManifestSHA256,
		Detail:                     fmt.Sprintf("staged %s as draft App-ID regression sample %s", obs.QueueID, sample.SampleID),
	}, nil
}

// CompareAppIdReplay returns a read-only App-ID lab replay/comparison report.
// It does not stage policy, append corpus rows, or apply runtime state.
//
//nolint:revive // Method name is fixed by the generated gRPC service interface.
func (s *AppIDServer) CompareAppIdReplay(_ context.Context, req *openngfwv1.CompareAppIdReplayRequest) (*openngfwv1.CompareAppIdReplayResponse, error) {
	input, err := s.appIDReplayInput(req)
	if err != nil {
		return nil, err
	}
	appPackage, err := appIDPackageSnapshot(s.ContentDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read App-ID content package: %v", err)
	}
	if input.AppIDPackageVersion == "" {
		input.AppIDPackageVersion = appPackage.Version
	}
	if input.AppIDPackageManifestSHA256 == "" {
		input.AppIDPackageManifestSHA256 = appPackage.ManifestSHA256
	}
	report := appid.CompareReplay(input, req.GetConfidenceThreshold())
	return &openngfwv1.CompareAppIdReplayResponse{
		Report:                     protoReplayReport(report),
		AppIdPackageVersion:        appPackage.Version,
		AppIdPackageManifestSha256: appPackage.ManifestSHA256,
		PolicyContext:              telemetryPolicyContext(s.Store, 0),
		Detail:                     "App-ID replay compared in lab evidence mode; no policy, corpus, or dataplane state changed",
	}, nil
}

func (s *AppIDServer) appIDReplayInput(req *openngfwv1.CompareAppIdReplayRequest) (appid.ReplayInput, error) {
	if strings.TrimSpace(req.GetQueueId()) != "" {
		obs, err := s.findAppIDObservation(req.GetQueueId(), req.GetFlowLimit(), req.GetConfidenceThreshold(), req.GetSince(), req.GetUntil())
		if err != nil {
			return appid.ReplayInput{}, err
		}
		return appid.ReplayInputFromObservation(obs, req.GetExpectedApp()), nil
	}
	if sample := req.GetCorpusSample(); sample != nil {
		return appid.ReplayInputFromRegressionSample(regressionSampleFromProto(sample), appid.RegressionCorpusArtifact, req.GetExpectedApp()), nil
	}
	if obs := req.GetObservation(); obs != nil {
		return appid.ReplayInputFromObservation(observationFromProto(obs), req.GetExpectedApp()), nil
	}
	return appid.ReplayInput{}, status.Error(codes.InvalidArgument, "queue_id, observation, or corpus_sample is required")
}

func appIDStageMode(mode openngfwv1.AppIdObservationStageMode) (openngfwv1.AppIdObservationStageMode, error) {
	switch mode {
	case openngfwv1.AppIdObservationStageMode_APP_ID_OBSERVATION_STAGE_MODE_UNSPECIFIED,
		openngfwv1.AppIdObservationStageMode_APP_ID_OBSERVATION_STAGE_MODE_DEFINE_ONLY:
		return openngfwv1.AppIdObservationStageMode_APP_ID_OBSERVATION_STAGE_MODE_DEFINE_ONLY, nil
	case openngfwv1.AppIdObservationStageMode_APP_ID_OBSERVATION_STAGE_MODE_DEFINE_AND_DROP:
		return mode, nil
	default:
		return openngfwv1.AppIdObservationStageMode_APP_ID_OBSERVATION_STAGE_MODE_UNSPECIFIED,
			status.Error(codes.InvalidArgument, "mode must be DEFINE_ONLY or DEFINE_AND_DROP")
	}
}

func (s *AppIDServer) findAppIDObservationForStage(req *openngfwv1.StageAppIdObservationRequest) (appid.Observation, error) {
	return s.findAppIDObservation(req.GetQueueId(), req.GetFlowLimit(), req.GetConfidenceThreshold(), req.GetSince(), req.GetUntil())
}

func (s *AppIDServer) findAppIDObservationForRegressionSample(req *openngfwv1.StageAppIdRegressionSampleRequest) (appid.Observation, error) {
	return s.findAppIDObservation(req.GetQueueId(), req.GetFlowLimit(), req.GetConfidenceThreshold(), req.GetSince(), req.GetUntil())
}

func (s *AppIDServer) findAppIDObservation(queueID string, flowLimitValue, confidenceThreshold uint32, sinceTS, untilTS *timestamppb.Timestamp) (appid.Observation, error) {
	since, err := optionalTimestamp(sinceTS, "since")
	if err != nil {
		return appid.Observation{}, err
	}
	until, err := optionalTimestamp(untilTS, "until")
	if err != nil {
		return appid.Observation{}, err
	}
	if !since.IsZero() && !until.IsZero() && since.After(until) {
		return appid.Observation{}, status.Error(codes.InvalidArgument, "since must be at or before until")
	}
	running, _, err := runningPolicySnapshot(s.Store)
	if err != nil {
		return appid.Observation{}, status.Errorf(codes.Internal, "read running policy context: %v", err)
	}
	flowLimit := int(flowLimitValue)
	if flowLimit <= 0 {
		flowLimit = defaultAppIDObservationFlowLimit
	}
	threshold := confidenceThreshold
	if threshold == 0 {
		threshold = appid.DefaultObservationConfidenceThreshold
	}
	appDefs, err := appDefinitionsForClassification(running, s.ContentDir)
	if err != nil {
		return appid.Observation{}, status.Errorf(codes.Internal, "read App-ID taxonomy: %v", err)
	}
	flows, err := telemetry.ReadFlowsFilteredWithAppDefinitions(s.EvePath, telemetry.FlowFilter{
		Limit: flowLimit,
		Since: since,
		Until: until,
	}, appDefs)
	if err != nil {
		return appid.Observation{}, status.Errorf(codes.Internal, "read flows: %v", err)
	}
	for _, obs := range appid.BuildObservations(observedFlows(flows), appid.ObservationOptions{ConfidenceThreshold: threshold}) {
		if obs.QueueID == strings.TrimSpace(queueID) {
			return obs, nil
		}
	}
	return appid.Observation{}, status.Errorf(codes.NotFound, "App-ID observation queue_id %q was not found in current telemetry", strings.TrimSpace(queueID))
}

type stagedAppIDObservation struct {
	policy            *openngfwv1.Policy
	application       *openngfwv1.Application
	applicationReused bool
	rule              *openngfwv1.Rule
}

func (s *AppIDServer) stageAppIDObservationCandidate(obs appid.Observation, app *openngfwv1.Application, mode openngfwv1.AppIdObservationStageMode, reason string) (*stagedAppIDObservation, error) {
	base, err := s.Policy.candidateOrRunningPolicy()
	if err != nil {
		return nil, err
	}
	app = proto.Clone(app).(*openngfwv1.Application)
	var reused bool
	if existing := findApplicationByName(base.GetApplications(), app.GetName()); existing != nil {
		if !proto.Equal(existing, app) {
			return nil, status.Errorf(codes.AlreadyExists, "application %q already exists with different definition", app.GetName())
		}
		app = proto.Clone(existing).(*openngfwv1.Application)
		reused = true
	} else {
		base.Applications = append(base.Applications, app)
	}
	var rule *openngfwv1.Rule
	if mode == openngfwv1.AppIdObservationStageMode_APP_ID_OBSERVATION_STAGE_MODE_DEFINE_AND_DROP {
		var created bool
		rule, created, err = ensureAppIDObservationDropRule(base, obs, app, reason)
		if err != nil {
			return nil, err
		}
		if created {
			base.Rules = append([]*openngfwv1.Rule{rule}, base.GetRules()...)
		}
	}
	return &stagedAppIDObservation{policy: base, application: app, applicationReused: reused, rule: rule}, nil
}

func appIDPromotionApplication(obs appid.Observation, override *openngfwv1.Application) (*openngfwv1.Application, error) {
	var app *openngfwv1.Application
	if override != nil && strings.TrimSpace(override.GetName()) != "" {
		app = proto.Clone(override).(*openngfwv1.Application)
	} else {
		app = protoObservation(obs).GetSuggestedApplication()
	}
	if app == nil || strings.TrimSpace(app.GetName()) == "" {
		return nil, status.Error(codes.FailedPrecondition, "observation has no suggested App-ID application")
	}
	app.Name = strings.TrimSpace(app.GetName())
	app.DisplayName = strings.TrimSpace(app.GetDisplayName())
	app.Category = strings.TrimSpace(app.GetCategory())
	app.Description = strings.TrimSpace(app.GetDescription())
	for i, signal := range app.EngineSignals {
		app.EngineSignals[i] = strings.TrimSpace(signal)
	}
	if len(app.GetEngineSignals()) == 0 && !hasAppIDPortHints(app) {
		return nil, status.Error(codes.FailedPrecondition, "application needs an engine signal or TCP/UDP port hint before promotion")
	}
	return app, nil
}

func hasAppIDPortHints(app *openngfwv1.Application) bool {
	return len(appPortMatches(app)) > 0
}

func appMatchesObservationPort(app *openngfwv1.Application, obs appid.Observation) bool {
	protoName := strings.ToLower(strings.TrimSpace(obs.Protocol))
	if obs.DestPort == 0 || obs.DestPort > 65535 || (protoName != "tcp" && protoName != "udp") {
		return false
	}
	port := uint16(obs.DestPort)
	for _, match := range appPortMatches(app) {
		end := match.End
		if end == 0 {
			end = match.Start
		}
		if match.Protocol == protoName && port >= match.Start && port <= end {
			return true
		}
	}
	return false
}

func ensureAppIDObservationDropRule(p *openngfwv1.Policy, obs appid.Observation, app *openngfwv1.Application, reason string) (*openngfwv1.Rule, bool, error) {
	src, _, err := ensureAppIDObservationAddress(p, obs.SampleSrcIP, "appid-src-")
	if err != nil {
		return nil, false, status.Errorf(codes.FailedPrecondition, "sample source address: %v", err)
	}
	dst, _, err := ensureAppIDObservationAddress(p, obs.SampleDestIP, "appid-dst-")
	if err != nil {
		return nil, false, status.Errorf(codes.FailedPrecondition, "sample destination address: %v", err)
	}
	if existing := findMatchingAppIDObservationDropRule(p.GetRules(), src.GetName(), dst.GetName(), app.GetName()); existing != nil {
		return proto.Clone(existing).(*openngfwv1.Rule), false, nil
	}
	name := uniquePolicyObjectName(p.GetRules(), fmt.Sprintf("drop-app-%s-%s-to-%s", app.GetName(), obs.SampleSrcIP, obs.SampleDestIP))
	detail := fmt.Sprintf("Drop observed App-ID %s for %s to %s using current TCP/UDP port-hint enforcement.", app.GetName(), obs.SampleSrcIP, obs.SampleDestIP)
	if reason != "" {
		detail += " Reason: " + reason
	}
	return &openngfwv1.Rule{
		Name:                 name,
		SourceAddresses:      []string{src.GetName()},
		DestinationAddresses: []string{dst.GetName()},
		Applications:         []string{app.GetName()},
		Action:               openngfwv1.Action_ACTION_DENY,
		Log:                  true,
		Description:          detail,
	}, true, nil
}

func findMatchingAppIDObservationDropRule(rules []*openngfwv1.Rule, srcName, dstName, appName string) *openngfwv1.Rule {
	for _, rule := range rules {
		if rule.GetDisabled() ||
			rule.GetAction() != openngfwv1.Action_ACTION_DENY ||
			len(rule.GetServices()) != 0 ||
			!sameSingleRef(rule.GetSourceAddresses(), srcName) ||
			!sameSingleRef(rule.GetDestinationAddresses(), dstName) ||
			!sameSingleRef(rule.GetApplications(), appName) {
			continue
		}
		return rule
	}
	return nil
}

func sameSingleRef(values []string, want string) bool {
	return len(values) == 1 && values[0] == want
}

//nolint:unparam // The created flag is part of the helper contract for audited candidate changes.
func ensureAppIDObservationAddress(p *openngfwv1.Policy, ip, prefix string) (*openngfwv1.Address, bool, error) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil, false, fmt.Errorf("is required")
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, false, fmt.Errorf("invalid IP %q", ip)
	}
	cidr := netip.PrefixFrom(addr, addr.BitLen()).String()
	for _, existing := range p.GetAddresses() {
		if existing.GetCidr() == cidr {
			return existing, true, nil
		}
	}
	created := &openngfwv1.Address{
		Name:        uniquePolicyObjectName(p.GetAddresses(), prefix+ip),
		Cidr:        cidr,
		Description: "Auto-added from App-ID observation promotion",
	}
	p.Addresses = append(p.Addresses, created)
	return created, false, nil
}

func findApplicationByName(apps []*openngfwv1.Application, name string) *openngfwv1.Application {
	name = strings.TrimSpace(name)
	for _, app := range apps {
		if app.GetName() == name {
			return app
		}
	}
	return nil
}

func appIDPromotionAuditDetail(obs appid.Observation, app *openngfwv1.Application, rule *openngfwv1.Rule, mode openngfwv1.AppIdObservationStageMode, reason string, reused bool) string {
	parts := []string{
		"queue_id=" + compactAuditField(obs.QueueID),
		"kind=" + compactAuditField(string(obs.Kind)),
		"app=" + compactAuditField(app.GetName()),
		"mode=" + compactAuditField(strings.ToLower(strings.TrimPrefix(mode.String(), "APP_ID_OBSERVATION_STAGE_MODE_"))),
		"reason=" + compactAuditField(reason),
	}
	if obs.EngineSignal != "" {
		parts = append(parts, "signal="+compactAuditField(obs.EngineSignal))
	}
	if obs.Protocol != "" && obs.DestPort != 0 {
		parts = append(parts, fmt.Sprintf("l4=%s/%d", strings.ToLower(obs.Protocol), obs.DestPort))
	}
	if reused {
		parts = append(parts, "application=reused")
	}
	if rule != nil {
		parts = append(parts, "rule="+compactAuditField(rule.GetName()))
	}
	return strings.Join(parts, " ")
}

func appIDRegressionSampleAuditDetail(obs appid.Observation, sample appid.RegressionSample, result appid.AppendResult) string {
	parts := []string{
		"queue_id=" + compactAuditField(obs.QueueID),
		"kind=" + compactAuditField(string(obs.Kind)),
		"sample_id=" + compactAuditField(sample.SampleID),
		"expected_app=" + compactAuditField(sample.ExpectedApp),
		"observed_app=" + compactAuditField(sample.ObservedApp),
		"pcap_sha256=" + compactAuditField(sample.PCAPSHA256),
		"artifact=" + compactAuditField(result.Artifact),
		fmt.Sprintf("sample_count=%d", result.SampleCount),
		"reason=" + compactAuditField(sample.Reason),
	}
	if sample.EngineSignal != "" {
		parts = append(parts, "signal="+compactAuditField(sample.EngineSignal))
	}
	if sample.Protocol != "" && sample.DestPort != 0 {
		parts = append(parts, fmt.Sprintf("l4=%s/%d", strings.ToLower(sample.Protocol), sample.DestPort))
	}
	return strings.Join(parts, " ")
}

func observedFlows(flows []telemetry.Flow) []appid.ObservedFlow {
	out := make([]appid.ObservedFlow, 0, len(flows))
	for _, flow := range flows {
		signalSource := ""
		if strings.TrimSpace(flow.AppProto) != "" {
			signalSource = "suricata.app_proto"
		}
		out = append(out, appid.ObservedFlow{
			Timestamp:          flow.Timestamp,
			SrcIP:              flow.SrcIP,
			SrcPort:            flow.SrcPort,
			DestIP:             flow.DestIP,
			DestPort:           flow.DestPort,
			Protocol:           flow.Proto,
			EngineSignal:       flow.AppProto,
			EngineSignalSource: signalSource,
			AppID:              flow.AppID,
			AppName:            flow.AppName,
			AppCategory:        flow.AppCategory,
			AppConfidence:      flow.AppConfidence,
			AppEvidence:        flow.AppEvidence,
			BytesToServer:      flow.BytesToServer,
			BytesToClient:      flow.BytesToClient,
			Packets:            flow.Packets,
			FlowID:             flow.FlowID,
			PolicyVersion:      flow.PolicyVersion,
		})
	}
	return out
}

func protoObservation(obs appid.Observation) *openngfwv1.AppIdObservation {
	return &openngfwv1.AppIdObservation{
		QueueId:              obs.QueueID,
		Kind:                 protoObservationKind(obs.Kind),
		AppId:                obs.AppID,
		AppName:              obs.AppName,
		AppCategory:          obs.AppCategory,
		AppConfidence:        obs.AppConfidence,
		EngineSignal:         obs.EngineSignal,
		EngineSignalSource:   obs.EngineSignalSource,
		Protocol:             obs.Protocol,
		DestPort:             obs.DestPort,
		Count:                obs.Count,
		FirstSeen:            timestamppb.New(obs.FirstSeen),
		LastSeen:             timestamppb.New(obs.LastSeen),
		Bytes:                obs.Bytes,
		Packets:              obs.Packets,
		SampleFlowId:         obs.SampleFlowID,
		SampleSrcIp:          obs.SampleSrcIP,
		SampleSrcPort:        obs.SampleSrcPort,
		SampleDestIp:         obs.SampleDestIP,
		AppEvidence:          obs.AppEvidence,
		SuggestedApplication: protoApplication(obs.SuggestedApplication),
	}
}

func protoRegressionSample(sample appid.RegressionSample) *openngfwv1.AppIdRegressionSample {
	return &openngfwv1.AppIdRegressionSample{
		SchemaVersion:              sample.SchemaVersion,
		SampleId:                   sample.SampleID,
		QueueId:                    sample.QueueID,
		ObservationKind:            protoObservationKind(sample.ObservationKind),
		ExpectedApp:                sample.ExpectedApp,
		ObservedApp:                sample.ObservedApp,
		EngineSignal:               sample.EngineSignal,
		EngineSignalSource:         sample.EngineSignalSource,
		Protocol:                   sample.Protocol,
		DestPort:                   sample.DestPort,
		SampleFlowId:               sample.SampleFlowID,
		SampleSrcIp:                sample.SampleSrcIP,
		SampleSrcPort:              sample.SampleSrcPort,
		SampleDestIp:               sample.SampleDestIP,
		AppConfidence:              sample.AppConfidence,
		AppEvidence:                append([]string(nil), sample.AppEvidence...),
		PcapSha256:                 sample.PCAPSHA256,
		Reason:                     sample.Reason,
		CreatedAt:                  timestamppb.New(sample.CreatedAt),
		AppIdPackageVersion:        sample.AppIDPackageVersion,
		AppIdPackageManifestSha256: sample.AppIDPackageManifestSHA256,
	}
}

func protoReplayReport(report appid.ReplayReport) *openngfwv1.AppIdReplayReport {
	return &openngfwv1.AppIdReplayReport{
		ReportId:              report.ReportID,
		Source:                report.Source,
		QueueId:               report.QueueID,
		SampleId:              report.SampleID,
		CorpusArtifact:        report.CorpusArtifact,
		PcapSha256:            report.PCAPSHA256,
		ObservedApp:           report.ObservedApp,
		ExpectedApp:           report.ExpectedApp,
		Confidence:            report.Confidence,
		Verdict:               protoReplayVerdict(report.Verdict),
		MismatchReasons:       append([]string(nil), report.MismatchReasons...),
		BoundedEvidence:       append([]string(nil), report.BoundedEvidence...),
		RecommendedNextAction: report.RecommendedNextAction,
		SampleFlowId:          report.SampleFlowID,
		EngineSignal:          report.EngineSignal,
		EngineSignalSource:    report.EngineSignalSource,
		Protocol:              report.Protocol,
		DestPort:              report.DestPort,
		ComparisonScope:       report.ComparisonScope,
	}
}

func protoReplayVerdict(verdict appid.ReplayVerdict) openngfwv1.AppIdReplayVerdict {
	switch verdict {
	case appid.ReplayVerdictMatch:
		return openngfwv1.AppIdReplayVerdict_APP_ID_REPLAY_VERDICT_MATCH
	case appid.ReplayVerdictMismatch:
		return openngfwv1.AppIdReplayVerdict_APP_ID_REPLAY_VERDICT_MISMATCH
	case appid.ReplayVerdictNeedsExpectedApp:
		return openngfwv1.AppIdReplayVerdict_APP_ID_REPLAY_VERDICT_NEEDS_EXPECTED_APP
	case appid.ReplayVerdictNeedsEvidence:
		return openngfwv1.AppIdReplayVerdict_APP_ID_REPLAY_VERDICT_NEEDS_EVIDENCE
	default:
		return openngfwv1.AppIdReplayVerdict_APP_ID_REPLAY_VERDICT_UNSPECIFIED
	}
}

func observationFromProto(obs *openngfwv1.AppIdObservation) appid.Observation {
	if obs == nil {
		return appid.Observation{}
	}
	return appid.Observation{
		QueueID:              strings.TrimSpace(obs.GetQueueId()),
		Kind:                 appObservationKind(obs.GetKind()),
		AppID:                strings.TrimSpace(obs.GetAppId()),
		AppName:              strings.TrimSpace(obs.GetAppName()),
		AppCategory:          strings.TrimSpace(obs.GetAppCategory()),
		AppConfidence:        obs.GetAppConfidence(),
		EngineSignal:         strings.TrimSpace(obs.GetEngineSignal()),
		EngineSignalSource:   strings.TrimSpace(obs.GetEngineSignalSource()),
		Protocol:             strings.TrimSpace(obs.GetProtocol()),
		DestPort:             obs.GetDestPort(),
		Count:                obs.GetCount(),
		FirstSeen:            protoTimestampTime(obs.GetFirstSeen()),
		LastSeen:             protoTimestampTime(obs.GetLastSeen()),
		Bytes:                obs.GetBytes(),
		Packets:              obs.GetPackets(),
		SampleFlowID:         strings.TrimSpace(obs.GetSampleFlowId()),
		SampleSrcIP:          strings.TrimSpace(obs.GetSampleSrcIp()),
		SampleSrcPort:        obs.GetSampleSrcPort(),
		SampleDestIP:         strings.TrimSpace(obs.GetSampleDestIp()),
		AppEvidence:          append([]string(nil), obs.GetAppEvidence()...),
		SuggestedApplication: appDefinitionFromProto(obs.GetSuggestedApplication()),
	}
}

func regressionSampleFromProto(sample *openngfwv1.AppIdRegressionSample) appid.RegressionSample {
	if sample == nil {
		return appid.RegressionSample{}
	}
	return appid.RegressionSample{
		SchemaVersion:              strings.TrimSpace(sample.GetSchemaVersion()),
		SampleID:                   strings.TrimSpace(sample.GetSampleId()),
		QueueID:                    strings.TrimSpace(sample.GetQueueId()),
		ObservationKind:            appObservationKind(sample.GetObservationKind()),
		ExpectedApp:                strings.TrimSpace(sample.GetExpectedApp()),
		ObservedApp:                strings.TrimSpace(sample.GetObservedApp()),
		EngineSignal:               strings.TrimSpace(sample.GetEngineSignal()),
		EngineSignalSource:         strings.TrimSpace(sample.GetEngineSignalSource()),
		Protocol:                   strings.TrimSpace(sample.GetProtocol()),
		DestPort:                   sample.GetDestPort(),
		SampleFlowID:               strings.TrimSpace(sample.GetSampleFlowId()),
		SampleSrcIP:                strings.TrimSpace(sample.GetSampleSrcIp()),
		SampleSrcPort:              sample.GetSampleSrcPort(),
		SampleDestIP:               strings.TrimSpace(sample.GetSampleDestIp()),
		AppConfidence:              sample.GetAppConfidence(),
		AppEvidence:                append([]string(nil), sample.GetAppEvidence()...),
		PCAPSHA256:                 strings.TrimSpace(sample.GetPcapSha256()),
		Reason:                     strings.TrimSpace(sample.GetReason()),
		CreatedAt:                  protoTimestampTime(sample.GetCreatedAt()),
		AppIDPackageVersion:        strings.TrimSpace(sample.GetAppIdPackageVersion()),
		AppIDPackageManifestSHA256: strings.TrimSpace(sample.GetAppIdPackageManifestSha256()),
	}
}

func appDefinitionFromProto(app *openngfwv1.Application) appid.Definition {
	if app == nil {
		return appid.Definition{}
	}
	def := appid.Definition{
		ID:            strings.TrimSpace(app.GetName()),
		Name:          strings.TrimSpace(app.GetDisplayName()),
		Category:      strings.TrimSpace(app.GetCategory()),
		EngineSignals: append([]string(nil), app.GetEngineSignals()...),
	}
	for _, port := range app.GetPorts() {
		var protoName string
		switch port.GetProtocol() {
		case openngfwv1.Protocol_PROTOCOL_TCP:
			protoName = "tcp"
		case openngfwv1.Protocol_PROTOCOL_UDP:
			protoName = "udp"
		default:
			continue
		}
		for _, pr := range port.GetPorts() {
			if pr.GetStart() == 0 || pr.GetStart() > 65535 {
				continue
			}
			end := pr.GetEnd()
			if end == 0 {
				end = pr.GetStart()
			}
			if end > 65535 || end < pr.GetStart() {
				continue
			}
			def.Ports = append(def.Ports, appid.PortMatch{Protocol: protoName, Start: uint16(pr.GetStart()), End: uint16(end)})
		}
	}
	return def
}

func protoTimestampTime(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

func appIDPackageSnapshot(contentDir string) (contentpkg.Status, error) {
	if strings.TrimSpace(contentDir) == "" {
		return contentpkg.Status{}, nil
	}
	return contentpkg.StatusFromDir("app-id", filepath.Join(contentDir, "app-id"))
}

func appDefinitionsForClassification(p *openngfwv1.Policy, contentDir string) ([]appid.Definition, error) {
	defs := appDefinitionsFromPolicy(p)
	if strings.TrimSpace(contentDir) == "" {
		return defs, nil
	}
	taxonomy, err := contentpkg.ReadAppIDTaxonomy(contentDir)
	if err != nil {
		if errors.Is(err, contentpkg.ErrEvidenceNotFound) || errors.Is(err, contentpkg.ErrInvalidPackage) {
			return defs, nil
		}
		return nil, err
	}
	return append(defs, taxonomy.Definitions...), nil
}

func protoObservationKind(kind appid.ObservationKind) openngfwv1.AppIdObservationKind {
	switch kind {
	case appid.ObservationKindUnknown:
		return openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_UNKNOWN
	case appid.ObservationKindLowConfidence:
		return openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_LOW_CONFIDENCE
	case appid.ObservationKindConflictingEvidence:
		return openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_CONFLICTING_EVIDENCE
	default:
		return openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_UNSPECIFIED
	}
}

func appObservationKind(kind openngfwv1.AppIdObservationKind) appid.ObservationKind {
	switch kind {
	case openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_UNKNOWN:
		return appid.ObservationKindUnknown
	case openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_LOW_CONFIDENCE:
		return appid.ObservationKindLowConfidence
	case openngfwv1.AppIdObservationKind_APP_ID_OBSERVATION_KIND_CONFLICTING_EVIDENCE:
		return appid.ObservationKindConflictingEvidence
	default:
		return ""
	}
}

func protoApplication(def appid.Definition) *openngfwv1.Application {
	app := &openngfwv1.Application{
		Name:          def.ID,
		DisplayName:   def.Name,
		Category:      def.Category,
		EngineSignals: append([]string(nil), def.EngineSignals...),
	}
	for _, port := range def.Ports {
		var proto openngfwv1.Protocol
		switch strings.ToLower(port.Protocol) {
		case "tcp":
			proto = openngfwv1.Protocol_PROTOCOL_TCP
		case "udp":
			proto = openngfwv1.Protocol_PROTOCOL_UDP
		default:
			continue
		}
		pr := &openngfwv1.PortRange{Start: uint32(port.Start)}
		if port.End != 0 && port.End != port.Start {
			pr.End = uint32(port.End)
		}
		app.Ports = append(app.Ports, &openngfwv1.ApplicationPort{
			Protocol: proto,
			Ports:    []*openngfwv1.PortRange{pr},
		})
	}
	return app
}

func observationMatchesRequest(obs appid.Observation, req *openngfwv1.ListAppIdObservationsRequest) bool {
	if kind := appObservationKind(req.GetKind()); kind != "" && obs.Kind != kind {
		return false
	}
	if req.GetEngineSignal() != "" && !strings.EqualFold(obs.EngineSignal, req.GetEngineSignal()) {
		return false
	}
	if req.GetProtocol() != "" && !strings.EqualFold(obs.Protocol, req.GetProtocol()) {
		return false
	}
	if req.GetPort() != 0 && obs.DestPort != req.GetPort() {
		return false
	}
	if req.GetQuery() != "" && !containsFoldLocal(strings.Join([]string{
		obs.QueueID,
		string(obs.Kind),
		obs.AppID,
		obs.AppName,
		obs.AppCategory,
		obs.EngineSignal,
		obs.EngineSignalSource,
		obs.Protocol,
		obs.SampleFlowID,
		obs.SampleSrcIP,
		obs.SampleDestIP,
		obs.SuggestedApplication.ID,
		obs.SuggestedApplication.Name,
		obs.SuggestedApplication.Category,
		strings.Join(obs.SuggestedApplication.EngineSignals, "\n"),
		strings.Join(obs.AppEvidence, "\n"),
	}, "\n"), req.GetQuery()) {
		return false
	}
	return true
}

func containsFoldLocal(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
