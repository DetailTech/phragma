package apiserver

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/supportbundle"
	"github.com/detailtech/oss-ngfw/internal/version"
)

// GetSupportBundle returns a redacted operational support bundle assembled from
// runtime, policy, audit, release, and evidence endpoints.
func (s *SystemService) GetSupportBundle(ctx context.Context, req *openngfwv1.GetSupportBundleRequest) (*openngfwv1.GetSupportBundleResponse, error) {
	if req == nil {
		req = &openngfwv1.GetSupportBundleRequest{}
	}
	bundle := s.collectSupportBundle(ctx, time.Now().UTC(), supportbundle.Limits{
		VersionLimit: req.GetVersionLimit(),
		AuditLimit:   req.GetAuditLimit(),
		EventLimit:   req.GetEventLimit(),
	})
	resp, err := supportbundle.ToProto(bundle)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode support bundle response: %v", err)
	}
	return resp, nil
}

func (s *SystemService) collectSupportBundle(ctx context.Context, now time.Time, limits supportbundle.Limits) supportbundle.Bundle {
	limits = limits.Normalize()
	endpoints := map[string]supportbundle.Endpoint{}
	collected := supportbundle.Collected{}

	statusResp, err := s.GetStatus(ctx, &openngfwv1.GetStatusRequest{})
	collected.Status = statusResp
	endpoints["status"] = supportbundle.ProtoEndpoint(statusResp, err)

	haResp, err := s.GetHighAvailabilityStatus(ctx, &openngfwv1.GetHighAvailabilityStatusRequest{})
	endpoints["highAvailabilityStatus"] = supportbundle.ProtoEndpoint(haResp, err)

	telemetryExportResp, err := s.GetTelemetryExportStatus(ctx, &openngfwv1.GetTelemetryExportStatusRequest{})
	collected.TelemetryExport = telemetryExportResp
	endpoints["telemetryExportStatus"] = supportbundle.ProtoEndpoint(telemetryExportResp, err)

	identityResp, err := s.GetIdentity(ctx, &openngfwv1.GetIdentityRequest{})
	endpoints["identity"] = supportbundle.ProtoEndpoint(identityResp, err)

	if s.Policy == nil {
		err := status.Error(codes.Internal, "policy service is not configured")
		endpoints["runningPolicy"] = supportbundle.RunningPolicyEndpoint(nil, err)
		endpoints["candidatePolicy"] = supportbundle.CandidatePolicyEndpoint(nil, err)
		endpoints["candidateStatus"] = supportbundle.ProtoEndpoint(nil, err)
		endpoints["candidateValidation"] = supportbundle.CandidateValidationEndpoint(nil, err)
		endpoints["runtimeReadinessPreflight"] = supportbundle.ProtoEndpoint(nil, err)
		endpoints["versions"] = supportbundle.ProtoEndpoint(nil, err)
		endpoints["audit"] = supportbundle.ProtoEndpoint(nil, err)
		endpoints["auditIntegrity"] = supportbundle.ProtoEndpoint(nil, err)
	} else {
		runningResp, err := s.Policy.GetPolicy(ctx, &openngfwv1.GetPolicyRequest{Source: openngfwv1.PolicySource_POLICY_SOURCE_RUNNING})
		collected.Running = runningResp
		endpoints["runningPolicy"] = supportbundle.RunningPolicyEndpoint(runningResp, err)

		candidateResp, err := s.Policy.GetPolicy(ctx, &openngfwv1.GetPolicyRequest{Source: openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE})
		endpoints["candidatePolicy"] = supportbundle.CandidatePolicyEndpoint(candidateResp, err)

		candidateStatusResp, err := s.Policy.GetCandidateStatus(ctx, &openngfwv1.GetCandidateStatusRequest{})
		collected.CandStat = candidateStatusResp
		endpoints["candidateStatus"] = supportbundle.ProtoEndpoint(candidateStatusResp, err)

		validateResp, err := s.Policy.Validate(ctx, &openngfwv1.ValidateRequest{})
		collected.Validate = validateResp
		endpoints["candidateValidation"] = supportbundle.CandidateValidationEndpoint(validateResp, err)

		runningPolicy, targetPolicy := supportBundleRuntimeReadinessPolicies(runningResp, candidateResp)
		runtimeReadinessResp, err := s.CheckRuntimeReadiness(ctx, &openngfwv1.CheckRuntimeReadinessRequest{
			Operation:     "commit",
			TargetPolicy:  targetPolicy,
			RunningPolicy: runningPolicy,
		})
		endpoints["runtimeReadinessPreflight"] = supportbundle.ProtoEndpoint(runtimeReadinessResp, err)

		versionsResp, err := s.Policy.ListVersions(ctx, &openngfwv1.ListVersionsRequest{Limit: limits.VersionLimit})
		endpoints["versions"] = supportbundle.ProtoEndpoint(versionsResp, err)

		auditResp, err := s.Policy.ListAuditEntries(ctx, &openngfwv1.ListAuditEntriesRequest{Limit: limits.AuditLimit})
		endpoints["audit"] = supportbundle.ProtoEndpoint(auditResp, err)

		auditIntegrityResp, err := s.Policy.VerifyAuditIntegrity(ctx, &openngfwv1.VerifyAuditIntegrityRequest{})
		collected.AuditOK = auditIntegrityResp
		endpoints["auditIntegrity"] = supportbundle.ProtoEndpoint(auditIntegrityResp, err)
	}

	if s.Alerts == nil {
		endpoints["alerts"] = supportbundle.ProtoEndpoint(nil, status.Error(codes.Internal, "alert service is not configured"))
	} else {
		alertResp, err := s.Alerts.ListAlerts(ctx, &openngfwv1.ListAlertsRequest{Limit: limits.EventLimit})
		collected.Alerts = alertResp
		endpoints["alerts"] = supportbundle.ProtoEndpoint(alertResp, err)
	}

	if s.Flows == nil {
		err := status.Error(codes.Internal, "flow service is not configured")
		endpoints["flows"] = supportbundle.ProtoEndpoint(nil, err)
		endpoints["sessions"] = supportbundle.ProtoEndpoint(nil, err)
	} else {
		flowResp, err := s.Flows.ListFlows(ctx, &openngfwv1.ListFlowsRequest{Limit: limits.EventLimit})
		collected.Flows = flowResp
		endpoints["flows"] = supportbundle.ProtoEndpoint(flowResp, err)

		sessionResp, err := s.Flows.ListSessions(ctx, &openngfwv1.ListSessionsRequest{Limit: limits.EventLimit})
		collected.Sessions = sessionResp
		endpoints["sessions"] = supportbundle.ProtoEndpoint(sessionResp, err)
	}

	if s.Intel == nil {
		err := status.Error(codes.Internal, "intel service is not configured")
		endpoints["feeds"] = supportbundle.ProtoEndpoint(nil, err)
		endpoints["contentPackages"] = supportbundle.ProtoEndpoint(nil, err)
	} else {
		feedResp, err := s.Intel.ListFeeds(ctx, &openngfwv1.ListFeedsRequest{})
		collected.Feeds = feedResp
		endpoints["feeds"] = supportbundle.ProtoEndpoint(feedResp, err)

		contentResp, err := s.Intel.ListContentPackages(ctx, &openngfwv1.ListContentPackagesRequest{})
		collected.Content = contentResp
		endpoints["contentPackages"] = supportbundle.ProtoEndpoint(contentResp, err)
	}

	releaseResp, err := s.GetReleaseAcceptanceStatus(ctx, &openngfwv1.GetReleaseAcceptanceStatusRequest{})
	collected.Release = releaseResp
	endpoints["releaseAcceptanceStatus"] = supportbundle.ProtoEndpoint(releaseResp, err)

	return supportbundle.Build(
		now,
		supportbundle.Collector{Type: "server", Name: "controld", Version: version.String()},
		supportbundle.Client{},
		endpoints,
		collected,
	)
}

func supportBundleRuntimeReadinessPolicies(runningResp, candidateResp *openngfwv1.GetPolicyResponse) (*openngfwv1.Policy, *openngfwv1.Policy) {
	var runningPolicy *openngfwv1.Policy
	if runningResp != nil {
		runningPolicy = runningResp.GetPolicy()
	}
	targetPolicy := runningPolicy
	if candidateResp != nil && candidateResp.GetPolicy() != nil {
		targetPolicy = candidateResp.GetPolicy()
	}
	return runningPolicy, targetPolicy
}
