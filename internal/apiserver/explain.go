package apiserver

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/conntrack"
	"github.com/detailtech/oss-ngfw/internal/explain"
	"github.com/detailtech/oss-ngfw/internal/policy"
	"github.com/detailtech/oss-ngfw/internal/store"
	"github.com/detailtech/oss-ngfw/internal/telemetry"
)

// ExplainServer implements openngfw.v1.ExplainService over stored policies.
type ExplainServer struct {
	openngfwv1.UnimplementedExplainServiceServer

	Store *store.Store
	// EvePath is the local EVE stream used for flow_id correlation.
	EvePath string
	// CaptureDir is the local packet-capture artifact directory used for
	// flow_id correlation.
	CaptureDir string

	// CommandLookup and CommandRun are injectable for conntrack runtime
	// evidence tests. Nil values use the host defaults.
	CommandLookup func(string) (string, error)
	CommandRun    conntrack.Runner
}

// ExplainFlow evaluates a single tuple against running/candidate/version policy.
func (s *ExplainServer) ExplainFlow(ctx context.Context, req *openngfwv1.ExplainFlowRequest) (*openngfwv1.ExplainFlowResponse, error) {
	if s.Store == nil {
		return nil, status.Error(codes.Internal, "store is not configured")
	}
	p, version, err := s.policyFor(req)
	if err != nil {
		return nil, err
	}
	if errs := policy.Validate(p); len(errs) > 0 {
		return nil, status.Errorf(codes.FailedPrecondition, "policy is invalid: %s", strings.Join(errs, "; "))
	}
	resp, err := explain.ExplainFlow(p, req, version)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if req.GetIncludeRuntime() {
		s.attachRuntimeEvidence(ctx, req, resp)
		explain.AnnotateDecisionVocabulary(resp)
	}
	return resp, nil
}

func (s *ExplainServer) attachRuntimeEvidence(ctx context.Context, req *openngfwv1.ExplainFlowRequest, resp *openngfwv1.ExplainFlowResponse) {
	runtime := &openngfwv1.ExplainRuntimeEvidence{Queried: true}
	var running *openngfwv1.Policy
	if s.Store != nil {
		var runningVersion uint64
		var err error
		running, runningVersion, err = runningPolicySnapshot(s.Store)
		if err != nil {
			runtime.Warnings = append(runtime.Warnings, "could not read running policy context for runtime evidence: "+err.Error())
		} else {
			runtime.RunningPolicyVersion = runningVersion
			runtime.PolicyContext = telemetryPolicyContext(s.Store, runningVersion)
		}
	}
	result, err := conntrack.List(ctx, s.CommandLookup, s.CommandRun, conntrack.Filter{
		Limit:    5,
		SrcIP:    req.GetSrcIp(),
		SrcPort:  req.GetSrcPort(),
		DestIP:   req.GetDestIp(),
		DestPort: req.GetDestPort(),
		Protocol: protocolForConntrack(req.GetProtocol()),
	})
	if err != nil {
		runtime.State = "unavailable"
		runtime.Detail = "live conntrack lookup failed: " + err.Error()
		runtime.Warnings = append(runtime.Warnings, runtime.Detail)
		s.attachEveCorrelation(req, runtime, running)
		s.attachCaptureCorrelation(req, runtime)
		resp.RuntimeEvidence = runtime
		resp.Warnings = append(resp.Warnings, runtime.Detail)
		return
	}
	runtime.State = result.State
	runtime.Detail = result.Detail
	for _, session := range result.Sessions {
		runtime.Sessions = append(runtime.Sessions, conntrackSessionProto(session))
	}
	if len(runtime.Sessions) > 0 {
		runtime.Evidence = append(runtime.Evidence, fmt.Sprintf("live conntrack returned %d matching session(s) for the requested tuple", len(runtime.Sessions)))
	} else if result.State == "ready" {
		runtime.Evidence = append(runtime.Evidence, "live conntrack was queried but no matching session is currently active")
	} else if result.Detail != "" {
		runtime.Warnings = append(runtime.Warnings, result.Detail)
		resp.Warnings = append(resp.Warnings, result.Detail)
	}
	s.attachEveCorrelation(req, runtime, running)
	s.attachCaptureCorrelation(req, runtime)
	resp.RuntimeEvidence = runtime
}

func (s *ExplainServer) attachEveCorrelation(req *openngfwv1.ExplainFlowRequest, runtime *openngfwv1.ExplainRuntimeEvidence, running *openngfwv1.Policy) {
	flowID := strings.TrimSpace(req.GetFlowId())
	if flowID == "" {
		return
	}
	appDefs := appDefinitionsFromPolicy(running)
	flows, err := telemetry.ReadFlowsFilteredWithAppDefinitions(s.EvePath, telemetry.FlowFilter{
		Limit:  5,
		FlowID: flowID,
	}, appDefs)
	if err != nil {
		runtime.Warnings = append(runtime.Warnings, "could not read EVE flow correlation: "+err.Error())
	}
	for _, flow := range flows {
		runtime.CorrelatedFlows = append(runtime.CorrelatedFlows, flowProto(flow))
	}
	alerts, err := telemetry.ReadAlertsFiltered(s.EvePath, telemetry.AlertFilter{
		Limit:  5,
		FlowID: flowID,
	})
	if err != nil {
		runtime.Warnings = append(runtime.Warnings, "could not read EVE alert correlation: "+err.Error())
	}
	for _, alert := range alerts {
		runtime.CorrelatedAlerts = append(runtime.CorrelatedAlerts, alertProto(alert))
	}
	if len(runtime.GetCorrelatedFlows()) == 0 && len(runtime.GetCorrelatedAlerts()) == 0 {
		runtime.Evidence = append(runtime.Evidence, fmt.Sprintf("EVE correlation found no flow or alert events for flow_id=%s", flowID))
		return
	}
	runtime.Evidence = append(runtime.Evidence, fmt.Sprintf("EVE correlation returned %d flow event(s) and %d alert event(s) for flow_id=%s", len(runtime.GetCorrelatedFlows()), len(runtime.GetCorrelatedAlerts()), flowID))
}

func (s *ExplainServer) attachCaptureCorrelation(req *openngfwv1.ExplainFlowRequest, runtime *openngfwv1.ExplainRuntimeEvidence) {
	flowID := strings.TrimSpace(req.GetFlowId())
	if flowID == "" || strings.TrimSpace(s.CaptureDir) == "" {
		return
	}
	resp, err := listPacketCapturesFromDir(s.CaptureDir, &openngfwv1.ListPacketCapturesRequest{
		Limit:  3,
		FlowId: flowID,
	})
	if err != nil {
		runtime.Warnings = append(runtime.Warnings, "could not read packet capture correlation: "+err.Error())
		return
	}
	runtime.CorrelatedCaptures = append(runtime.CorrelatedCaptures, resp.GetCaptures()...)
	if len(runtime.GetCorrelatedCaptures()) == 0 {
		runtime.Evidence = append(runtime.Evidence, fmt.Sprintf("packet capture correlation found no artifacts for flow_id=%s", flowID))
		return
	}
	runtime.Evidence = append(runtime.Evidence, fmt.Sprintf("packet capture correlation returned %d artifact(s) for flow_id=%s", len(runtime.GetCorrelatedCaptures()), flowID))
}

func conntrackSessionProto(session conntrack.Session) *openngfwv1.ConntrackSession {
	return &openngfwv1.ConntrackSession{
		Family:         session.Family,
		Protocol:       session.Protocol,
		State:          session.State,
		TimeoutSeconds: session.TimeoutSeconds,
		SrcIp:          session.SrcIP,
		SrcPort:        session.SrcPort,
		DestIp:         session.DestIP,
		DestPort:       session.DestPort,
		ReplySrcIp:     session.ReplySrcIP,
		ReplySrcPort:   session.ReplySrcPort,
		ReplyDestIp:    session.ReplyDestIP,
		ReplyDestPort:  session.ReplyDestPort,
		Packets:        session.Packets,
		Bytes:          session.Bytes,
		Assured:        session.Assured,
		Raw:            session.Raw,
	}
}

func protocolForConntrack(proto openngfwv1.Protocol) string {
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

func (s *ExplainServer) policyFor(req *openngfwv1.ExplainFlowRequest) (*openngfwv1.Policy, uint64, error) {
	switch req.GetPolicySource() {
	case openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE:
		p, ok, err := s.Store.GetCandidate()
		if err != nil {
			return nil, 0, status.Errorf(codes.Internal, "read candidate: %v", err)
		}
		if !ok {
			return nil, 0, status.Error(codes.NotFound, "no candidate policy is set")
		}
		return p, 0, nil
	case openngfwv1.PolicySource_POLICY_SOURCE_VERSION:
		if req.GetVersion() == 0 {
			return nil, 0, status.Error(codes.InvalidArgument, "version is required when policy_source is POLICY_SOURCE_VERSION")
		}
		p, err := s.Store.GetVersion(req.GetVersion())
		if err != nil {
			return nil, 0, status.Errorf(codes.NotFound, "%v", err)
		}
		return p, req.GetVersion(), nil
	case openngfwv1.PolicySource_POLICY_SOURCE_UNSPECIFIED, openngfwv1.PolicySource_POLICY_SOURCE_RUNNING:
		p, ver, err := s.Store.GetRunning()
		if err != nil {
			return nil, 0, status.Errorf(codes.Internal, "read running policy: %v", err)
		}
		return p, ver, nil
	default:
		return nil, 0, status.Error(codes.InvalidArgument, fmt.Sprintf("unsupported policy_source %s", req.GetPolicySource()))
	}
}
