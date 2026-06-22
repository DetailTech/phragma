package apiserver

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/appid"
	"github.com/detailtech/oss-ngfw/internal/conntrack"
	"github.com/detailtech/oss-ngfw/internal/store"
	"github.com/detailtech/oss-ngfw/internal/telemetry"
)

// FlowServer implements openngfw.v1.FlowService over the EVE stream.
type FlowServer struct {
	openngfwv1.UnimplementedFlowServiceServer

	// EvePath is the Suricata EVE JSON file.
	EvePath string
	// Store supplies the running policy's custom OpenNGFW App-ID definitions.
	Store *store.Store
	// ContentDir supplies verified App-ID package taxonomy definitions.
	ContentDir string
	// CommandLookup and CommandRun are injectable for conntrack session tests.
	CommandLookup func(string) (string, error)
	CommandRun    conntrack.Runner
}

// ListFlows returns recent flows with app/protocol labels, newest first.
func (s *FlowServer) ListFlows(_ context.Context, req *openngfwv1.ListFlowsRequest) (*openngfwv1.ListFlowsResponse, error) {
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
	appDefs, err := appDefinitionsForClassification(running, s.ContentDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read App-ID taxonomy: %v", err)
	}
	flows, page, err := telemetry.ReadFlowsFilteredPageWithAppDefinitions(s.EvePath, telemetry.FlowFilter{
		Limit:    int(req.GetLimit()),
		Offset:   offset,
		SrcIP:    req.GetSrcIp(),
		DestIP:   req.GetDestIp(),
		IP:       req.GetIp(),
		Protocol: req.GetProtocol(),
		App:      req.GetApp(),
		Port:     req.GetPort(),
		Since:    since,
		Until:    until,
		Query:    req.GetQuery(),
		FlowID:   req.GetFlowId(),
	}, appDefs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read flows: %v", err)
	}
	resp := &openngfwv1.ListFlowsResponse{
		RunningPolicyVersion: runningVersion,
		PolicyContext:        telemetryPolicyContext(s.Store, runningVersion),
		NextCursor:           page.NextCursor,
		HasMore:              page.HasMore,
		TotalMatches:         uint32(page.TotalMatches),
	}
	for _, f := range flows {
		resp.Flows = append(resp.Flows, flowProto(f))
	}
	return resp, nil
}

func flowProto(f telemetry.Flow) *openngfwv1.Flow {
	return &openngfwv1.Flow{
		Time:               timestamppb.New(f.Timestamp),
		SrcIp:              f.SrcIP,
		SrcPort:            uint32(f.SrcPort),
		DestIp:             f.DestIP,
		DestPort:           uint32(f.DestPort),
		Protocol:           f.Proto,
		AppProtocol:        f.AppProto,
		BytesToServer:      f.BytesToServer,
		BytesToClient:      f.BytesToClient,
		Packets:            f.Packets,
		AppId:              f.AppID,
		AppName:            f.AppName,
		AppCategory:        f.AppCategory,
		AppConfidence:      f.AppConfidence,
		AppEvidence:        appendEventPolicyEvidence(f.AppEvidence, f.PolicyStamp, f.PolicyFreshness, f.PolicySource),
		PolicyVersion:      f.PolicyVersion,
		PolicyVersionKnown: f.PolicyVersion != 0,
		FlowId:             f.FlowID,
	}
}

func appendEventPolicyEvidence(evidence []string, stamp, freshness, source string) []string {
	out := append([]string{}, evidence...)
	if stamp != "" {
		out = append(out, "event policy stamp: "+stamp)
	}
	if freshness != "" {
		out = append(out, "event policy freshness: "+freshness)
	}
	if source != "" {
		out = append(out, "event policy source: "+source)
	}
	return out
}

func appDefinitionsFromPolicy(p *openngfwv1.Policy) []appid.Definition {
	if p == nil {
		return nil
	}
	defs := make([]appid.Definition, 0, len(p.GetApplications()))
	for _, app := range p.GetApplications() {
		defs = append(defs, appid.Definition{
			ID:            app.GetName(),
			Name:          displayName(app),
			Category:      app.GetCategory(),
			EngineSignals: app.GetEngineSignals(),
			Ports:         appPortMatches(app),
		})
	}
	return defs
}

func displayName(app *openngfwv1.Application) string {
	if app.GetDisplayName() != "" {
		return app.GetDisplayName()
	}
	return app.GetName()
}

func appPortMatches(app *openngfwv1.Application) []appid.PortMatch {
	var out []appid.PortMatch
	for _, hint := range app.GetPorts() {
		proto := ""
		switch hint.GetProtocol() {
		case openngfwv1.Protocol_PROTOCOL_TCP:
			proto = "tcp"
		case openngfwv1.Protocol_PROTOCOL_UDP:
			proto = "udp"
		default:
			continue
		}
		for _, pr := range hint.GetPorts() {
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
			out = append(out, appid.PortMatch{Protocol: proto, Start: uint16(pr.GetStart()), End: uint16(end)})
		}
	}
	return out
}

// ListSessions returns live Linux conntrack sessions. It is intentionally
// separate from ListFlows: sessions are current kernel state, while flows are
// historical inspection telemetry with App-ID evidence.
func (s *FlowServer) ListSessions(ctx context.Context, req *openngfwv1.ListSessionsRequest) (*openngfwv1.ListSessionsResponse, error) {
	offset, err := pageOffset(req.GetPageCursor())
	if err != nil {
		return nil, err
	}
	result, err := conntrack.List(ctx, s.CommandLookup, s.CommandRun, conntrack.Filter{
		Limit:    int(req.GetLimit()),
		Offset:   offset,
		SrcIP:    req.GetSrcIp(),
		DestIP:   req.GetDestIp(),
		IP:       req.GetIp(),
		Protocol: req.GetProtocol(),
		Port:     req.GetPort(),
		State:    req.GetState(),
		Query:    req.GetQuery(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read sessions: %v", err)
	}
	resp := &openngfwv1.ListSessionsResponse{
		State:        result.State,
		Detail:       result.Detail,
		NextCursor:   result.NextCursor,
		HasMore:      result.HasMore,
		TotalMatches: result.TotalMatches,
	}
	_, runningVersion, err := runningPolicySnapshot(s.Store)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read running policy context: %v", err)
	}
	resp.RunningPolicyVersion = runningVersion
	resp.PolicyContext = telemetryPolicyContext(s.Store, runningVersion)
	for _, session := range result.Sessions {
		resp.Sessions = append(resp.Sessions, &openngfwv1.ConntrackSession{
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
		})
	}
	return resp, nil
}
