package apiserver

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/contentpkg"
	"github.com/detailtech/oss-ngfw/internal/store"
	"github.com/detailtech/oss-ngfw/internal/telemetry"
	"github.com/detailtech/oss-ngfw/internal/threatid"
)

// AlertServer implements openngfw.v1.AlertService over the local EVE
// stream.
type AlertServer struct {
	openngfwv1.UnimplementedAlertServiceServer

	// EvePath is the Suricata EVE JSON file.
	EvePath string
	// Store supplies the running policy version used as response context.
	Store *store.Store
	// ContentDir contains installed content packages, including threat-id.
	ContentDir string
}

// ListAlerts returns recent IDS/IPS alerts, newest first.
func (s *AlertServer) ListAlerts(_ context.Context, req *openngfwv1.ListAlertsRequest) (*openngfwv1.ListAlertsResponse, error) {
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
	_, runningVersion, err := runningPolicySnapshot(s.Store)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read running policy context: %v", err)
	}
	threatMetadata := threatMetadataFromContentPackage(s.ContentDir)
	alerts, page, err := telemetry.ReadAlertsFilteredPageWithThreatMetadata(s.EvePath, telemetry.AlertFilter{
		Limit:          int(req.GetLimit()),
		Offset:         offset,
		SrcIP:          req.GetSrcIp(),
		DestIP:         req.GetDestIp(),
		IP:             req.GetIp(),
		Protocol:       req.GetProtocol(),
		Action:         req.GetAction(),
		Severity:       req.GetSeverity(),
		ThreatSeverity: req.GetThreatSeverity(),
		SignatureID:    req.GetSignatureId(),
		Port:           req.GetPort(),
		Since:          since,
		Until:          until,
		Query:          req.GetQuery(),
		FlowID:         req.GetFlowId(),
	}, threatMetadata)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read alerts: %v", err)
	}
	resp := &openngfwv1.ListAlertsResponse{
		RunningPolicyVersion: runningVersion,
		PolicyContext:        telemetryPolicyContext(s.Store, runningVersion),
		NextCursor:           page.NextCursor,
		HasMore:              page.HasMore,
		TotalMatches:         uint32(page.TotalMatches),
	}
	for _, a := range alerts {
		resp.Alerts = append(resp.Alerts, alertProto(a))
	}
	return resp, nil
}

func alertProto(a telemetry.Alert) *openngfwv1.Alert {
	return &openngfwv1.Alert{
		Time:               timestamppb.New(a.Timestamp),
		Signature:          a.Signature,
		SignatureId:        a.SignatureID,
		Severity:           uint32(a.Severity),
		Category:           a.Category,
		SrcIp:              a.SrcIP,
		SrcPort:            uint32(a.SrcPort),
		DestIp:             a.DestIP,
		DestPort:           uint32(a.DestPort),
		Protocol:           a.Proto,
		Action:             a.Action,
		ThreatId:           a.ThreatID,
		ThreatName:         a.ThreatName,
		ThreatCategory:     a.ThreatCategory,
		ThreatSeverity:     a.ThreatSeverity,
		ThreatConfidence:   a.ThreatConfidence,
		ThreatEvidence:     appendEventPolicyEvidence(a.ThreatEvidence, a.PolicyStamp, a.PolicyFreshness, a.PolicySource),
		PolicyVersion:      a.PolicyVersion,
		PolicyVersionKnown: a.PolicyVersion != 0,
		FlowId:             a.FlowID,
	}
}

func threatMetadataFromContentPackage(contentDir string) []threatid.PackageMetadata {
	if strings.TrimSpace(contentDir) == "" {
		return nil
	}
	taxonomy, err := contentpkg.ReadThreatIDTaxonomy(contentDir)
	if err != nil {
		return nil
	}
	return taxonomy.Metadata
}
