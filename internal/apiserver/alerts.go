package apiserver

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/telemetry"
)

// AlertServer implements openngfw.v1.AlertService over the local EVE
// stream.
type AlertServer struct {
	openngfwv1.UnimplementedAlertServiceServer

	// EvePath is the Suricata EVE JSON file.
	EvePath string
}

// ListAlerts returns recent IDS/IPS alerts, newest first.
func (s *AlertServer) ListAlerts(_ context.Context, req *openngfwv1.ListAlertsRequest) (*openngfwv1.ListAlertsResponse, error) {
	alerts, err := telemetry.ReadAlerts(s.EvePath, int(req.GetLimit()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read alerts: %v", err)
	}
	resp := &openngfwv1.ListAlertsResponse{}
	for _, a := range alerts {
		resp.Alerts = append(resp.Alerts, &openngfwv1.Alert{
			Time:        timestamppb.New(a.Timestamp),
			Signature:   a.Signature,
			SignatureId: a.SignatureID,
			Severity:    uint32(a.Severity),
			Category:    a.Category,
			SrcIp:       a.SrcIP,
			SrcPort:     uint32(a.SrcPort),
			DestIp:      a.DestIP,
			DestPort:    uint32(a.DestPort),
			Protocol:    a.Proto,
			Action:      a.Action,
		})
	}
	return resp, nil
}
