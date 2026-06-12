package apiserver

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/telemetry"
)

// FlowServer implements openngfw.v1.FlowService over the EVE stream.
type FlowServer struct {
	openngfwv1.UnimplementedFlowServiceServer

	// EvePath is the Suricata EVE JSON file.
	EvePath string
}

// ListFlows returns recent flows with app/protocol labels, newest first.
func (s *FlowServer) ListFlows(_ context.Context, req *openngfwv1.ListFlowsRequest) (*openngfwv1.ListFlowsResponse, error) {
	flows, err := telemetry.ReadFlows(s.EvePath, int(req.GetLimit()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read flows: %v", err)
	}
	resp := &openngfwv1.ListFlowsResponse{}
	for _, f := range flows {
		resp.Flows = append(resp.Flows, &openngfwv1.Flow{
			Time:          timestamppb.New(f.Timestamp),
			SrcIp:         f.SrcIP,
			SrcPort:       uint32(f.SrcPort),
			DestIp:        f.DestIP,
			DestPort:      uint32(f.DestPort),
			Protocol:      f.Proto,
			AppProtocol:   f.AppProto,
			BytesToServer: f.BytesToServer,
			BytesToClient: f.BytesToClient,
			Packets:       f.Packets,
		})
	}
	return resp, nil
}
