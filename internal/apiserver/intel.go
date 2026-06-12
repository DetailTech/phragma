package apiserver

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/intel"
	"github.com/detailtech/oss-ngfw/internal/store"
)

// IntelServer implements openngfw.v1.IntelService.
type IntelServer struct {
	openngfwv1.UnimplementedIntelServiceServer

	Store   *store.Store
	Updater *intel.Updater
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

// RefreshFeeds triggers an immediate fetch-and-program cycle.
func (s *IntelServer) RefreshFeeds(ctx context.Context, _ *openngfwv1.RefreshFeedsRequest) (*openngfwv1.RefreshFeedsResponse, error) {
	n, err := s.Updater.Refresh(ctx)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "refresh: %v", err)
	}
	_, at := s.Updater.Status()
	return &openngfwv1.RefreshFeedsResponse{Entries: uint32(n), RefreshedAt: timestamppb.New(at)}, nil
}
