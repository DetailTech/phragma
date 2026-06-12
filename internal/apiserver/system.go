// Package apiserver hosts the gRPC implementation of the canonical
// OpenNGFW API. The API is the contract: every client (CLI, UI, GitOps)
// goes through it.
package apiserver

import (
	"context"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/version"
)

// SystemService implements openngfw.v1.SystemService.
type SystemService struct {
	openngfwv1.UnimplementedSystemServiceServer
}

// GetVersion reports the running build's version metadata.
func (s *SystemService) GetVersion(_ context.Context, _ *openngfwv1.GetVersionRequest) (*openngfwv1.GetVersionResponse, error) {
	return &openngfwv1.GetVersionResponse{
		Version:   version.Version,
		Commit:    version.Commit,
		BuildDate: version.BuildDate,
	}, nil
}
