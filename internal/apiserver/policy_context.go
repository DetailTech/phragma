package apiserver

import (
	"fmt"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/store"
)

func runningPolicySnapshot(st *store.Store) (*openngfwv1.Policy, uint64, error) {
	if st == nil {
		return nil, 0, nil
	}
	return st.GetRunning()
}

func telemetryPolicyContext(st *store.Store, version uint64) string {
	if st == nil {
		return "running policy context unavailable: store not configured"
	}
	if version == 0 {
		return "no committed running policy; event policy versions are unknown unless telemetry is stamped"
	}
	return fmt.Sprintf("running policy v%d at query time; event policy versions are exact only when telemetry is stamped", version)
}
