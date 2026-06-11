// Package renderers exposes the full render pipeline: policy → IR →
// one native config artifact per engine.
package renderers

import (
	"fmt"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/compiler"
	"github.com/detailtech/oss-ngfw/internal/engines"
	"github.com/detailtech/oss-ngfw/internal/renderers/iproute"
	"github.com/detailtech/oss-ngfw/internal/renderers/nftables"
)

// RenderAll compiles p and renders every engine artifact, keyed by
// engine name.
func RenderAll(p *openngfwv1.Policy) (map[string][]byte, error) {
	ir, err := compiler.Compile(p)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}

	nft, err := nftables.Render(ir)
	if err != nil {
		return nil, fmt.Errorf("render nftables: %w", err)
	}
	out[engines.NftablesName] = nft

	routes, err := iproute.Render(ir)
	if err != nil {
		return nil, fmt.Errorf("render routes: %w", err)
	}
	out[engines.RoutesName] = routes

	return out, nil
}
