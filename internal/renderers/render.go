// Package renderers exposes the full render pipeline: policy → IR →
// one native config artifact per engine.
package renderers

import (
	"fmt"
	"path/filepath"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/compiler"
	"github.com/detailtech/oss-ngfw/internal/engines"
	"github.com/detailtech/oss-ngfw/internal/renderers/frr"
	"github.com/detailtech/oss-ngfw/internal/renderers/iproute"
	"github.com/detailtech/oss-ngfw/internal/renderers/netdev"
	"github.com/detailtech/oss-ngfw/internal/renderers/nftables"
	"github.com/detailtech/oss-ngfw/internal/renderers/proxy"
	"github.com/detailtech/oss-ngfw/internal/renderers/strongswan"
	"github.com/detailtech/oss-ngfw/internal/renderers/suricata"
	"github.com/detailtech/oss-ngfw/internal/renderers/vector"
	"github.com/detailtech/oss-ngfw/internal/renderers/wireguard"
)

// Options carries deployment-level paths the renderers embed in native
// configs. These are node configuration, not policy.
type Options struct {
	// SuricataRulesDir holds managed IDS rule files.
	SuricataRulesDir string
	// LogDir receives eve.json.
	LogDir string
	// VectorDataDir is Vector's disk-buffer directory.
	VectorDataDir string
	// InspectionWorkers is how many NFQUEUEs the inline IPS fans out
	// across (one Suricata worker each) for multi-core throughput.
	// Typically the host CPU count; 0 or 1 means a single queue.
	InspectionWorkers int
}

// DefaultOptions derives engine paths from controld's data/log dirs.
func DefaultOptions(dataDir, logDir string) Options {
	return Options{
		SuricataRulesDir: filepath.Join(dataDir, "suricata", "rules"),
		LogDir:           logDir,
		VectorDataDir:    filepath.Join(dataDir, "vector"),
	}
}

// EvePath returns the Suricata EVE JSON path for these options.
func (o Options) EvePath() string { return filepath.Join(o.LogDir, "eve.json") }

// Pipeline returns a render function bound to opts.
func Pipeline(opts Options) func(*openngfwv1.Policy) (map[string][]byte, error) {
	return func(p *openngfwv1.Policy) (map[string][]byte, error) {
		return RenderAll(p, opts)
	}
}

// RenderAll compiles p and renders every engine artifact, keyed by
// engine name.
func RenderAll(p *openngfwv1.Policy, opts Options) (map[string][]byte, error) {
	ir, err := compiler.Compile(p)
	if err != nil {
		return nil, err
	}
	// Resolve the inline-IPS queue fan-out from node config (the pure
	// renderers stay deterministic; this is where host facts enter).
	if ir.IDs != nil && ir.IDs.Prevent {
		workers := opts.InspectionWorkers
		if workers < 1 {
			workers = 1
		}
		ir.IDs.QueueCount = uint16(workers)
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

	suri, err := suricata.Render(ir, suricata.Options{RulesDir: opts.SuricataRulesDir, LogDir: opts.LogDir})
	if err != nil {
		return nil, fmt.Errorf("render suricata: %w", err)
	}
	out[engines.SuricataName] = suri

	vec, err := vector.Render(ir, vector.Options{EvePath: opts.EvePath(), DataDir: opts.VectorDataDir})
	if err != nil {
		return nil, fmt.Errorf("render vector: %w", err)
	}
	out[engines.VectorName] = vec

	frrConf, err := frr.Render(ir)
	if err != nil {
		return nil, fmt.Errorf("render frr: %w", err)
	}
	out[engines.FRRName] = frrConf

	swan, err := strongswan.Render(ir)
	if err != nil {
		return nil, fmt.Errorf("render strongswan: %w", err)
	}
	out[engines.StrongswanName] = swan

	wg, err := wireguard.Render(ir)
	if err != nil {
		return nil, fmt.Errorf("render wireguard: %w", err)
	}
	out[engines.WireguardName] = wg

	nd, err := netdev.Render(ir)
	if err != nil {
		return nil, fmt.Errorf("render netdev: %w", err)
	}
	out[engines.NetdevName] = nd

	proxyPlan, err := proxy.Render(ir)
	if err != nil {
		return nil, fmt.Errorf("render proxy plan: %w", err)
	}
	if ir.Proxy != nil {
		out["proxy"] = proxyPlan
	}

	return out, nil
}
