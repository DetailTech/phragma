package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/supportbundle"
	"github.com/detailtech/oss-ngfw/internal/version"
)

const supportBundleSchema = supportbundle.Schema
const supportBundleRedacted = supportbundle.Redacted

type supportBundleOptions struct {
	output       string
	outputDir    string
	versionLimit uint32
	auditLimit   uint32
	eventLimit   uint32
}

type supportBundle = supportbundle.Bundle
type supportBundleCollector = supportbundle.Collector
type supportBundleClient = supportbundle.Client
type supportBundleEndpoint = supportbundle.Endpoint
type supportBundleSummary = supportbundle.Summary
type supportBundleCollected = supportbundle.Collected

func newSupportBundleCommand(server *string) *cobra.Command {
	defaults := supportbundle.DefaultLimits()
	opts := supportBundleOptions{
		versionLimit: defaults.VersionLimit,
		auditLimit:   defaults.AuditLimit,
		eventLimit:   defaults.EventLimit,
	}
	cmd := &cobra.Command{
		Use:   "support-bundle",
		Short: "Export a read-only diagnostic support bundle",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			now := time.Now().UTC()
			bundle := collectSupportBundle(ctx, conn, now, opts)
			raw, err := json.MarshalIndent(bundle, "", "  ")
			if err != nil {
				return fmt.Errorf("encode support bundle: %w", err)
			}
			raw = append(raw, '\n')
			output, err := supportBundleOutputPath(now, opts)
			if err != nil {
				return err
			}
			if output == "-" {
				cmd.Print(string(raw))
				return nil
			}
			if outputDir := strings.TrimSpace(opts.outputDir); outputDir != "" {
				if err := os.MkdirAll(outputDir, 0o755); err != nil {
					return fmt.Errorf("create support bundle output directory %s: %w", outputDir, err)
				}
			}
			if err := os.WriteFile(output, raw, 0o600); err != nil {
				return fmt.Errorf("write support bundle %s: %w", output, err)
			}
			cmd.Printf("support bundle written to %s", output)
			if failed := len(bundle.Summary.FailedEndpoints); failed > 0 {
				cmd.Printf(" (%d endpoint error(s): %s)", failed, strings.Join(bundle.Summary.FailedEndpoints, ", "))
			}
			cmd.Println()
			return nil
		},
	}
	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "output file path (default: generated filename; use '-' for stdout)")
	cmd.Flags().StringVar(&opts.outputDir, "output-dir", "", "directory for generated phragma-support-...json filename")
	cmd.Flags().Uint32Var(&opts.versionLimit, "version-limit", opts.versionLimit, "number of policy versions to include")
	cmd.Flags().Uint32Var(&opts.auditLimit, "audit-limit", opts.auditLimit, "number of audit entries to include")
	cmd.Flags().Uint32Var(&opts.eventLimit, "event-limit", opts.eventLimit, "number of alerts, flows, and sessions to include")
	return cmd
}

func supportBundleOutputPath(now time.Time, opts supportBundleOptions) (string, error) {
	output := strings.TrimSpace(opts.output)
	outputDir := strings.TrimSpace(opts.outputDir)
	if output != "" && outputDir != "" {
		return "", fmt.Errorf("support-bundle accepts either --output or --output-dir, not both")
	}
	if output == "-" {
		return "-", nil
	}
	if output != "" {
		return output, nil
	}
	name := supportBundleFilename(now)
	if outputDir != "" {
		return filepath.Join(outputDir, name), nil
	}
	return name, nil
}

func collectSupportBundle(ctx context.Context, conn grpc.ClientConnInterface, now time.Time, opts supportBundleOptions) supportBundle {
	limits := supportbundle.Limits{
		VersionLimit: opts.versionLimit,
		AuditLimit:   opts.auditLimit,
		EventLimit:   opts.eventLimit,
	}
	client := supportbundle.Client{Name: "ngfwctl", Version: version.String()}
	system := openngfwv1.NewSystemServiceClient(conn)
	resp, err := system.GetSupportBundle(ctx, &openngfwv1.GetSupportBundleRequest{
		VersionLimit: limits.VersionLimit,
		AuditLimit:   limits.AuditLimit,
		EventLimit:   limits.EventLimit,
	})
	if err == nil {
		bundle, convertErr := supportbundle.FromProto(resp, client)
		if convertErr == nil {
			return bundle
		}
		return supportbundle.Build(now, supportbundle.Collector{Type: "cli", Name: "ngfwctl", Version: version.String()}, client, map[string]supportbundle.Endpoint{
			"supportBundle": {OK: false, Error: supportbundle.RedactString(convertErr.Error())},
		}, supportbundle.Collected{})
	}
	if err != nil && status.Code(err) != codes.Unimplemented {
		return supportbundle.Build(now, supportbundle.Collector{Type: "cli", Name: "ngfwctl", Version: version.String()}, client, map[string]supportbundle.Endpoint{
			"supportBundle": {OK: false, Error: supportbundle.EndpointError(err)},
		}, supportbundle.Collected{})
	}
	return supportbundle.CollectClient(ctx, conn, now, limits, supportbundle.Collector{Type: "cli", Name: "ngfwctl", Version: version.String()}, client)
}

func protoEndpoint(msg proto.Message, err error) supportBundleEndpoint {
	return supportbundle.ProtoEndpoint(msg, err)
}

func candidatePolicyEndpoint(resp *openngfwv1.GetPolicyResponse, err error) supportBundleEndpoint {
	return supportbundle.CandidatePolicyEndpoint(resp, err)
}

func runningPolicyEndpoint(resp *openngfwv1.GetPolicyResponse, err error) supportBundleEndpoint {
	return supportbundle.RunningPolicyEndpoint(resp, err)
}

func candidateValidationEndpoint(resp *openngfwv1.ValidateResponse, err error) supportBundleEndpoint {
	return supportbundle.CandidateValidationEndpoint(resp, err)
}

func redactSupportBundleRawJSON(raw []byte) json.RawMessage {
	return supportbundle.RedactRawJSON(raw)
}

func summarizeSupportBundle(endpoints map[string]supportBundleEndpoint, collected supportBundleCollected) supportBundleSummary {
	return supportbundle.Summarize(endpoints, collected)
}

func supportBundleFilename(now time.Time) string {
	return supportbundle.Filename(now)
}
