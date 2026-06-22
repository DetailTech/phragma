package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

type complianceReportsClient interface {
	ListComplianceReports(context.Context, *openngfwv1.ListComplianceReportsRequest, ...grpc.CallOption) (*openngfwv1.ListComplianceReportsResponse, error)
	GetComplianceReport(context.Context, *openngfwv1.GetComplianceReportRequest, ...grpc.CallOption) (*openngfwv1.GetComplianceReportResponse, error)
	CreateComplianceReport(context.Context, *openngfwv1.CreateComplianceReportRequest, ...grpc.CallOption) (*openngfwv1.CreateComplianceReportResponse, error)
	ExportComplianceReport(context.Context, *openngfwv1.ExportComplianceReportRequest, ...grpc.CallOption) (*openngfwv1.ExportComplianceReportResponse, error)
}

type complianceReportCreateOptions struct {
	profile      string
	title        string
	auditLimit   uint32
	versionLimit uint32
	logLimit     uint32
	actor        string
	action       string
	version      uint64
	since        string
	until        string
	query        string
	outJSON      bool
}

func newComplianceCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compliance",
		Short: "Generate and export retained compliance reports",
	}
	cmd.AddCommand(newComplianceReportsCommand(server))
	return cmd
}

func newComplianceReportsCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reports",
		Short: "List, create, inspect, and export retained compliance reports",
	}
	cmd.AddCommand(
		newComplianceReportsListCommand(server),
		newComplianceReportsGetCommand(server),
		newComplianceReportsCreateCommand(server),
		newComplianceReportsExportCommand(server),
	)
	return cmd
}

func newComplianceReportsListCommand(server *string) *cobra.Command {
	var limit uint32
	var outJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List retained compliance report summaries",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runComplianceReportsList(ctx, cmd, openngfwv1.NewComplianceServiceClient(conn), limit, outJSON)
		},
	}
	cmd.Flags().Uint32Var(&limit, "limit", 0, "max reports (0 = server default)")
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

func newComplianceReportsGetCommand(server *string) *cobra.Command {
	var outJSON bool
	cmd := &cobra.Command{
		Use:   "get REPORT_ID",
		Short: "Show one retained compliance report summary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runComplianceReportsGet(ctx, cmd, openngfwv1.NewComplianceServiceClient(conn), args[0], outJSON)
		},
	}
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

func newComplianceReportsCreateCommand(server *string) *cobra.Command {
	opts := complianceReportCreateOptions{
		profile:      "operational",
		auditLimit:   300,
		versionLimit: 100,
		logLimit:     100,
	}
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Generate and retain a new unsigned compliance report",
		Long: "Generate one server-retained compliance report from bounded audit, version, and system-log state. " +
			"The report is intentionally unsigned until the production custody hardening pass.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runComplianceReportsCreate(ctx, cmd, openngfwv1.NewComplianceServiceClient(conn), opts)
		},
	}
	cmd.Flags().StringVar(&opts.profile, "profile", opts.profile, "report profile: operational|change-control|privileged-access|content-lifecycle|incident-evidence")
	cmd.Flags().StringVar(&opts.title, "title", "", "report title")
	cmd.Flags().Uint32Var(&opts.auditLimit, "audit-limit", opts.auditLimit, "max audit entries")
	cmd.Flags().Uint32Var(&opts.versionLimit, "version-limit", opts.versionLimit, "max versions")
	cmd.Flags().Uint32Var(&opts.logLimit, "log-limit", opts.logLimit, "max system log entries")
	cmd.Flags().StringVar(&opts.actor, "actor", "", "filter audit entries by actor")
	cmd.Flags().StringVar(&opts.action, "action", "", "filter audit entries by action")
	cmd.Flags().Uint64Var(&opts.version, "version", 0, "filter audit entries by running version")
	cmd.Flags().StringVar(&opts.since, "since", "", "include audit/log entries at or after RFC3339, YYYY-MM-DD, or 'YYYY-MM-DD HH:MM:SS' UTC")
	cmd.Flags().StringVar(&opts.until, "until", "", "include audit/log entries at or before RFC3339, YYYY-MM-DD, or 'YYYY-MM-DD HH:MM:SS' UTC")
	cmd.Flags().StringVar(&opts.query, "query", "", "search audit detail text")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func newComplianceReportsExportCommand(server *string) *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "export REPORT_ID",
		Short: "Export one retained compliance report JSON artifact",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runComplianceReportsExport(ctx, cmd, openngfwv1.NewComplianceServiceClient(conn), args[0], output)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "write report JSON to path (default: stdout)")
	return cmd
}

func runComplianceReportsList(ctx context.Context, cmd *cobra.Command, client complianceReportsClient, limit uint32, outJSON bool) error {
	resp, err := client.ListComplianceReports(ctx, &openngfwv1.ListComplianceReportsRequest{Limit: limit})
	if err != nil {
		return err
	}
	if outJSON {
		return printProtoJSON(cmd, resp)
	}
	if len(resp.GetReports()) == 0 {
		cmd.Println("no compliance reports")
		return nil
	}
	cmd.Println("compliance reports")
	for _, report := range resp.GetReports() {
		printComplianceReportSummary(cmd, report)
	}
	return nil
}

func runComplianceReportsGet(ctx context.Context, cmd *cobra.Command, client complianceReportsClient, id string, outJSON bool) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("report id is required")
	}
	resp, err := client.GetComplianceReport(ctx, &openngfwv1.GetComplianceReportRequest{Id: id})
	if err != nil {
		return err
	}
	if outJSON {
		return printProtoJSON(cmd, resp)
	}
	printComplianceReportSummary(cmd, resp.GetReport())
	return nil
}

func runComplianceReportsCreate(ctx context.Context, cmd *cobra.Command, client complianceReportsClient, opts complianceReportCreateOptions) error {
	req := &openngfwv1.CreateComplianceReportRequest{
		Profile:      opts.profile,
		Title:        opts.title,
		AuditLimit:   opts.auditLimit,
		VersionLimit: opts.versionLimit,
		LogLimit:     opts.logLimit,
		Actor:        opts.actor,
		Action:       opts.action,
		Version:      opts.version,
		Query:        opts.query,
	}
	if opts.since != "" {
		ts, err := parseAuditTimeBound(opts.since, false)
		if err != nil {
			return fmt.Errorf("invalid --since: %w", err)
		}
		req.Since = timestamppb.New(ts)
	}
	if opts.until != "" {
		ts, err := parseAuditTimeBound(opts.until, true)
		if err != nil {
			return fmt.Errorf("invalid --until: %w", err)
		}
		req.Until = timestamppb.New(ts)
	}
	resp, err := client.CreateComplianceReport(ctx, req)
	if err != nil {
		return err
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	cmd.Println("created compliance report")
	printComplianceReportSummary(cmd, resp.GetReport())
	return nil
}

func runComplianceReportsExport(ctx context.Context, cmd *cobra.Command, client complianceReportsClient, id string, output string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("report id is required")
	}
	resp, err := client.ExportComplianceReport(ctx, &openngfwv1.ExportComplianceReportRequest{Id: id})
	if err != nil {
		return err
	}
	payload := resp.GetPayload()
	if len(payload) == 0 {
		return fmt.Errorf("report %q has empty payload", id)
	}
	output = strings.TrimSpace(output)
	if output == "" || output == "-" {
		_, err := cmd.OutOrStdout().Write(payload)
		return err
	}
	if err := os.WriteFile(output, payload, 0o600); err != nil {
		return fmt.Errorf("write compliance report to %s: %w", output, err)
	}
	cmd.Printf("wrote %s (%d bytes, sha256=%s)\n", output, len(payload), valueOrDash(resp.GetReport().GetPayloadSha256()))
	return nil
}

func printComplianceReportSummary(cmd *cobra.Command, report *openngfwv1.ComplianceReportSummary) {
	if report == nil {
		cmd.Println("report: <none>")
		return
	}
	generated := "-"
	if report.GetGeneratedAt() != nil {
		generated = report.GetGeneratedAt().AsTime().Format("2006-01-02 15:04:05")
	}
	cmd.Printf("%s  profile=%s generated=%s by=%s role=%s unsigned=%t stored=%t audit=%d versions=%d logs=%d sha256=%s export=%s\n",
		report.GetId(),
		valueOrDash(report.GetProfile()),
		generated,
		valueOrDash(report.GetGeneratedBy()),
		valueOrDash(report.GetGeneratedByRole()),
		report.GetUnsigned(),
		report.GetServerStored(),
		report.GetAuditEntryCount(),
		report.GetVersionCount(),
		report.GetSystemLogEntryCount(),
		valueOrDash(report.GetPayloadSha256()),
		valueOrDash(report.GetExportPath()),
	)
	if report.GetTitle() != "" {
		cmd.Printf("  title: %s\n", report.GetTitle())
	}
	if !report.GetSigned() || !report.GetRetentionEnforced() {
		cmd.Println("  custody: unsigned report; signing and retention enforcement remain hardening work")
	}
}
