package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestRootCommandIncludesComplianceReports(t *testing.T) {
	root := NewRootCommand()
	for _, args := range [][]string{
		{"compliance", "reports", "list"},
		{"compliance", "reports", "get", "report-20260622T120000Z-abcdef12"},
		{"compliance", "reports", "create"},
		{"compliance", "reports", "export", "report-20260622T120000Z-abcdef12"},
	} {
		cmd, _, err := root.Find(args)
		if err != nil {
			t.Fatalf("find %v: %v", args, err)
		}
		if cmd == nil {
			t.Fatalf("command missing for %v", args)
		}
	}
}

func TestRunComplianceReportsListPrintsSummaries(t *testing.T) {
	client := &fakeComplianceReportsClient{listResp: &openngfwv1.ListComplianceReportsResponse{
		SchemaVersion: "phragma.compliance.report-api.v1",
		Reports: []*openngfwv1.ComplianceReportSummary{{
			Id:                  "report-20260622T120000Z-abcdef12",
			GeneratedAt:         timestamppb.New(mustComplianceTime(t, "2026-06-22T12:00:00Z")),
			GeneratedBy:         "alice",
			GeneratedByRole:     "operator",
			Profile:             "change-control",
			Title:               "CAB report",
			Unsigned:            true,
			ServerStored:        true,
			AuditEntryCount:     12,
			VersionCount:        3,
			SystemLogEntryCount: 7,
			PayloadSha256:       strings.Repeat("a", 64),
			ExportPath:          "/v1/compliance/reports/report-20260622T120000Z-abcdef12/export",
		}},
	}}
	out, err := runComplianceReportsListForTest(client, 5, false)
	if err != nil {
		t.Fatalf("runComplianceReportsList returned error: %v", err)
	}
	if client.listReq == nil || client.listReq.GetLimit() != 5 {
		t.Fatalf("list request = %#v", client.listReq)
	}
	for _, want := range []string{
		"compliance reports",
		"report-20260622T120000Z-abcdef12",
		"profile=change-control",
		"by=alice",
		"role=operator",
		"unsigned=true",
		"audit=12 versions=3 logs=7",
		"custody: unsigned report",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestRunComplianceReportsCreateMapsFiltersAndPrintsJSON(t *testing.T) {
	client := &fakeComplianceReportsClient{createResp: &openngfwv1.CreateComplianceReportResponse{
		SchemaVersion: "phragma.compliance.report-api.v1",
		Report: &openngfwv1.ComplianceReportSummary{
			Id:              "report-20260622T120000Z-abcdef12",
			Profile:         "privileged-access",
			GeneratedAt:     timestamppb.New(mustComplianceTime(t, "2026-06-22T12:00:00Z")),
			Unsigned:        true,
			ServerStored:    true,
			PayloadSha256:   strings.Repeat("b", 64),
			AuditEntryCount: 1,
		},
	}}
	out, err := runComplianceReportsCreateForTest(client, complianceReportCreateOptions{
		profile:      "privileged-access",
		title:        "admin report",
		auditLimit:   50,
		versionLimit: 10,
		logLimit:     25,
		actor:        "alice",
		action:       "commit",
		version:      9,
		since:        "2026-06-22T11:00:00Z",
		until:        "2026-06-22T13:00:00Z",
		query:        "change",
		outJSON:      true,
	})
	if err != nil {
		t.Fatalf("runComplianceReportsCreate returned error: %v", err)
	}
	req := client.createReq
	if req == nil || req.GetProfile() != "privileged-access" || req.GetTitle() != "admin report" ||
		req.GetAuditLimit() != 50 || req.GetVersionLimit() != 10 || req.GetLogLimit() != 25 ||
		req.GetActor() != "alice" || req.GetAction() != "commit" || req.GetVersion() != 9 ||
		req.GetSince() == nil || req.GetUntil() == nil || req.GetQuery() != "change" {
		t.Fatalf("create request = %#v", req)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("json output did not parse: %v\n%s", err, out)
	}
	if payload["schema_version"] != "phragma.compliance.report-api.v1" {
		t.Fatalf("json output missing schema: %#v", payload)
	}
}

func TestRunComplianceReportsExportWritesPayload(t *testing.T) {
	client := &fakeComplianceReportsClient{exportResp: &openngfwv1.ExportComplianceReportResponse{
		SchemaVersion: "phragma.compliance.report-api.v1",
		Filename:      "report-20260622T120000Z-abcdef12.json",
		ContentType:   "application/json",
		Payload:       []byte("{\"schemaVersion\":\"phragma.compliance.report-record.v1\"}\n"),
		Report: &openngfwv1.ComplianceReportSummary{
			Id:            "report-20260622T120000Z-abcdef12",
			PayloadSha256: strings.Repeat("c", 64),
		},
	}}
	output := filepath.Join(t.TempDir(), "report.json")
	out, err := runComplianceReportsExportForTest(client, "report-20260622T120000Z-abcdef12", output)
	if err != nil {
		t.Fatalf("runComplianceReportsExport returned error: %v", err)
	}
	if client.exportReq == nil || client.exportReq.GetId() != "report-20260622T120000Z-abcdef12" {
		t.Fatalf("export request = %#v", client.exportReq)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read export output: %v", err)
	}
	if !strings.Contains(string(raw), "phragma.compliance.report-record.v1") {
		t.Fatalf("unexpected export payload: %s", raw)
	}
	if !strings.Contains(out, "wrote ") || !strings.Contains(out, "sha256=cccccccc") {
		t.Fatalf("unexpected export output:\n%s", out)
	}
}

func runComplianceReportsListForTest(client complianceReportsClient, limit uint32, outJSON bool) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runComplianceReportsList(context.Background(), cmd, client, limit, outJSON)
	return out.String(), err
}

func runComplianceReportsCreateForTest(client complianceReportsClient, opts complianceReportCreateOptions) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runComplianceReportsCreate(context.Background(), cmd, client, opts)
	return out.String(), err
}

func runComplianceReportsExportForTest(client complianceReportsClient, id, output string) (string, error) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := runComplianceReportsExport(context.Background(), cmd, client, id, output)
	return out.String(), err
}

type fakeComplianceReportsClient struct {
	listReq    *openngfwv1.ListComplianceReportsRequest
	listResp   *openngfwv1.ListComplianceReportsResponse
	getReq     *openngfwv1.GetComplianceReportRequest
	getResp    *openngfwv1.GetComplianceReportResponse
	createReq  *openngfwv1.CreateComplianceReportRequest
	createResp *openngfwv1.CreateComplianceReportResponse
	exportReq  *openngfwv1.ExportComplianceReportRequest
	exportResp *openngfwv1.ExportComplianceReportResponse
}

func (f *fakeComplianceReportsClient) ListComplianceReports(_ context.Context, req *openngfwv1.ListComplianceReportsRequest, _ ...grpc.CallOption) (*openngfwv1.ListComplianceReportsResponse, error) {
	f.listReq = req
	if f.listResp != nil {
		return f.listResp, nil
	}
	return &openngfwv1.ListComplianceReportsResponse{}, nil
}

func (f *fakeComplianceReportsClient) GetComplianceReport(_ context.Context, req *openngfwv1.GetComplianceReportRequest, _ ...grpc.CallOption) (*openngfwv1.GetComplianceReportResponse, error) {
	f.getReq = req
	if f.getResp != nil {
		return f.getResp, nil
	}
	return &openngfwv1.GetComplianceReportResponse{}, nil
}

func (f *fakeComplianceReportsClient) CreateComplianceReport(_ context.Context, req *openngfwv1.CreateComplianceReportRequest, _ ...grpc.CallOption) (*openngfwv1.CreateComplianceReportResponse, error) {
	f.createReq = req
	if f.createResp != nil {
		return f.createResp, nil
	}
	return &openngfwv1.CreateComplianceReportResponse{}, nil
}

func (f *fakeComplianceReportsClient) ExportComplianceReport(_ context.Context, req *openngfwv1.ExportComplianceReportRequest, _ ...grpc.CallOption) (*openngfwv1.ExportComplianceReportResponse, error) {
	f.exportReq = req
	if f.exportResp != nil {
		return f.exportResp, nil
	}
	return &openngfwv1.ExportComplianceReportResponse{}, nil
}

func mustComplianceTime(t *testing.T, value string) time.Time {
	t.Helper()
	out, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return out
}
