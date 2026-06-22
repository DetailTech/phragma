package apiserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
	"github.com/detailtech/oss-ngfw/internal/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestComplianceReportsGRPCCreateListGetExport(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if err := st.AppendAudit(store.AuditEntry{
		Time:  time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC),
		Actor: "alice", Action: "commit", Detail: "committed candidate v7",
	}); err != nil {
		t.Fatal(err)
	}
	svc := &SystemService{Store: st, Status: SystemStatusConfig{LogDir: t.TempDir()}}

	createResp, err := svc.CreateComplianceReport(context.Background(), &openngfwv1.CreateComplianceReportRequest{
		Profile:    "change-control",
		Title:      "CAB window report",
		AuditLimit: 25,
		LogLimit:   10,
		Action:     "commit",
		Since:      timestamppb.New(time.Date(2026, 6, 22, 11, 0, 0, 0, time.UTC)),
		Until:      timestamppb.New(time.Date(2026, 6, 22, 13, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("CreateComplianceReport returned error: %v", err)
	}
	report := createResp.GetReport()
	if report.GetId() == "" || report.GetProfile() != "change-control" || report.GetTitle() != "CAB window report" ||
		!report.GetUnsigned() || report.GetSigned() || !report.GetServerStored() || report.GetRetentionEnforced() ||
		report.GetAuditEntryCount() == 0 || report.GetExportPath() == "" || report.GetPayloadSha256() == "" {
		t.Fatalf("report summary = %#v", report)
	}

	listResp, err := svc.ListComplianceReports(context.Background(), &openngfwv1.ListComplianceReportsRequest{Limit: 5})
	if err != nil {
		t.Fatalf("ListComplianceReports returned error: %v", err)
	}
	if len(listResp.GetReports()) != 1 || listResp.GetReports()[0].GetId() != report.GetId() {
		t.Fatalf("list reports = %#v", listResp.GetReports())
	}

	getResp, err := svc.GetComplianceReport(context.Background(), &openngfwv1.GetComplianceReportRequest{Id: report.GetId()})
	if err != nil {
		t.Fatalf("GetComplianceReport returned error: %v", err)
	}
	if getResp.GetReport().GetPayloadSha256() != report.GetPayloadSha256() {
		t.Fatalf("get report sha = %q, want %q", getResp.GetReport().GetPayloadSha256(), report.GetPayloadSha256())
	}

	exportResp, err := svc.ExportComplianceReport(context.Background(), &openngfwv1.ExportComplianceReportRequest{Id: report.GetId()})
	if err != nil {
		t.Fatalf("ExportComplianceReport returned error: %v", err)
	}
	if exportResp.GetFilename() != report.GetId()+".json" || exportResp.GetContentType() != "application/json" ||
		!strings.Contains(string(exportResp.GetPayload()), `"schemaVersion": "phragma.compliance.report-record.v1"`) ||
		!strings.Contains(string(exportResp.GetPayload()), `"signed": false`) {
		t.Fatalf("export response = filename:%q type:%q payload:%s", exportResp.GetFilename(), exportResp.GetContentType(), exportResp.GetPayload())
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/compliance/reports/"+report.GetId()+"/export", nil)
	httpResp := httptest.NewRecorder()
	svc.ComplianceReportHandler().ServeHTTP(httpResp, req)
	if httpResp.Code != http.StatusOK {
		t.Fatalf("HTTP export status = %d body=%s", httpResp.Code, httpResp.Body.String())
	}
	if got := httpResp.Header().Get("X-Phragma-Payload-Sha256"); got != report.GetPayloadSha256() {
		t.Fatalf("HTTP export payload sha header = %q, want %q", got, report.GetPayloadSha256())
	}
	if got := httpResp.Header().Get("ETag"); got != `"`+report.GetPayloadSha256()+`"` {
		t.Fatalf("HTTP export ETag = %q, want digest ETag", got)
	}
}

func TestComplianceReportsGRPCRejectsInvalidInputs(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	svc := &SystemService{Store: st, Status: SystemStatusConfig{LogDir: t.TempDir()}}

	_, err = svc.CreateComplianceReport(context.Background(), &openngfwv1.CreateComplianceReportRequest{
		Since: timestamppb.New(time.Date(2026, 6, 22, 13, 0, 0, 0, time.UTC)),
		Until: timestamppb.New(time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)),
	})
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err=%v)", got, err)
	}

	_, err = svc.GetComplianceReport(context.Background(), &openngfwv1.GetComplianceReportRequest{Id: "../secret"})
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("unsafe id code = %v, want InvalidArgument (err=%v)", got, err)
	}
	for _, id := range []string{
		"report-../../x",
		"report-20260622T120000Z-abcdef1",
		"report-20260622T120000Z-abcdef123",
		"report-20260622T120000Z-ABCDEF12",
		"report-20260622T120000Z-abc\n1234",
	} {
		_, err = svc.GetComplianceReport(context.Background(), &openngfwv1.GetComplianceReportRequest{Id: id})
		if got := status.Code(err); got != codes.InvalidArgument {
			t.Fatalf("malformed id %q code = %v, want InvalidArgument (err=%v)", id, got, err)
		}
	}
	_, err = svc.GetComplianceReport(context.Background(), &openngfwv1.GetComplianceReportRequest{Id: "report-20260622T120000Z-deadbeef"})
	if got := status.Code(err); got != codes.NotFound {
		t.Fatalf("missing id code = %v, want NotFound (err=%v)", got, err)
	}
}
