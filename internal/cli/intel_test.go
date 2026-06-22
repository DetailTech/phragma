package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func TestRunIntelContentPrintsPackagePosture(t *testing.T) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	client := fakeIntelContentClient{resp: &openngfwv1.ListContentPackagesResponse{
		Packages: []*openngfwv1.ContentPackageInfo{{
			Kind:              "app-id",
			Name:              "Phragma App-ID catalog",
			State:             "local-only",
			SignatureStatus:   "missing",
			RegressionStatus:  "missing",
			RolloutState:      "",
			RollbackAvailable: false,
			ManifestPath:      "/var/lib/openngfw/content/app-id/manifest.json",
			Blockers:          []string{"signed manifest", "package version/hash"},
			ContentReadiness: &openngfwv1.ContentReadinessInfo{
				Scope:                      "demo-only",
				ProductionContent:          false,
				ProductionReady:            false,
				EvidenceStatus:             "demo-only",
				ReadinessLabel:             "demo-only",
				ReadinessDetail:            "This package is verified for demo or lab use only and is not approved for verdict-changing production content.",
				RequiredProductionEvidence: []string{"app-taxonomy", "app-regression-corpus"},
				Evidence: []*openngfwv1.ContentEvidenceRef{{
					Type:     "app-taxonomy",
					Artifact: "evidence/app-taxonomy.json",
					Sha256:   strings.Repeat("a", 64),
				}},
			},
			Provenance: []*openngfwv1.ContentProvenance{{
				Name:    "Phragma lab",
				License: "Apache-2.0",
			}},
		}},
	}}

	if err := runIntelContent(context.Background(), cmd, client); err != nil {
		t.Fatalf("runIntelContent: %v", err)
	}
	text := out.String()
	for _, want := range []string{
		"app-id",
		"local-only",
		"signature=missing",
		"regression=missing",
		"rollback-backup=no",
		"name: Phragma App-ID catalog",
		"content-readiness: demo-only scope=demo-only production-content=false production-ready=false",
		"production-evidence-inventory: demo required=2 attached=1",
		"readiness-detail: This package is verified for demo or lab use only",
		"required-evidence: 1/2 attached missing=app-regression-corpus",
		"evidence: app-taxonomy artifact=evidence/app-taxonomy.json sha256=sha256:aaaaaaaaaaaa",
		"next-action: ngfwctl intel content",
		"next-action: ngfwctl intel content preview app-id --source <data-dir>/content-import/app-id",
		"next-action: ngfwctl intel content install app-id --source <data-dir>/content-import/app-id",
		"blockers: signed manifest, package version/hash",
		"provenance: Phragma lab (Apache-2.0)",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in output:\n%s", want, text)
		}
	}
	if strings.Contains(text, "/var/lib/openngfw") || strings.Contains(text, "manifest:") {
		t.Fatalf("viewer package output leaked manifest path:\n%s", text)
	}
}

func TestRunIntelContentPreviewPrintsPackagePosture(t *testing.T) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	client := &fakeIntelContentPreviewClient{resp: &openngfwv1.PreviewContentPackageResponse{
		Package: &openngfwv1.ContentPackageInfo{
			Kind:              "app-id",
			Name:              "Phragma App-ID catalog",
			State:             "verified",
			Version:           "2.1.0",
			SignatureStatus:   "verified",
			RegressionStatus:  "passed",
			RolloutState:      "stable",
			RollbackAvailable: true,
			ManifestPath:      "/var/lib/openngfw/content-import/app-id/manifest.json",
			ManifestSha256:    strings.Repeat("a", 64),
		},
		Detail: "app-id package source verified for audited install",
	}}

	if err := runIntelContentPreview(context.Background(), cmd, client, "app-id", "app-preview"); err != nil {
		t.Fatalf("runIntelContentPreview: %v", err)
	}
	if client.req.GetKind() != "app-id" || client.req.GetSourcePath() != "app-preview" {
		t.Fatalf("request = %#v", client.req)
	}
	text := out.String()
	for _, want := range []string{
		"app-id package source verified for audited install",
		"app-id",
		"verified",
		"version=2.1.0",
		"manifest-sha256: " + strings.Repeat("a", 64),
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in output:\n%s", want, text)
		}
	}
	if strings.Contains(text, "/var/lib/openngfw") || strings.Contains(text, "manifest:") {
		t.Fatalf("preview output leaked manifest path:\n%s", text)
	}
}

func TestRunIntelContentCorpusPrintsRows(t *testing.T) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	client := &fakeIntelContentCorpusClient{resp: &openngfwv1.GetContentCorpusResponse{
		Kind:           "app-id",
		EvidenceType:   "app-regression-corpus",
		PackageVersion: "2.4.1",
		ManifestSha256: strings.Repeat("c", 64),
		Status:         "passed",
		SampleCount:    2,
		FailedSamples:  1,
		Verdicts:       []string{"failed", "passed"},
		Summary:        "2 samples loaded; 1 failing sample reported.",
		Samples: []*openngfwv1.ContentCorpusSample{{
			Id:         "corp-admin",
			PcapSha256: strings.Repeat("a", 64),
			Expected:   "corp-admin",
			Observed:   "corp-admin",
			Verdict:    "passed",
		}, {
			Id:         "corp-ssh",
			PcapSha256: strings.Repeat("b", 64),
			Expected:   "ssh",
			Observed:   "unknown",
			Verdict:    "failed",
			Detail:     "classification drift",
		}},
	}}

	if err := runIntelContentCorpus(context.Background(), cmd, client, "app-id", "", "ssh", "failed", 50); err != nil {
		t.Fatalf("runIntelContentCorpus: %v", err)
	}
	if client.req.GetKind() != "app-id" || client.req.GetQuery() != "ssh" || client.req.GetVerdict() != "failed" || client.req.GetLimit() != 50 {
		t.Fatalf("request = %#v", client.req)
	}
	text := out.String()
	for _, want := range []string{
		"app-id corpus app-regression-corpus package=2.4.1 samples=2 failed=1 status=passed",
		"summary: 2 samples loaded",
		"verdicts: failed, passed",
		"corp-ssh",
		"classification drift",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in output:\n%s", want, text)
		}
	}
}

func TestRunIntelContentComparePrintsPackageAndCorpusDiff(t *testing.T) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	client := &fakeIntelContentCompareClient{resp: &openngfwv1.CompareContentPackageResponse{
		CurrentPackage: &openngfwv1.ContentPackageInfo{Kind: "app-id", State: "verified", Version: "1.0.0", SignatureStatus: "verified", RegressionStatus: "passed"},
		PreviewPackage: &openngfwv1.ContentPackageInfo{Kind: "app-id", State: "verified", Version: "1.1.0", SignatureStatus: "verified", RegressionStatus: "passed"},
		Detail:         "app-id package source compared without promotion",
		CorpusDiff: &openngfwv1.ContentCorpusDiff{
			Kind:                  "app-id",
			EvidenceType:          "app-regression-corpus",
			CurrentPackageVersion: "1.0.0",
			PreviewPackageVersion: "1.1.0",
			CurrentSampleCount:    1,
			PreviewSampleCount:    2,
			Added:                 1,
			FailedDelta:           1,
			Summary:               "1 added, 0 removed, 0 changed; failed sample delta +1.",
			SampleDiffs: []*openngfwv1.ContentCorpusSampleDiff{{
				Id:      "corp-ssh",
				Change:  "added",
				Preview: &openngfwv1.ContentCorpusSample{Expected: "ssh", Observed: "unknown"},
			}},
		},
	}}

	if err := runIntelContentCompare(context.Background(), cmd, client, "app-id", "candidate", ""); err != nil {
		t.Fatalf("runIntelContentCompare: %v", err)
	}
	if client.req.GetKind() != "app-id" || client.req.GetSourcePath() != "candidate" {
		t.Fatalf("request = %#v", client.req)
	}
	text := out.String()
	for _, want := range []string{
		"app-id package source compared without promotion",
		"installed:",
		"preview:",
		"corpus-diff app-regression-corpus current=1.0.0/1 samples preview=1.1.0/2 samples added=1 removed=0 changed=0 failed-delta=+1",
		"corp-ssh",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in output:\n%s", want, text)
		}
	}
}

func TestRunIntelContentInstallPrintsAction(t *testing.T) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	client := &fakeIntelContentInstallClient{resp: &openngfwv1.InstallContentPackageResponse{
		Package: &openngfwv1.ContentPackageInfo{
			Kind:              "app-id",
			State:             "verified",
			Version:           "2.0.0",
			SignatureStatus:   "verified",
			RegressionStatus:  "passed",
			RolloutState:      "stable",
			RollbackAvailable: true,
		},
		RollbackCreated: true,
		RollbackPath:    "/var/lib/openngfw/content/app-id/.rollback/backup",
		Detail:          "installed app-id content package 2.0.0",
	}}

	if err := runIntelContentInstall(context.Background(), cmd, client, "app-id", "/tmp/pkg"); err != nil {
		t.Fatalf("runIntelContentInstall: %v", err)
	}
	if client.req.GetKind() != "app-id" || client.req.GetSourcePath() != "/tmp/pkg" {
		t.Fatalf("request = %#v", client.req)
	}
	text := out.String()
	for _, want := range []string{
		"installed app-id content package 2.0.0",
		"rollback-backup: /var/lib/openngfw/content/app-id/.rollback/backup",
		"app-id",
		"verified",
		"version=2.0.0",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in output:\n%s", want, text)
		}
	}
}

func TestRunIntelContentRollbackPrintsAction(t *testing.T) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	client := &fakeIntelContentRollbackClient{resp: &openngfwv1.RollbackContentPackageResponse{
		Package: &openngfwv1.ContentPackageInfo{
			Kind:             "threat-id",
			State:            "verified",
			Version:          "1.0.0",
			SignatureStatus:  "verified",
			RegressionStatus: "passed",
			RolloutState:     "stable",
		},
		RestoredRollbackPath: "/var/lib/openngfw/content/threat-id/.rollback/restored",
		RollbackCreated:      true,
		RollbackPath:         "/var/lib/openngfw/content/threat-id/.rollback/pre-rollback",
		Detail:               "rolled back threat-id content package to 1.0.0",
	}}

	if err := runIntelContentRollback(context.Background(), cmd, client, "threat-id"); err != nil {
		t.Fatalf("runIntelContentRollback: %v", err)
	}
	if client.req.GetKind() != "threat-id" || !client.req.GetAckRollback() {
		t.Fatalf("request = %#v", client.req)
	}
	text := out.String()
	for _, want := range []string{
		"rolled back threat-id content package to 1.0.0",
		"rollback-restored: /var/lib/openngfw/content/threat-id/.rollback/restored",
		"rollback-backup: /var/lib/openngfw/content/threat-id/.rollback/pre-rollback",
		"threat-id",
		"verified",
		"version=1.0.0",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in output:\n%s", want, text)
		}
	}
}

func TestIntelContentRollbackRequiresAck(t *testing.T) {
	server := "127.0.0.1:1"
	cmd := newIntelContentRollbackCommand(&server)
	cmd.SetArgs([]string{"app-id"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--ack-rollback is required") {
		t.Fatalf("Execute error = %v, want ack requirement", err)
	}
}

func TestIntelContentPreviewHelpExplainsNonMutatingServerLocalReview(t *testing.T) {
	server := "127.0.0.1:1"
	cmd := newIntelContentPreviewCommand(&server)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("help Execute error = %v", err)
	}
	text := out.String()
	flat := compactWhitespace(text)
	for _, want := range []string{
		"preview KIND --source SERVER_DIR",
		"without promoting files or writing lifecycle audit entries",
		"firewall server under the configured content import directory",
		"does not upload files from a browser or operator workstation",
	} {
		if !strings.Contains(flat, want) {
			t.Fatalf("missing %q in help:\n%s", want, text)
		}
	}
}

func TestIntelContentInstallHelpExplainsServerLocalImportRoot(t *testing.T) {
	server := "127.0.0.1:1"
	cmd := newIntelContentInstallCommand(&server)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("help Execute error = %v", err)
	}
	text := out.String()
	flat := compactWhitespace(text)
	for _, want := range []string{
		"install KIND --source SERVER_DIR",
		"firewall server under the configured content import directory",
		"<data-dir>/content-import",
		"does not upload files from a browser or operator workstation",
		"server-local package directory under the configured content import directory",
	} {
		if !strings.Contains(flat, want) {
			t.Fatalf("missing %q in help:\n%s", want, text)
		}
	}
}

func TestIntelContentRollbackHelpExplainsLifecycleAction(t *testing.T) {
	server := "127.0.0.1:1"
	cmd := newIntelContentRollbackCommand(&server)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("help Execute error = %v", err)
	}
	text := out.String()
	flat := compactWhitespace(text)
	for _, want := range []string{
		"audited content lifecycle action",
		"separate from policy candidate",
		"acknowledge that an audited content lifecycle rollback will replace the installed package",
	} {
		if !strings.Contains(flat, want) {
			t.Fatalf("missing %q in help:\n%s", want, text)
		}
	}
}

func compactWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

type fakeIntelContentClient struct {
	resp *openngfwv1.ListContentPackagesResponse
	err  error
}

func (f fakeIntelContentClient) ListContentPackages(context.Context, *openngfwv1.ListContentPackagesRequest, ...grpc.CallOption) (*openngfwv1.ListContentPackagesResponse, error) {
	return f.resp, f.err
}

type fakeIntelContentPreviewClient struct {
	resp *openngfwv1.PreviewContentPackageResponse
	err  error
	req  *openngfwv1.PreviewContentPackageRequest
}

func (f *fakeIntelContentPreviewClient) PreviewContentPackage(_ context.Context, req *openngfwv1.PreviewContentPackageRequest, _ ...grpc.CallOption) (*openngfwv1.PreviewContentPackageResponse, error) {
	f.req = req
	return f.resp, f.err
}

type fakeIntelContentCorpusClient struct {
	resp *openngfwv1.GetContentCorpusResponse
	err  error
	req  *openngfwv1.GetContentCorpusRequest
}

func (f *fakeIntelContentCorpusClient) GetContentCorpus(_ context.Context, req *openngfwv1.GetContentCorpusRequest, _ ...grpc.CallOption) (*openngfwv1.GetContentCorpusResponse, error) {
	f.req = req
	return f.resp, f.err
}

type fakeIntelContentCompareClient struct {
	resp *openngfwv1.CompareContentPackageResponse
	err  error
	req  *openngfwv1.CompareContentPackageRequest
}

func (f *fakeIntelContentCompareClient) CompareContentPackage(_ context.Context, req *openngfwv1.CompareContentPackageRequest, _ ...grpc.CallOption) (*openngfwv1.CompareContentPackageResponse, error) {
	f.req = req
	return f.resp, f.err
}

type fakeIntelContentInstallClient struct {
	resp *openngfwv1.InstallContentPackageResponse
	err  error
	req  *openngfwv1.InstallContentPackageRequest
}

func (f *fakeIntelContentInstallClient) InstallContentPackage(_ context.Context, req *openngfwv1.InstallContentPackageRequest, _ ...grpc.CallOption) (*openngfwv1.InstallContentPackageResponse, error) {
	f.req = req
	return f.resp, f.err
}

type fakeIntelContentRollbackClient struct {
	resp *openngfwv1.RollbackContentPackageResponse
	err  error
	req  *openngfwv1.RollbackContentPackageRequest
}

func (f *fakeIntelContentRollbackClient) RollbackContentPackage(_ context.Context, req *openngfwv1.RollbackContentPackageRequest, _ ...grpc.CallOption) (*openngfwv1.RollbackContentPackageResponse, error) {
	f.req = req
	return f.resp, f.err
}
