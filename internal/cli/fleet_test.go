package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

type fakeFleetHTTPClient struct {
	status int
	body   string
	err    error
	req    *http.Request
	raw    []byte
}

func (f *fakeFleetHTTPClient) Do(req *http.Request) (*http.Response, error) {
	f.req = req
	if req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		f.raw = raw
	}
	if f.err != nil {
		return nil, f.err
	}
	status := f.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Header:     make(http.Header),
	}, nil
}

func TestFleetGatewayURLDefaultsFromServerHost(t *testing.T) {
	got, err := fleetGatewayURL("10.0.0.5:9443", "")
	if err != nil {
		t.Fatalf("fleetGatewayURL returned error: %v", err)
	}
	if got != "http://10.0.0.5:8080" {
		t.Fatalf("gateway = %q", got)
	}
	got, err = fleetGatewayURL("[::1]:9443", "")
	if err != nil {
		t.Fatalf("fleetGatewayURL IPv6 returned error: %v", err)
	}
	if got != "http://[::1]:8080" {
		t.Fatalf("gateway IPv6 = %q", got)
	}
	if _, err := fleetGatewayURL("127.0.0.1:9443", "ftp://fw.example"); err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Fatalf("expected scheme error, got %v", err)
	}
}

func TestFleetTokenTransportRequiresHTTPSOrLoopback(t *testing.T) {
	if err := validateFleetTokenTransport("http://198.51.100.10:8080", "token"); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("expected refusal for remote HTTP token, got %v", err)
	}
	if err := validateFleetTokenTransport("http://127.0.0.1:8080", "token"); err != nil {
		t.Fatalf("loopback HTTP token rejected: %v", err)
	}
	if err := validateFleetTokenTransport("https://fw.example:8443", "token"); err != nil {
		t.Fatalf("HTTPS token rejected: %v", err)
	}
}

func TestFleetClientSendsJSONAndToken(t *testing.T) {
	fake := &fakeFleetHTTPClient{body: `{"ok":true}`}
	client := &fleetClient{baseURL: "http://127.0.0.1:8080", token: "secret", httpClient: fake}
	body, err := client.post(context.Background(), "/v1/fleet/templates/tmpl-a:apply-preview", map[string]any{"expectedCandidateRevision": "sha256:1"})
	if err != nil {
		t.Fatalf("post returned error: %v", err)
	}
	if body["ok"] != true {
		t.Fatalf("body = %#v", body)
	}
	if fake.req.Method != http.MethodPost || fake.req.URL.String() != "http://127.0.0.1:8080/v1/fleet/templates/tmpl-a:apply-preview" {
		t.Fatalf("request = %s %s", fake.req.Method, fake.req.URL.String())
	}
	if got := fake.req.Header.Get("Authorization"); got != "Bearer secret" {
		t.Fatalf("Authorization = %q", got)
	}
	if !bytes.Contains(fake.raw, []byte(`"expectedCandidateRevision":"sha256:1"`)) {
		t.Fatalf("request body = %s", string(fake.raw))
	}
}

func TestFleetClientReturnsAPIErrorDetails(t *testing.T) {
	client := &fleetClient{
		baseURL: "http://127.0.0.1:8080",
		httpClient: &fakeFleetHTTPClient{
			status: http.StatusPreconditionFailed,
			body:   `{"error":{"code":"CANDIDATE_REVISION_CONFLICT","message":"candidate changed"}}`,
		},
	}
	_, err := client.post(context.Background(), "/v1/fleet/templates/tmpl-a:stage-candidate", map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "CANDIDATE_REVISION_CONFLICT") {
		t.Fatalf("expected detailed API error, got %v", err)
	}
}

func TestFleetTemplateCreateRequestReadsYAMLAndCleansLabels(t *testing.T) {
	file := writeFleetPolicyFile(t, "zones:\n- name: lan\nrules:\n- name: allow\n  action: ACTION_ALLOW\n")
	req, err := fleetTemplateCreateRequest(fleetTemplateCreateOptions{
		name:        " Branch Edge ",
		description: " branch template ",
		scope:       " local-appliance ",
		labels:      []string{"branch,edge", "edge"},
		policyFile:  file,
	})
	if err != nil {
		t.Fatalf("fleetTemplateCreateRequest returned error: %v", err)
	}
	if req["name"] != "Branch Edge" || req["scope"] != "local-appliance" {
		t.Fatalf("request = %#v", req)
	}
	labels := req["labels"].([]string)
	if strings.Join(labels, ",") != "branch,edge" {
		t.Fatalf("labels = %#v", labels)
	}
	policy := req["policy"].(map[string]any)
	if _, ok := policy["zones"]; !ok {
		t.Fatalf("policy missing zones: %#v", policy)
	}
}

func TestFleetStageCandidateRequiresRevisionAndComment(t *testing.T) {
	cmd, _ := fleetCommandForTest()
	client := &fleetClient{baseURL: "http://127.0.0.1:8080", httpClient: &fakeFleetHTTPClient{body: `{}`}}
	if err := runFleetTemplatesStageCandidate(context.Background(), cmd, client, "tmpl-a", fleetCommandOptions{comment: "stage"}); err == nil || !strings.Contains(err.Error(), "--expected-candidate-revision") {
		t.Fatalf("expected revision error, got %v", err)
	}
	if err := runFleetTemplatesStageCandidate(context.Background(), cmd, client, "tmpl-a", fleetCommandOptions{expectedRevision: "sha256:1"}); err == nil || !strings.Contains(err.Error(), "--message") {
		t.Fatalf("expected message error, got %v", err)
	}
}

func TestFleetStageCandidatePostsRevisionGuardAndPrintsNextStep(t *testing.T) {
	fake := &fakeFleetHTTPClient{body: `{
		"template":{"id":"tmpl-branch","name":"Branch","revision":"sha256:t"},
		"validation":{"valid":true},
		"previousCandidateRevision":"sha256:old",
		"candidateRevision":"sha256:new",
		"impact":{"risk":"CHANGE_RISK_LOW"},
		"applyPath":"candidate staged locally",
		"orchestrationBoundary":"local candidate stage only"
	}`}
	client := &fleetClient{baseURL: "http://127.0.0.1:8080", httpClient: fake}
	cmd, stdout := fleetCommandForTest()
	err := runFleetTemplatesStageCandidate(context.Background(), cmd, client, "tmpl-branch", fleetCommandOptions{
		expectedRevision: "sha256:old",
		comment:          "stage branch",
	})
	if err != nil {
		t.Fatalf("runFleetTemplatesStageCandidate returned error: %v", err)
	}
	var req map[string]any
	if err := json.Unmarshal(fake.raw, &req); err != nil {
		t.Fatalf("request JSON: %v", err)
	}
	if req["expectedCandidateRevision"] != "sha256:old" || req["comment"] != "stage branch" {
		t.Fatalf("request = %#v", req)
	}
	out := stdout.String()
	for _, want := range []string{"fleet template staged as candidate", "candidate:       sha256:new", "boundary:        local candidate stage only", "ngfwctl policy validate"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q:\n%s", want, out)
		}
	}
}

func TestFleetApplyPlanPostsPeerInventoryAndPrintsNodePlan(t *testing.T) {
	fake := &fakeFleetHTTPClient{body: `{
		"template":{"id":"tmpl-branch","name":"Branch","revision":"sha256:t"},
		"validation":{"valid":true},
		"candidateRevision":"sha256:candidate",
		"result":"previewable",
		"nodeCount":2,
		"eligibleNodeCount":1,
		"nodes":[
			{"id":"local","name":"local appliance","status":"blocked","plannedAction":"hold; collect readiness evidence","blockers":["runtime readiness needs positive evidence"]},
			{"id":"fw-peer","name":"fw-peer","status":"eligible","plannedAction":"handoff candidate apply through node-local workflow","blockers":[]}
		],
		"orchestrationBoundary":"multi-node apply plan only; no peer RPC"
	}`}
	client := &fleetClient{baseURL: "http://127.0.0.1:8080", httpClient: fake}
	cmd, stdout := fleetCommandForTest()
	err := runFleetTemplatesApplyPlan(context.Background(), cmd, client, "tmpl-branch", fleetCommandOptions{
		expectedRevision: "sha256:candidate",
		peers:            []string{"id=fw-peer,name=fw-peer,role=passive,runtime=ready,running=17,haReady=true"},
	})
	if err != nil {
		t.Fatalf("runFleetTemplatesApplyPlan returned error: %v", err)
	}
	if fake.req.URL.String() != "http://127.0.0.1:8080/v1/fleet/templates/tmpl-branch:apply-plan" {
		t.Fatalf("request URL = %s", fake.req.URL.String())
	}
	var req map[string]any
	if err := json.Unmarshal(fake.raw, &req); err != nil {
		t.Fatalf("request JSON: %v", err)
	}
	if req["expectedCandidateRevision"] != "sha256:candidate" {
		t.Fatalf("request = %#v, missing revision", req)
	}
	nodes := req["nodes"].([]any)
	peer := nodes[0].(map[string]any)
	if peer["id"] != "fw-peer" || peer["runtimeState"] != "ready" || peer["runningVersion"] != "17" || peer["haReady"] != true {
		t.Fatalf("peer request = %#v", peer)
	}
	out := stdout.String()
	for _, want := range []string{"fleet template apply plan", "nodes:           1 eligible / 2 total", "fw-peer", "no peer RPC"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q:\n%s", want, out)
		}
	}
}

func TestFleetApplyPostsPeerInventoryAndPrintsResultCustody(t *testing.T) {
	fake := &fakeFleetHTTPClient{body: `{
		"template":{"id":"tmpl-branch","name":"Branch","revision":"sha256:t"},
		"validation":{"valid":true},
		"previousCandidateRevision":"sha256:old",
		"candidateRevision":"sha256:new",
		"applyResult":{
			"id":"apply-20260622T120000Z-abcd",
			"status":"applied",
			"custodyBoundary":"server-retained local Fleet apply result; unsigned and not distributed custody",
			"nodeResults":[
				{"nodeId":"local","nodeName":"local appliance","result":"applied","mutation":"local candidate policy updated; running policy not applied","reason":"template staged to local candidate revision sha256:new"},
				{"nodeId":"fw-peer","nodeName":"fw-peer","result":"skipped","mutation":"none","reason":"peer eligible but skipped because Fleet has no safe peer RPC transport in this slice"}
			]
		},
		"applyPath":"local candidate applied",
		"orchestrationBoundary":"local candidate apply plus explicit peer result custody only; no peer RPC"
	}`}
	client := &fleetClient{baseURL: "http://127.0.0.1:8080", httpClient: fake}
	cmd, stdout := fleetCommandForTest()
	err := runFleetTemplatesApply(context.Background(), cmd, client, "tmpl-branch", fleetCommandOptions{
		expectedRevision: "sha256:old",
		comment:          "apply branch",
		peers:            []string{"id=fw-peer,name=fw-peer,role=passive,runtime=ready,running=17,haReady=true"},
	})
	if err != nil {
		t.Fatalf("runFleetTemplatesApply returned error: %v", err)
	}
	if fake.req.URL.String() != "http://127.0.0.1:8080/v1/fleet/templates/tmpl-branch:apply" {
		t.Fatalf("request URL = %s", fake.req.URL.String())
	}
	var req map[string]any
	if err := json.Unmarshal(fake.raw, &req); err != nil {
		t.Fatalf("request JSON: %v", err)
	}
	if req["expectedCandidateRevision"] != "sha256:old" || req["comment"] != "apply branch" {
		t.Fatalf("request = %#v", req)
	}
	nodes := req["nodes"].([]any)
	if nodes[0].(map[string]any)["id"] != "fw-peer" {
		t.Fatalf("nodes request = %#v", nodes)
	}
	out := stdout.String()
	for _, want := range []string{"fleet template apply", "apply result:    apply-20260622T120000Z-abcd status=applied", "fw-peer", "result=skipped", "no peer RPC", "ngfwctl policy validate"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q:\n%s", want, out)
		}
	}
}

func TestFleetApplyRequiresRevisionAndComment(t *testing.T) {
	cmd, _ := fleetCommandForTest()
	client := &fleetClient{baseURL: "http://127.0.0.1:8080", httpClient: &fakeFleetHTTPClient{body: `{}`}}
	if err := runFleetTemplatesApply(context.Background(), cmd, client, "tmpl-a", fleetCommandOptions{comment: "apply"}); err == nil || !strings.Contains(err.Error(), "--expected-candidate-revision") {
		t.Fatalf("expected revision error, got %v", err)
	}
	if err := runFleetTemplatesApply(context.Background(), cmd, client, "tmpl-a", fleetCommandOptions{expectedRevision: "sha256:1"}); err == nil || !strings.Contains(err.Error(), "--message") {
		t.Fatalf("expected message error, got %v", err)
	}
}

func TestFleetTemplateResultsListsRetainedCustody(t *testing.T) {
	fake := &fakeFleetHTTPClient{body: `{
		"results":[{
			"id":"apply-20260622T120000Z-abcd",
			"templateId":"tmpl-branch",
			"status":"applied",
			"candidateRevisionAfter":"sha256:new",
			"custodyBoundary":"server-retained local Fleet apply result; unsigned and not distributed custody",
			"nodeResults":[
				{"nodeId":"local","nodeName":"local appliance","result":"applied","mutation":"local candidate policy updated; running policy not applied","reason":"template staged"},
				{"nodeId":"fw-peer","nodeName":"fw-peer","result":"skipped","mutation":"none","reason":"no safe peer RPC"}
			]
		}],
		"boundaries":["no signed result chain"]
	}`}
	client := &fleetClient{baseURL: "http://127.0.0.1:8080", httpClient: fake}
	cmd, stdout := fleetCommandForTest()
	if err := runFleetTemplateResults(context.Background(), cmd, client, "tmpl-branch", false); err != nil {
		t.Fatalf("runFleetTemplateResults returned error: %v", err)
	}
	if fake.req.URL.String() != "http://127.0.0.1:8080/v1/fleet/template-results?templateId=tmpl-branch" {
		t.Fatalf("request URL = %s", fake.req.URL.String())
	}
	out := stdout.String()
	for _, want := range []string{"fleet template apply results", "apply-20260622T120000Z-abcd", "result=skipped", "no signed result chain"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q:\n%s", want, out)
		}
	}
}

func TestFleetApplyPlanRejectsMalformedPeerInventory(t *testing.T) {
	cmd, _ := fleetCommandForTest()
	client := &fleetClient{baseURL: "http://127.0.0.1:8080", httpClient: &fakeFleetHTTPClient{body: `{}`}}
	if err := runFleetTemplatesApplyPlan(context.Background(), cmd, client, "tmpl-a", fleetCommandOptions{peers: []string{"name=missing-id"}}); err == nil || !strings.Contains(err.Error(), "id=<node-id>") {
		t.Fatalf("expected peer id error, got %v", err)
	}
}

func TestFleetTemplatesGetUsesListAPI(t *testing.T) {
	client := &fleetClient{baseURL: "http://127.0.0.1:8080", httpClient: &fakeFleetHTTPClient{body: `{
		"templates":[
			{"id":"tmpl-a","name":"A","scope":"local-appliance","revision":"sha256:a","policySummary":{"rules":1,"zones":2},"updatedAt":"2026-06-22T12:00:00Z"},
			{"id":"tmpl-b","name":"B","scope":"local-appliance","revision":"sha256:b","policySummary":{"rules":3,"zones":4},"updatedAt":"2026-06-22T12:01:00Z"}
		]
	}`}}
	cmd, stdout := fleetCommandForTest()
	if err := runFleetTemplatesGet(context.Background(), cmd, client, "tmpl-b", false); err != nil {
		t.Fatalf("runFleetTemplatesGet returned error: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "tmpl-b") || !strings.Contains(out, "rules=3") {
		t.Fatalf("stdout = %s", out)
	}
}

func fleetCommandForTest() (*cobra.Command, *bytes.Buffer) {
	var stdout bytes.Buffer
	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)
	return cmd, &stdout
}

func writeFleetPolicyFile(t *testing.T, body string) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "policy-*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := file.WriteString(body); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	return file.Name()
}
