package main

import (
	"os"
	"strings"
	"testing"
)

func TestOverlayAddsBrowserAuthRoutes(t *testing.T) {
	input := []byte(`swagger: "2.0"
info:
  title: Phragma Control Plane API
paths:
  /v1/system/status:
    get:
      operationId: getSystemStatus
definitions: {}
securityDefinitions:
  BearerAuth:
    type: apiKey
security:
  - BearerAuth: []
`)
	out, err := overlay(input)
	if err != nil {
		t.Fatalf("overlay() error = %v", err)
	}
	text := string(out)
	for _, want := range []string{
		"/v1/auth/oidc/status:",
		"operationId: getOIDCStatus",
		"/v1/auth/oidc/login:",
		"/v1/auth/oidc/callback:",
		"/v1/auth/saml/status:",
		"operationId: getSAMLStatus",
		"/v1/auth/saml/login:",
		"/v1/auth/saml/acs:",
		"/v1/auth/logout:",
		"name: X-Phragma-CSRF",
		"openngfw.v1.OIDCStatusResponse:",
		"csrf_token:",
		"/v1/fleet/nodes:",
		"operationId: listFleetNodes",
		"/v1/fleet/templates:",
		"operationId: listFleetTemplates",
		"operationId: createFleetTemplate",
		"$ref: '#/definitions/openngfw.v1.CreateFleetTemplateRequest'",
		"/v1/fleet/templates/{id}:validate:",
		"operationId: validateFleetTemplate",
		"/v1/fleet/templates/{id}:apply-preview:",
		"operationId: applyPreviewFleetTemplate",
		"$ref: '#/definitions/openngfw.v1.ApplyPreviewFleetTemplateRequest'",
		"/v1/fleet/templates/{id}:apply-plan:",
		"operationId: applyPlanFleetTemplate",
		"$ref: '#/definitions/openngfw.v1.ApplyPlanFleetTemplateRequest'",
		"/v1/fleet/templates/{id}:apply:",
		"operationId: applyFleetTemplate",
		"$ref: '#/definitions/openngfw.v1.ApplyFleetTemplateRequest'",
		"/v1/fleet/template-results:",
		"operationId: listFleetTemplateResults",
		"/v1/fleet/templates/{id}:stage-candidate:",
		"operationId: stageCandidateFleetTemplate",
		"$ref: '#/definitions/openngfw.v1.StageCandidateFleetTemplateRequest'",
		"openngfw.v1.FleetApplyPlanNodeInput:",
		"maxItems: 32",
		"/v1/compliance/reports:",
		"operationId: listComplianceReports",
		"operationId: createComplianceReport",
		"$ref: '#/definitions/openngfw.v1.CreateComplianceReportRequest'",
		"$ref: '#/definitions/openngfw.v1.CreateComplianceReportResponse'",
		"$ref: '#/definitions/openngfw.v1.GetComplianceReportResponse'",
		"/v1/compliance/reports/{id}:",
		"operationId: getComplianceReport",
		"/v1/compliance/reports/{id}/export:",
		"operationId: exportComplianceReport",
		"Content-Disposition:",
		"X-Phragma-Payload-Sha256:",
		"ETag:",
		"openngfw.v1.ListComplianceReportsResponse:",
		"openngfw.v1.ComplianceReportSummary:",
		"openngfw.v1.ComplianceErrorResponse:",
		"/v1/system/automation/replay:validate:",
		"operationId: validateAutomationReplay",
		"Normalizes browser-exported automation recordings",
		"/v1/investigation/cases:",
		"operationId: listInvestigationCases",
		"operationId: createInvestigationCase",
		"/v1/investigation/cases/{id}:",
		"operationId: getInvestigationCase",
		"operationId: updateInvestigationCaseLifecycle",
		"/v1/investigation/cases/{id}/evidence:",
		"operationId: addInvestigationCaseEvidence",
		"tags:\n        - investigation",
		"name: limit",
		"name: state",
		"name: id",
		"openngfw.v1.ListInvestigationCasesResponse:",
		"openngfw.v1.InvestigationCaseResponse:",
		"openngfw.v1.InvestigationCaseRecord:",
		"openngfw.v1.InvestigationCaseSummary:",
		"openngfw.v1.InvestigationEvidence:",
		"openngfw.v1.InvestigationTargetSummary:",
		"target:",
		"$ref: '#/definitions/openngfw.v1.InvestigationTargetSummary'",
		"openngfw.v1.CreateInvestigationCaseRequest:",
		"openngfw.v1.UpdateInvestigationCaseLifecycleRequest:",
		"openngfw.v1.AddInvestigationCaseEvidenceRequest:",
		"openngfw.v1.InvestigationErrorResponse:",
		"case-YYYYMMDDTHHMMSSZ-xxxxxxxx",
		"resolutionNote",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("overlay output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "operationId: listInvestigationCases\n      security: []") ||
		strings.Contains(text, "operationId: createInvestigationCase\n      security: []") {
		t.Fatalf("investigation operations should inherit global bearer security:\n%s", text)
	}
	listFleetNodesBlock := text[strings.Index(text, "operationId: listFleetNodes"):strings.Index(text, "/v1/fleet/templates:")]
	if hasStatus(listFleetNodesBlock, "201") || !hasStatus(listFleetNodesBlock, "200") {
		t.Fatalf("list fleet nodes should advertise 200 success and no 201 Created:\n%s", listFleetNodesBlock)
	}
	listFleetTemplatesBlock := text[strings.Index(text, "operationId: listFleetTemplates"):strings.Index(text, "operationId: createFleetTemplate")]
	if hasStatus(listFleetTemplatesBlock, "201") || !hasStatus(listFleetTemplatesBlock, "200") {
		t.Fatalf("list fleet templates should advertise 200 success and no 201 Created:\n%s", listFleetTemplatesBlock)
	}
	createFleetTemplateBlock := text[strings.Index(text, "operationId: createFleetTemplate"):strings.Index(text, "/v1/fleet/templates/{id}:validate:")]
	if !hasStatus(createFleetTemplateBlock, "201") || !hasStatus(createFleetTemplateBlock, "409") || hasStatus(createFleetTemplateBlock, "200") {
		t.Fatalf("create fleet template should advertise 201 Created, 409 conflict, and no 200 success:\n%s", createFleetTemplateBlock)
	}
	if !strings.Contains(createFleetTemplateBlock, "$ref: '#/definitions/openngfw.v1.CreateFleetTemplateRequest'") {
		t.Fatalf("create fleet template body should reference concrete request schema:\n%s", createFleetTemplateBlock)
	}
	validateFleetBlock := text[strings.Index(text, "operationId: validateFleetTemplate"):strings.Index(text, "operationId: applyPreviewFleetTemplate")]
	if hasStatus(validateFleetBlock, "201") || !hasStatus(validateFleetBlock, "200") {
		t.Fatalf("validate fleet template should advertise 200 success and no 201 Created:\n%s", validateFleetBlock)
	}
	applyPreviewFleetBlock := text[strings.Index(text, "operationId: applyPreviewFleetTemplate"):strings.Index(text, "operationId: applyPlanFleetTemplate")]
	if hasStatus(applyPreviewFleetBlock, "201") || !hasStatus(applyPreviewFleetBlock, "200") {
		t.Fatalf("fleet apply-preview should advertise 200 success and no 201 Created:\n%s", applyPreviewFleetBlock)
	}
	if !strings.Contains(applyPreviewFleetBlock, "$ref: '#/definitions/openngfw.v1.ApplyPreviewFleetTemplateRequest'") {
		t.Fatalf("fleet apply-preview body should reference concrete request schema:\n%s", applyPreviewFleetBlock)
	}
	applyPlanFleetBlock := text[strings.Index(text, "operationId: applyPlanFleetTemplate"):strings.Index(text, "operationId: applyFleetTemplate")]
	if hasStatus(applyPlanFleetBlock, "201") || !hasStatus(applyPlanFleetBlock, "200") {
		t.Fatalf("fleet apply-plan should advertise 200 success and no 201 Created:\n%s", applyPlanFleetBlock)
	}
	if !strings.Contains(applyPlanFleetBlock, "$ref: '#/definitions/openngfw.v1.ApplyPlanFleetTemplateRequest'") {
		t.Fatalf("fleet apply-plan body should reference concrete request schema:\n%s", applyPlanFleetBlock)
	}
	applyFleetBlock := text[strings.Index(text, "operationId: applyFleetTemplate"):strings.Index(text, "/v1/fleet/template-results:")]
	if hasStatus(applyFleetBlock, "201") || !hasStatus(applyFleetBlock, "200") {
		t.Fatalf("fleet apply should advertise 200 success and no 201 Created:\n%s", applyFleetBlock)
	}
	if !strings.Contains(applyFleetBlock, "$ref: '#/definitions/openngfw.v1.ApplyFleetTemplateRequest'") {
		t.Fatalf("fleet apply body should reference concrete request schema:\n%s", applyFleetBlock)
	}
	resultsFleetBlock := text[strings.Index(text, "operationId: listFleetTemplateResults"):strings.Index(text, "operationId: stageCandidateFleetTemplate")]
	if hasStatus(resultsFleetBlock, "201") || !hasStatus(resultsFleetBlock, "200") {
		t.Fatalf("fleet template results should advertise 200 success and no 201 Created:\n%s", resultsFleetBlock)
	}
	stageFleetBlock := text[strings.Index(text, "operationId: stageCandidateFleetTemplate"):strings.Index(text, "operationId: listComplianceReports")]
	if hasStatus(stageFleetBlock, "201") || !hasStatus(stageFleetBlock, "200") {
		t.Fatalf("stage fleet template should advertise 200 success and no 201 Created:\n%s", stageFleetBlock)
	}
	if !strings.Contains(stageFleetBlock, "$ref: '#/definitions/openngfw.v1.StageCandidateFleetTemplateRequest'") {
		t.Fatalf("fleet stage-candidate body should reference concrete request schema:\n%s", stageFleetBlock)
	}
	if strings.Contains(text, "operationId: listComplianceReports\n      tags:") && strings.Contains(text[strings.Index(text, "operationId: listComplianceReports"):strings.Index(text, "operationId: createComplianceReport")], "201:") {
		t.Fatalf("list compliance reports should not advertise 201 Created:\n%s", text)
	}
	if createComplianceBlock := text[strings.Index(text, "operationId: createComplianceReport"):strings.Index(text, "/v1/compliance/reports/{id}:")]; !strings.Contains(createComplianceBlock, "Location:") || hasStatus(createComplianceBlock, "200") {
		t.Fatalf("create compliance report should advertise Location and only 201 success:\n%s", createComplianceBlock)
	}
	if strings.Contains(text, "operationId: exportComplianceReport") && strings.Contains(text[strings.Index(text, "operationId: exportComplianceReport"):strings.Index(text, "operationId: validateAutomationReplay")], "201:") {
		t.Fatalf("export compliance report should not advertise 201 Created:\n%s", text)
	}
	listInvestigationBlock := text[strings.Index(text, "operationId: listInvestigationCases"):strings.Index(text, "operationId: createInvestigationCase")]
	if hasStatus(listInvestigationBlock, "201") || !hasStatus(listInvestigationBlock, "200") {
		t.Fatalf("list investigation cases should advertise only 200 success:\n%s", listInvestigationBlock)
	}
	createInvestigationBlock := text[strings.Index(text, "operationId: createInvestigationCase"):strings.Index(text, "/v1/investigation/cases/{id}:")]
	if !hasStatus(createInvestigationBlock, "201") || !strings.Contains(createInvestigationBlock, "Location:") || hasStatus(createInvestigationBlock, "200") {
		t.Fatalf("create investigation case should advertise 201 Location and no 200 success:\n%s", createInvestigationBlock)
	}
	getInvestigationBlock := text[strings.Index(text, "operationId: getInvestigationCase"):strings.Index(text, "operationId: updateInvestigationCaseLifecycle")]
	if hasStatus(getInvestigationBlock, "201") || !hasStatus(getInvestigationBlock, "200") {
		t.Fatalf("get investigation case should advertise only 200 success:\n%s", getInvestigationBlock)
	}
	patchInvestigationBlock := text[strings.Index(text, "operationId: updateInvestigationCaseLifecycle"):strings.Index(text, "/v1/investigation/cases/{id}/evidence:")]
	if hasStatus(patchInvestigationBlock, "201") || !hasStatus(patchInvestigationBlock, "200") {
		t.Fatalf("patch investigation case should advertise only 200 success:\n%s", patchInvestigationBlock)
	}
	evidenceInvestigationBlock := text[strings.Index(text, "operationId: addInvestigationCaseEvidence"):strings.Index(text, "operationId: validateAutomationReplay")]
	if hasStatus(evidenceInvestigationBlock, "201") || !hasStatus(evidenceInvestigationBlock, "413") || !strings.Contains(evidenceInvestigationBlock, "Evidence limit exceeded") {
		t.Fatalf("add investigation evidence should advertise 200 plus 413 and no 201:\n%s", evidenceInvestigationBlock)
	}
	if strings.Count(text, "description: SAML login failed") != 2 {
		t.Fatalf("SAML browser routes should have SAML-specific 401 descriptions:\n%s", text)
	}
}

func hasStatus(block, code string) bool {
	return strings.Contains(block, "\n        "+code+":") || strings.Contains(block, "\n        \""+code+"\":")
}

func TestPublishedOpenAPISpecIncludesFleetRequestDefinitions(t *testing.T) {
	spec, err := os.ReadFile("../../docs/api-spec.yaml")
	if err != nil {
		t.Fatalf("read published OpenAPI spec: %v", err)
	}
	text := string(spec)
	for _, want := range []string{
		"$ref: '#/definitions/openngfw.v1.CreateFleetTemplateRequest'",
		"$ref: '#/definitions/openngfw.v1.ApplyPreviewFleetTemplateRequest'",
		"$ref: '#/definitions/openngfw.v1.ApplyPlanFleetTemplateRequest'",
		"$ref: '#/definitions/openngfw.v1.ApplyFleetTemplateRequest'",
		"$ref: '#/definitions/openngfw.v1.StageCandidateFleetTemplateRequest'",
		"openngfw.v1.CreateFleetTemplateRequest:",
		"openngfw.v1.ApplyPreviewFleetTemplateRequest:",
		"openngfw.v1.ApplyPlanFleetTemplateRequest:",
		"openngfw.v1.ApplyFleetTemplateRequest:",
		"openngfw.v1.StageCandidateFleetTemplateRequest:",
		"openngfw.v1.FleetApplyPlanNodeInput:",
		"maxItems: 32",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("published OpenAPI spec missing %q", want)
		}
	}
	createBlock := definitionBlock(text, "openngfw.v1.CreateFleetTemplateRequest:")
	if !strings.Contains(createBlock, "- name") || !strings.Contains(createBlock, "- policy") {
		t.Fatalf("create fleet template request should require name and policy:\n%s", createBlock)
	}
	applyBlock := definitionBlock(text, "openngfw.v1.ApplyFleetTemplateRequest:")
	if !strings.Contains(applyBlock, "- expectedCandidateRevision") || !strings.Contains(applyBlock, "- comment") {
		t.Fatalf("apply fleet template request should require revision guard and comment:\n%s", applyBlock)
	}
	stageBlock := definitionBlock(text, "openngfw.v1.StageCandidateFleetTemplateRequest:")
	if !strings.Contains(stageBlock, "- expectedCandidateRevision") {
		t.Fatalf("stage candidate fleet template request should require revision guard:\n%s", stageBlock)
	}
}

func definitionBlock(text, marker string) string {
	start := strings.Index(text, marker)
	if start < 0 {
		return ""
	}
	end := strings.Index(text[start+len(marker):], "\n  openngfw.v1.")
	if end < 0 {
		return text[start:]
	}
	return text[start : start+len(marker)+end]
}

func TestPublishedOpenAPISpecIncludesReleaseRecordabilityStaleEvidencePaths(t *testing.T) {
	spec, err := os.ReadFile("../../docs/api-spec.yaml")
	if err != nil {
		t.Fatalf("read published OpenAPI spec: %v", err)
	}
	text := string(spec)
	blockStart := strings.Index(text, "openngfw.v1.ReleaseAcceptanceRecordabilityStatus:")
	if blockStart < 0 {
		t.Fatalf("published OpenAPI spec missing release acceptance recordability schema")
	}
	blockEnd := strings.Index(text[blockStart:], "\n  openngfw.v1.")
	if blockEnd < 0 {
		blockEnd = len(text) - blockStart
	}
	block := text[blockStart : blockStart+blockEnd]
	if !strings.Contains(block, "staleEvidencePaths:") {
		t.Fatalf("release acceptance recordability schema should expose staleEvidencePaths:\n%s", block)
	}
}
