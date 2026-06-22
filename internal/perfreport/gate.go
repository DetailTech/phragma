package perfreport

import (
	"fmt"
	"sort"
	"strings"
)

const (
	// GateOK means the publication check passed.
	GateOK = "ok"
	// GateWarn means the publication check needs operator review.
	GateWarn = "warn"
	// GateBad means the publication check blocks release or comparison use.
	GateBad = "bad"
)

// GateItem is one operator-facing publication or release-use check.
type GateItem struct {
	Label  string
	State  string
	Title  string
	Detail string
}

// PublicationGate classifies whether a benchmark artifact is suitable for
// release, publication, or comparison under its stated claim scope.
type PublicationGate struct {
	State  string
	Label  string
	Title  string
	Detail string
	Items  []GateItem
}

// RepairStep is one concrete operator action for turning benchmark evidence
// into a release-usable artifact.
type RepairStep struct {
	Level   string
	Badge   string
	Title   string
	Detail  string
	Command string
}

// Publishable reports whether all gate checks are clean.
func (g PublicationGate) Publishable() bool {
	return g.State == GateOK
}

// EvaluatePublicationGate derives the same operator-use gate shown in the
// WebUI Performance page from the validated benchmark summary.
func EvaluatePublicationGate(result ValidationResult, strict bool) PublicationGate {
	gates := []GateItem{
		schemaGate(result.Errors, result.Warnings, strict),
		publicationScopeGate(result.Summary),
		inspectionGate(result.Summary.InspectionState),
		hostTuningGate(result.Summary),
		conntrackGate(result.Summary),
		flowtableGate(result.Summary),
	}
	state := GateOK
	for _, gate := range gates {
		if gate.State == GateBad {
			state = GateBad
			break
		}
		if gate.State == GateWarn {
			state = GateWarn
		}
	}
	switch state {
	case GateOK:
		return PublicationGate{
			State:  state,
			Label:  "publishable",
			Title:  "Evidence is ready for scoped publication",
			Detail: "The artifact passes the local contract and carries the required context for its stated scope.",
			Items:  gates,
		}
	case GateWarn:
		return PublicationGate{
			State:  state,
			Label:  "review required",
			Title:  "Evidence needs operator review",
			Detail: "The artifact may still be useful internally, but publication or release use needs the listed context or evidence gaps resolved.",
			Items:  gates,
		}
	default:
		return PublicationGate{
			State:  state,
			Label:  "blocked",
			Title:  "Evidence is not publishable",
			Detail: "Fix the blocking evidence issues before using this artifact for release, publication, or comparison.",
			Items:  gates,
		}
	}
}

// RecommendRepairSteps translates validation and publication-gate findings into
// concrete operator actions. The WebUI uses the same shape for its repair queue,
// and ngfwperf uses it for headless benchmark workflows.
func RecommendRepairSteps(result ValidationResult, strict bool) []RepairStep {
	var steps []RepairStep
	seen := map[string]bool{}
	add := func(step RepairStep) {
		step.Title = strings.TrimSpace(step.Title)
		if step.Title == "" {
			return
		}
		if step.Level == "" {
			step.Level = "medium"
		}
		if step.Badge == "" {
			step.Badge = step.Level
		}
		key := step.Title + "\n" + step.Command + "\n" + step.Detail
		if seen[key] {
			return
		}
		seen[key] = true
		steps = append(steps, step)
	}

	if len(result.Errors) > 0 {
		add(RepairStep{
			Level:   "high",
			Badge:   "contract",
			Title:   "Fix blocking evidence errors",
			Detail:  fmt.Sprintf("%d schema, raw-artifact, or consistency error%s must be corrected before this benchmark can support a release or comparison claim.", len(result.Errors), plural(len(result.Errors))),
			Command: "ngfwperf verify --strict --publishable perf/results/<run>",
		})
	}
	if strict && len(result.Warnings) > 0 {
		add(RepairStep{
			Level:  "high",
			Badge:  "strict",
			Title:  "Resolve strict-gate warnings",
			Detail: fmt.Sprintf("%d warning%s remain. Strict release mode treats warnings as failures.", len(result.Warnings), plural(len(result.Warnings))),
		})
	} else if len(result.Warnings) > 0 {
		add(RepairStep{
			Level:  "medium",
			Badge:  "review",
			Title:  "Review evidence warnings",
			Detail: fmt.Sprintf("%d warning%s remain before this should be used outside local regression work.", len(result.Warnings), plural(len(result.Warnings))),
		})
	}

	messages := append(append([]string{}, result.Errors...), result.Warnings...)
	if includesAny(messages, "raw iperf3.json is not present", "iperf3.json invalid JSON", "iperf3.json reports benchmark error", "iperf3.json does not contain") {
		add(RepairStep{
			Level:  "high",
			Badge:  "iperf",
			Title:  "Load raw iperf3 evidence",
			Detail: "Throughput summaries must be traceable to the raw iperf3 JSON from the measured run.",
		})
	}
	if includesAny(messages, "no raw ngfwctl status artifact is present", "read status artifact", "has no inspection lines", "has no state table line", "has no flowtable host line", "has no flowtable live line") {
		add(RepairStep{
			Level:   "high",
			Badge:   "status",
			Title:   "Load active runtime status",
			Detail:  "Capture status during benchmark traffic so inspection readiness, state-table pressure, and flowtable runtime state match the summary.",
			Command: "ngfwctl status > ngfw-status-active.txt",
		})
	}
	if includesAny(messages, "no raw nftables artifact is present", "read nftables artifact") {
		add(RepairStep{
			Level:   "high",
			Badge:   "nft",
			Title:   "Load nftables ruleset evidence",
			Detail:  "Flowtable claims need the active nftables ruleset showing the fastpath declaration and offload rule.",
			Command: "sudo nft list table inet openngfw > nft-openngfw-active.txt",
		})
	}
	if includesAny(messages, "does not match iperf3.json", "does not match ngfw-status", "does not match firewall-status", "does not match nft-openngfw", "does not match status artifact", "does not match nftables artifact") {
		add(RepairStep{
			Level:   "high",
			Badge:   "mismatch",
			Title:   "Regenerate the summary from the raw artifacts",
			Detail:  "The loaded summary disagrees with raw benchmark evidence. Rebuild the report from the same run directory instead of editing fields by hand.",
			Command: "ngfwperf verify --strict perf/results/<run>",
		})
	}
	if includesAny(messages, "flowtable_evidence") {
		add(RepairStep{
			Level:   "high",
			Badge:   "fast path",
			Title:   "Prove the flowtable fast path",
			Detail:  "Flowtable evidence must agree with active runtime status and the loaded nftables ruleset.",
			Command: "ngfwctl status > ngfw-status-active.txt && sudo nft list table inet openngfw > nft-openngfw-active.txt",
		})
	}
	if includesAny(messages, "inspection_evidence") {
		add(RepairStep{
			Level:   "medium",
			Badge:   "inspection",
			Title:   "Capture inspection readiness",
			Detail:  "Inspection, bypass, failed-open, and failed-closed claims need policy-aware ngfwctl status evidence from the measured window.",
			Command: "ngfwctl status > ngfw-status-active.txt",
		})
	}

	for _, item := range EvaluatePublicationGate(result, strict).Items {
		if item.State == GateOK {
			continue
		}
		switch item.Label {
		case "Scope":
			add(RepairStep{
				Level:  gateRepairLevel(item.State),
				Badge:  "scope",
				Title:  "Tighten the claim scope",
				Detail: value(item.Detail, "State exactly what environment, policy, services, and inspection state the benchmark proves."),
			})
		case "Inspection":
			add(RepairStep{
				Level:  "medium",
				Badge:  "inspection",
				Title:  "Align the claim with inspection state",
				Detail: value(item.Detail, "Forwarding-only, bypassed, failed-open, and partially inspected runs must not be described as prevention throughput."),
			})
		case "Host tuning":
			step := RepairStep{
				Level:   gateRepairLevel(item.State),
				Badge:   "tuning",
				Title:   "Capture host-tuning context",
				Detail:  value(item.Detail, "High-bandwidth benchmarks require kernel forwarding and conntrack tuning evidence from active-load status."),
				Command: "ngfwctl status > ngfw-status-active.txt",
			}
			if item.State == GateBad {
				step.Title = "Apply the throughput tuning profile"
				step.Command = "sudo ngfwctl system tune --profile throughput --write --apply"
			}
			add(step)
		case "State table":
			step := RepairStep{
				Level:   gateRepairLevel(item.State),
				Badge:   "state",
				Title:   "Capture state-table context",
				Detail:  value(item.Detail, "State-table pressure affects high-throughput and high-connection-churn benchmark validity."),
				Command: "ngfwctl status > ngfw-status-active.txt",
			}
			if item.State == GateBad {
				step.Title = "Resolve state-table pressure"
				step.Command = "sudo ngfwctl system tune --profile throughput --write --apply"
			}
			add(step)
		case "Fast path":
			add(RepairStep{
				Level:   gateRepairLevel(item.State),
				Badge:   "fast path",
				Title:   "Prove the flowtable fast path",
				Detail:  value(item.Detail, "Flowtable claims require active runtime evidence and an nftables ruleset containing the fastpath and flow-add rule."),
				Command: "ngfwctl status > ngfw-status-active.txt && sudo nft list table inet openngfw > nft-openngfw-active.txt",
			})
		}
	}

	if len(steps) == 0 {
		add(RepairStep{
			Level:   "low",
			Badge:   "ready",
			Title:   "Archive this evidence with the run artifacts",
			Detail:  "The summary, raw iperf output, active status, nftables evidence, and report can be retained together for release review.",
			Command: "ngfwperf verify --strict --publishable perf/results/<run>",
		})
	}

	sort.SliceStable(steps, func(i, j int) bool {
		return repairLevelRank(steps[i].Level) < repairLevelRank(steps[j].Level)
	})
	return steps
}

func schemaGate(errors, warnings []string, strict bool) GateItem {
	if len(errors) > 0 {
		return gate("Contract", GateBad, "Schema or required evidence failed.", fmt.Sprintf("%d error(s) must be fixed.", len(errors)))
	}
	if strict && len(warnings) > 0 {
		return gate("Release gate", GateBad, "Strict release verification fails.", fmt.Sprintf("%d warning(s) remain.", len(warnings)))
	}
	if len(warnings) > 0 {
		return gate("Release gate", GateWarn, "Non-strict verification accepts this artifact.", fmt.Sprintf("%d warning(s) remain.", len(warnings)))
	}
	return gate("Release gate", GateOK, "Strict verification is clean.", "No schema errors or warnings.")
}

func publicationScopeGate(summary Summary) GateItem {
	scope := strings.ToLower(summary.ClaimScope)
	profile := strings.ToLower(summary.Profile)
	if summary.ClaimScope == "" {
		return gate("Scope", GateBad, "Claim scope is missing.", "A benchmark claim must state where it applies.")
	}
	if strings.Contains(scope, "do not publish") {
		return gate("Scope", GateWarn, "Publication requires the full external context.", summary.ClaimScope)
	}
	if strings.Contains(scope, "single-host") || strings.Contains(scope, "not a cloud") ||
		strings.Contains(scope, "not a nic") || strings.Contains(profile, "netns") {
		return gate("Scope", GateWarn, "Regression evidence only.", "Do not compare this as cloud-NIC or VM-Series-class throughput.")
	}
	if strings.Contains(scope, "measured environment only") {
		return gate("Scope", GateWarn, "Scoped to the measured environment.", "Publish only with instance shape, NIC mode, policy, services, and inspection state.")
	}
	return gate("Scope", GateOK, "Scope is explicit.", summary.ClaimScope)
}

func inspectionGate(state string) GateItem {
	switch state {
	case "fully-inspected":
		return gate("Inspection", GateOK, "Traffic is labeled fully inspected.", "This can support a threat-prevention throughput claim if the rest of the evidence is complete.")
	case "partially-inspected":
		return gate("Inspection", GateWarn, "Traffic is partially inspected.", "Describe what was inspected and what was bypassed.")
	case "failed-closed":
		return gate("Inspection", GateWarn, "Failed-closed behavior evidence.", "Useful failure-mode evidence, not normal throughput evidence.")
	case "failed-open":
		return gate("Inspection", GateWarn, "Failed-open behavior evidence.", "Do not present as strict prevention throughput.")
	case "bypassed-by-policy", "bypassed-by-engine-health":
		return gate("Inspection", GateWarn, "Inspection bypass is explicit.", "Useful only when the bypass reason is the intended claim.")
	case "blocked-before-inspection":
		return gate("Inspection", GateWarn, "Traffic was blocked before inspection.", "This is enforcement evidence, not forwarding throughput evidence.")
	case "not-inspected":
		return gate("Inspection", GateWarn, "Forwarding-only evidence.", "Do not use this as NGFW threat-prevention or App-ID throughput.")
	default:
		if state == "" {
			return gate("Inspection", GateBad, "Inspection state is missing.", "Use a canonical inspection state.")
		}
		return gate("Inspection", GateWarn, "Inspection state is non-canonical.", state)
	}
}

func hostTuningGate(summary Summary) GateItem {
	e := summary.HostTuningEvidence
	if e == nil {
		if requiresHostTuningEvidence(summary) {
			return gate("Host tuning", GateWarn, "High-bandwidth claim lacks kernel tuning evidence.", "Capture active-load ngfwctl status so forwarding and conntrack sysctl readiness is known.")
		}
		return gate("Host tuning", GateOK, "No high-bandwidth or connection-rate claim.", "Host tuning evidence is optional for this artifact.")
	}
	if e.State == "ready" {
		return gate("Host tuning", GateOK, "Kernel tuning is ready.", hostTuningDetail(e))
	}
	state := GateWarn
	if requiresHostTuningEvidence(summary) {
		state = GateBad
	}
	return gate("Host tuning", state, "Kernel tuning was not ready.", hostTuningDetail(e))
}

func conntrackGate(summary Summary) GateItem {
	e := summary.ConntrackEvidence
	if e == nil {
		if requiresConntrackEvidence(summary, nil) {
			return gate("State table", GateWarn, "Throughput claim lacks state-table evidence.", "Capture active-load ngfwctl status so conntrack capacity pressure is known.")
		}
		return gate("State table", GateOK, "No throughput or connection-rate claim.", "State-table evidence is optional for this artifact.")
	}
	switch e.State {
	case "degraded":
		return gate("State table", GateBad, "State table was degraded.", conntrackDetail(e))
	case "warning":
		return gate("State table", GateWarn, "State table pressure warning.", conntrackDetail(e))
	default:
		return gate("State table", GateOK, "State table evidence captured.", conntrackDetail(e))
	}
}

func flowtableGate(summary Summary) GateItem {
	text := strings.ToLower(summary.Profile + " " + summary.ClaimScope)
	claimed := strings.Contains(text, "flowtable")
	e := summary.FlowtableEvidence
	if e == nil {
		if claimed {
			return gate("Fast path", GateBad, "Flowtable claim lacks runtime evidence.", "Capture active-load status and nftables ruleset evidence.")
		}
		return gate("Fast path", GateOK, "No flowtable claim.", "Fast-path evidence is optional for this artifact.")
	}
	nftProven := e.NftRulesetCaptured && e.FlowtableDeclared && e.OffloadRulePresent
	if e.RuntimeState == "active" && nftProven {
		return gate("Fast path", GateOK, "Flowtable runtime is proven active.", "Status and nftables evidence agree.")
	}
	state := GateWarn
	if claimed {
		state = GateBad
	}
	return gate("Fast path", state, "Flowtable evidence is incomplete.",
		fmt.Sprintf("runtime=%s, nft=%s", value(e.RuntimeState, "unknown"), ternary(nftProven, "proven", "incomplete")))
}

func conntrackDetail(e *ConntrackEvidence) string {
	if e == nil {
		return ""
	}
	if e.MaxEntries > 0 {
		return fmt.Sprintf("%d/%d entries (%.1f%%).", e.CurrentEntries, e.MaxEntries, e.UsagePercent)
	}
	return e.State
}

func hostTuningDetail(e *HostTuningEvidence) string {
	if e == nil {
		return ""
	}
	parts := []string{value(e.State, "unknown")}
	if e.Profile != "" {
		parts = append(parts, "profile "+e.Profile)
	}
	if e.ConfigPath != "" {
		parts = append(parts, e.ConfigPath)
	}
	return strings.Join(parts, "; ")
}

func gate(label, state, title, detail string) GateItem {
	return GateItem{Label: label, State: state, Title: title, Detail: detail}
}

func value(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func ternary(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

func plural(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

func includesAny(messages []string, terms ...string) bool {
	text := strings.Join(messages, "\n")
	for _, term := range terms {
		if strings.Contains(text, term) {
			return true
		}
	}
	return false
}

func gateRepairLevel(state string) string {
	if state == GateBad {
		return "high"
	}
	return "medium"
}

func repairLevelRank(level string) int {
	switch level {
	case "high":
		return 0
	case "medium":
		return 1
	default:
		return 2
	}
}
