package replayvalidation

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	SchemaVersion    = "phragma.automation.replay-validation.v1"
	PlanSchema       = "phragma.automation.replay-execution-plan.v1"
	ResultSchema     = "phragma.automation.replay-execution-result.v1"
	MaxSteps         = 200
	MaxRunbookBytes  = 256 * 1024
	MaxCommandLength = 8192
)

var (
	curlLineRE      = regexp.MustCompile(`(?i)\bcurl\b[^\n\r]*`)
	ngfwctlLineRE   = regexp.MustCompile(`(?m)(?:^|\s)(?:sudo\s+)?ngfwctl\s+[^\n\r]*`)
	httpURLRE       = regexp.MustCompile(`https?://[^\s"'\\]+`)
	apiPathRE       = regexp.MustCompile(`/v1/[A-Za-z0-9._~!$&'()*+,;=:@/%?-]*`)
	shellTokenRE    = regexp.MustCompile(`"([^"\\]*(?:\\.[^"\\]*)*)"|'([^']*)'|(\S+)`)
	unsafeMethodSet = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}
)

type Request struct {
	SchemaVersion             string          `json:"schemaVersion,omitempty"`
	Runbook                   string          `json:"runbook,omitempty"`
	Recording                 json.RawMessage `json:"recording,omitempty"`
	Steps                     []InputStep     `json:"steps,omitempty"`
	CandidateRevision         string          `json:"candidateRevision,omitempty"`
	ExecutionMode             string          `json:"executionMode,omitempty"`
	Acknowledgements          map[string]bool `json:"acknowledgements,omitempty"`
	RequireAcknowledgements   *bool           `json:"requireAcknowledgements,omitempty"`
	RequireCandidateRevision  *bool           `json:"requireCandidateRevision,omitempty"`
	AllowUnknownReadOnlySteps bool            `json:"allowUnknownReadOnlySteps,omitempty"`
}

type InputStep struct {
	ID      string          `json:"id,omitempty"`
	Title   string          `json:"title,omitempty"`
	Type    string          `json:"type,omitempty"`
	Method  string          `json:"method,omitempty"`
	Path    string          `json:"path,omitempty"`
	URL     string          `json:"url,omitempty"`
	Body    json.RawMessage `json:"body,omitempty"`
	Command string          `json:"command,omitempty"`
	Curl    string          `json:"curl,omitempty"`
}

type State struct {
	RunningVersion     uint64 `json:"runningVersion"`
	HasCandidate       bool   `json:"hasCandidate"`
	CandidateDirty     bool   `json:"candidateDirty"`
	CandidateRevision  string `json:"candidateRevision,omitempty"`
	ExpectedRevision   string `json:"expectedRevision,omitempty"`
	Source             string `json:"source"`
	CurrentStateLoaded bool   `json:"currentStateLoaded"`
}

type Report struct {
	SchemaVersion   string   `json:"schemaVersion"`
	ValidatedAt     string   `json:"validatedAt"`
	Summary         Summary  `json:"summary"`
	State           State    `json:"state"`
	ExecutionPlan   *Plan    `json:"executionPlan,omitempty"`
	ExecutionResult *Result  `json:"executionResult,omitempty"`
	Steps           []Step   `json:"steps"`
	Issues          []Issue  `json:"issues"`
	NormalizedSteps []Step   `json:"normalizedSteps"`
	Boundaries      []string `json:"boundaries"`
	Hardening       []string `json:"hardening"`
}

type Summary struct {
	StepCount                   int  `json:"stepCount"`
	ExecutableStepCount         int  `json:"executableStepCount"`
	UnsafeMutationCount         int  `json:"unsafeMutationCount"`
	CandidateMutationCount      int  `json:"candidateMutationCount"`
	LiveApplyBlockedCount       int  `json:"liveApplyBlockedCount"`
	MissingAcknowledgementCount int  `json:"missingAcknowledgementCount"`
	MissingRevisionCount        int  `json:"missingRevisionCount"`
	UnknownRouteCount           int  `json:"unknownRouteCount"`
	Blocked                     bool `json:"blocked"`
	ReplayAllowed               bool `json:"replayAllowed"`
}

type Plan struct {
	SchemaVersion      string     `json:"schemaVersion"`
	Mode               string     `json:"mode"`
	DryRun             bool       `json:"dryRun"`
	AuthorityRequested bool       `json:"authorityRequested"`
	AuthorityGranted   bool       `json:"authorityGranted"`
	RequiredAcks       []string   `json:"requiredAcks,omitempty"`
	PresentAcks        []string   `json:"presentAcks,omitempty"`
	MissingAcks        []string   `json:"missingAcks,omitempty"`
	ReadOnlySteps      int        `json:"readOnlySteps"`
	CandidateOnlySteps int        `json:"candidateOnlySteps"`
	BlockedSteps       int        `json:"blockedSteps"`
	Steps              []PlanStep `json:"steps"`
	Boundaries         []string   `json:"boundaries"`
}

type PlanStep struct {
	StepIndex int      `json:"stepIndex"`
	Action    string   `json:"action"`
	Authority string   `json:"authority"`
	Eligible  bool     `json:"eligible"`
	DryRun    bool     `json:"dryRun"`
	Reason    string   `json:"reason,omitempty"`
	Required  []string `json:"required,omitempty"`
}

type Result struct {
	SchemaVersion string       `json:"schemaVersion"`
	Mode          string       `json:"mode"`
	StartedAt     string       `json:"startedAt"`
	CompletedAt   string       `json:"completedAt"`
	Status        string       `json:"status"`
	AuditRequired bool         `json:"auditRequired"`
	Results       []StepResult `json:"results"`
	Boundaries    []string     `json:"boundaries"`
}

type StepResult struct {
	StepIndex               int    `json:"stepIndex"`
	Action                  string `json:"action"`
	Status                  string `json:"status"`
	Mutation                string `json:"mutation,omitempty"`
	AuditAction             string `json:"auditAction,omitempty"`
	CandidateRevisionBefore string `json:"candidateRevisionBefore,omitempty"`
	CandidateRevisionAfter  string `json:"candidateRevisionAfter,omitempty"`
	Detail                  string `json:"detail,omitempty"`
}

type Step struct {
	Index                int               `json:"index"`
	ID                   string            `json:"id,omitempty"`
	Title                string            `json:"title,omitempty"`
	Source               string            `json:"source"`
	Raw                  string            `json:"raw,omitempty"`
	Method               string            `json:"method,omitempty"`
	Path                 string            `json:"path,omitempty"`
	Kind                 string            `json:"kind"`
	RouteClass           string            `json:"routeClass"`
	ReadOnly             bool              `json:"readOnly"`
	WouldMutate          bool              `json:"wouldMutate"`
	WouldApplyRunning    bool              `json:"wouldApplyRunning"`
	WouldMutateCandidate bool              `json:"wouldMutateCandidate"`
	KnownRoute           bool              `json:"knownRoute"`
	RequiredAcks         []string          `json:"requiredAcks,omitempty"`
	PresentAcks          []string          `json:"presentAcks,omitempty"`
	MissingAcks          []string          `json:"missingAcks,omitempty"`
	ExpectedRevision     string            `json:"expectedCandidateRevision,omitempty"`
	Warnings             []string          `json:"warnings,omitempty"`
	Body                 map[string]any    `json:"body,omitempty"`
	Metadata             map[string]string `json:"metadata,omitempty"`
}

type Issue struct {
	StepIndex int    `json:"stepIndex,omitempty"`
	Code      string `json:"code"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
}

func Validate(req Request, state State, now time.Time) Report {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	state.Source = firstNonEmpty(state.Source, "store")
	state.ExpectedRevision = strings.TrimSpace(req.CandidateRevision)
	steps, issues := collectSteps(req)
	report := Report{
		SchemaVersion: SchemaVersion,
		ValidatedAt:   now.UTC().Format(time.RFC3339Nano),
		State:         state,
		Boundaries: []string{
			"validation only; no replay steps are executed",
			"dry-run and apply-authority modes return an execution plan only; this package does not execute replay steps",
			"execute mode is implemented only by callers that attach an audited bounded executor; the controld API executor is limited to read-only and candidate-safe replay steps",
			"does not grant replay authority or bypass existing RBAC, CSRF, approval, candidate revision, validation, diff, commit, rollback, or audit controls",
			"browser-local recordings and runbooks remain unsigned input unless a future custody layer signs and retains them",
		},
		Hardening: []string{
			"certify replay authority separately from ordinary operator API access for production",
			"sign exported runbooks and preserve custody metadata from browser export through server validation",
			"set retention and legal-hold policy for validated runbook reports",
			"enforce least-privilege replay roles and step-level approval policy before expanding beyond bounded candidate-safe execution",
			"bind replay approval to candidate revision, actor, device, time window, and signed payload hash",
		},
	}
	if len(steps) > MaxSteps {
		issues = append(issues, Issue{Code: "STEP_LIMIT_EXCEEDED", Severity: "error", Message: fmt.Sprintf("step limit exceeded: max %d", MaxSteps)})
		steps = steps[:MaxSteps]
	}
	requireAcks := req.RequireAcknowledgements == nil || *req.RequireAcknowledgements
	requireRevision := req.RequireCandidateRevision == nil || *req.RequireCandidateRevision
	for i := range steps {
		step := validateStep(steps[i], state, requireAcks, requireRevision, req.AllowUnknownReadOnlySteps)
		report.Steps = append(report.Steps, step)
		report.NormalizedSteps = append(report.NormalizedSteps, step)
		report.Summary.StepCount++
		if step.Method != "" || step.Path != "" || step.Raw != "" {
			report.Summary.ExecutableStepCount++
		}
		if step.WouldMutate {
			report.Summary.UnsafeMutationCount++
		}
		if step.WouldMutateCandidate {
			report.Summary.CandidateMutationCount++
		}
		if step.WouldApplyRunning {
			report.Summary.LiveApplyBlockedCount++
		}
		if len(step.MissingAcks) > 0 {
			report.Summary.MissingAcknowledgementCount += len(step.MissingAcks)
		}
		for _, warning := range step.Warnings {
			issues = append(issues, Issue{StepIndex: step.Index, Code: warningCode(warning), Severity: issueSeverity(warning), Message: warning})
		}
		if !step.KnownRoute {
			report.Summary.UnknownRouteCount++
		}
		if step.ExpectedRevision == "" && step.WouldMutateCandidate {
			report.Summary.MissingRevisionCount++
		}
	}
	report.Issues = issues
	report.ExecutionPlan = buildPlan(req, report.Steps)
	for _, issue := range issues {
		if issue.Severity == "error" {
			report.Summary.Blocked = true
			break
		}
	}
	report.Summary.ReplayAllowed = !report.Summary.Blocked && report.Summary.UnsafeMutationCount == 0 && report.Summary.MissingAcknowledgementCount == 0
	return report
}

func buildPlan(req Request, steps []Step) *Plan {
	mode := replayMode(req.ExecutionMode)
	plan := &Plan{
		SchemaVersion:      PlanSchema,
		Mode:               mode,
		DryRun:             mode != "apply-authority" && mode != "execute",
		AuthorityRequested: mode == "apply-authority" || mode == "execute",
		Boundaries: []string{
			"validate, dry-run, and apply-authority responses are plan-only; execute mode requires an audited server-side executor such as controld's bounded replay handler",
			"running-policy, host-runtime, privileged capture, HA failover, rollback, commit, and unknown-route steps are blocked from bounded replay authority",
			"candidate-only authority is limited to staging/revalidation surfaces and still requires ordinary candidate review, validation, diff, commit, rollback, RBAC, CSRF, audit, and approval controls outside replay",
		},
	}
	if mode == "apply-authority" || mode == "execute" {
		plan.RequiredAcks = []string{"ackReplayAuthority", "ackReplayNoLiveApply"}
		if hasCandidateMutation(steps) {
			plan.RequiredAcks = append(plan.RequiredAcks, "ackCandidateOnlyReplay", "ackCandidateRevision")
		}
		if hasReadOnlyStep(steps) {
			plan.RequiredAcks = append(plan.RequiredAcks, "ackReadOnlyReplay")
		}
		plan.PresentAcks = presentAckMap(req.Acknowledgements, plan.RequiredAcks)
		plan.MissingAcks = missingStrings(plan.RequiredAcks, plan.PresentAcks)
	}
	for _, step := range steps {
		item := planStep(mode, step)
		if item.Eligible {
			switch item.Authority {
			case "read-only":
				plan.ReadOnlySteps++
			case "candidate-only":
				plan.CandidateOnlySteps++
			}
		} else {
			plan.BlockedSteps++
		}
		plan.Steps = append(plan.Steps, item)
	}
	plan.AuthorityGranted = (mode == "apply-authority" || mode == "execute") && plan.BlockedSteps == 0 && len(plan.MissingAcks) == 0
	return plan
}

func replayMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "dry-run", "apply-authority", "execute":
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return "validate"
	}
}

func planStep(mode string, step Step) PlanStep {
	item := PlanStep{StepIndex: step.Index, DryRun: mode != "apply-authority" && mode != "execute"}
	switch {
	case !step.KnownRoute:
		item.Action, item.Authority, item.Reason = "block", "none", "unknown route is outside the bounded replay safety table"
	case step.WouldApplyRunning:
		item.Action, item.Authority, item.Reason = "block", "none", "live running-policy or host-runtime apply is outside bounded replay authority"
	case step.WouldMutate && !step.WouldMutateCandidate:
		item.Action, item.Authority, item.Reason = "block", "none", "non-candidate mutation is outside bounded replay authority"
	case step.WouldMutateCandidate:
		item.Action, item.Authority, item.Eligible = "candidate-only-plan", "candidate-only", true
		if mode == "execute" {
			item.Action = "candidate-only-execute"
		}
		item.Required = []string{"ackReplayAuthority", "ackReplayNoLiveApply", "ackCandidateOnlyReplay", "ackCandidateRevision"}
		if step.ExpectedRevision == "" {
			item.Eligible = false
			item.Action = "block"
			item.Reason = "candidate-only authority requires expectedCandidateRevision"
		}
	case step.ReadOnly:
		item.Action, item.Authority, item.Eligible = "read-only-plan", "read-only", true
		if mode == "execute" {
			item.Action = "read-only-observe"
		}
		item.Required = []string{"ackReplayAuthority", "ackReplayNoLiveApply", "ackReadOnlyReplay"}
	default:
		item.Action, item.Authority, item.Reason = "block", "none", "step is not classified as read-only or candidate-only"
	}
	if mode == "validate" && item.Eligible {
		item.Action = "validate-only"
	}
	return item
}

func hasCandidateMutation(steps []Step) bool {
	for _, step := range steps {
		if step.WouldMutateCandidate {
			return true
		}
	}
	return false
}

func hasReadOnlyStep(steps []Step) bool {
	for _, step := range steps {
		if step.ReadOnly {
			return true
		}
	}
	return false
}

func collectSteps(req Request) ([]Step, []Issue) {
	var steps []Step
	var issues []Issue
	for _, input := range req.Steps {
		steps = append(steps, stepFromInput(input, len(steps)+1))
	}
	if len(req.Recording) > 0 {
		recorded, err := stepsFromRecording(req.Recording, len(steps)+1)
		if err != nil {
			issues = append(issues, Issue{Code: "INVALID_RECORDING", Severity: "error", Message: err.Error()})
		}
		steps = append(steps, recorded...)
	}
	if strings.TrimSpace(req.Runbook) != "" {
		if len(req.Runbook) > MaxRunbookBytes {
			issues = append(issues, Issue{Code: "RUNBOOK_TOO_LARGE", Severity: "error", Message: fmt.Sprintf("runbook exceeds %d bytes", MaxRunbookBytes)})
		} else {
			steps = append(steps, stepsFromRunbook(req.Runbook, len(steps)+1)...)
		}
	}
	if len(steps) == 0 && len(issues) == 0 {
		issues = append(issues, Issue{Code: "NO_STEPS", Severity: "error", Message: "request must include steps, recording, or runbook"})
	}
	return steps, issues
}

func stepFromInput(input InputStep, index int) Step {
	raw := firstNonEmpty(input.Command, input.Curl)
	method := strings.ToUpper(strings.TrimSpace(input.Method))
	path := normalizePath(firstNonEmpty(input.Path, input.URL))
	body := bodyMap(input.Body)
	source := strings.ToLower(strings.TrimSpace(input.Type))
	if source == "" {
		source = "api"
	}
	step := Step{Index: index, ID: input.ID, Title: input.Title, Source: source, Raw: truncate(input.Command, MaxCommandLength), Method: method, Path: path, Body: body}
	if method == "" && path == "" && raw != "" {
		if strings.Contains(strings.ToLower(raw), "curl") {
			return stepFromCurl(raw, index, input.Title)
		}
		if strings.Contains(raw, "ngfwctl") {
			return stepFromCLI(raw, index, input.Title)
		}
	}
	if method == "" {
		method = "GET"
		if len(input.Body) > 0 {
			method = "POST"
		}
	}
	step.Method = method
	return step
}

func stepsFromRecording(raw json.RawMessage, start int) ([]Step, error) {
	var packet map[string]any
	if err := json.Unmarshal(raw, &packet); err != nil {
		return nil, fmt.Errorf("recording must be JSON: %w", err)
	}
	var steps []Step
	walkRecording(packet, &steps, &start)
	return steps, nil
}

func walkRecording(value any, steps *[]Step, next *int) {
	switch v := value.(type) {
	case map[string]any:
		if method, _ := v["method"].(string); method != "" {
			if path, _ := v["path"].(string); strings.HasPrefix(path, "/v1/") {
				var rawBody json.RawMessage
				if body, ok := v["body"]; ok {
					if data, err := json.Marshal(body); err == nil {
						rawBody = data
					}
				}
				*steps = append(*steps, stepFromInput(InputStep{Type: "api", Method: method, Path: path, Body: rawBody, Title: stringValue(v["purpose"])}, *next))
				*next++
			}
		}
		if command, _ := v["command"].(string); strings.Contains(command, "ngfwctl") {
			*steps = append(*steps, stepFromCLI(command, *next, stringValue(v["purpose"])))
			*next++
		}
		if curl, _ := v["curl"].(string); strings.Contains(strings.ToLower(curl), "curl") {
			*steps = append(*steps, stepFromCurl(curl, *next, stringValue(v["purpose"])))
			*next++
		}
		for _, child := range v {
			walkRecording(child, steps, next)
		}
	case []any:
		for _, child := range v {
			walkRecording(child, steps, next)
		}
	}
}

func stepsFromRunbook(runbook string, start int) []Step {
	var steps []Step
	next := start
	for _, line := range curlLineRE.FindAllString(runbook, -1) {
		steps = append(steps, stepFromCurl(line, next, "curl runbook step"))
		next++
	}
	for _, line := range ngfwctlLineRE.FindAllString(runbook, -1) {
		steps = append(steps, stepFromCLI(strings.TrimSpace(line), next, "CLI runbook step"))
		next++
	}
	return steps
}

func stepFromCurl(command string, index int, title string) Step {
	tokens := shellTokens(command)
	method := ""
	path := ""
	var body json.RawMessage
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		switch tok {
		case "-X", "--request":
			if i+1 < len(tokens) {
				method = strings.ToUpper(tokens[i+1])
				i++
			}
		case "-d", "--data", "--data-raw", "--data-binary":
			if i+1 < len(tokens) {
				body = json.RawMessage(tokens[i+1])
				i++
			}
		default:
			if path == "" {
				path = normalizePath(tok)
			}
		}
	}
	if path == "" {
		if m := httpURLRE.FindString(command); m != "" {
			path = normalizePath(m)
		} else if m := apiPathRE.FindString(command); m != "" {
			path = normalizePath(m)
		}
	}
	if method == "" {
		if len(body) > 0 {
			method = "POST"
		} else {
			method = "GET"
		}
	}
	return Step{Index: index, Title: title, Source: "curl", Raw: truncate(command, MaxCommandLength), Method: method, Path: path, Body: bodyMap(body)}
}

func stepFromCLI(command string, index int, title string) Step {
	clean := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(command), "sudo "))
	lower := strings.ToLower(clean)
	step := Step{Index: index, Title: title, Source: "cli", Raw: truncate(command, MaxCommandLength), Method: "GET", Path: "", Metadata: map[string]string{"command": clean}}
	switch {
	case strings.Contains(lower, " policy validate"):
		step.Method, step.Path = "POST", "/v1/candidate/validate"
	case strings.Contains(lower, " policy status"):
		step.Method, step.Path = "GET", "/v1/candidate/status"
	case strings.Contains(lower, " policy diff"):
		step.Method, step.Path = "GET", "/v1/policy/diff?fromSource=POLICY_SOURCE_RUNNING&toSource=POLICY_SOURCE_CANDIDATE"
	case strings.Contains(lower, " policy show"):
		source := "POLICY_SOURCE_RUNNING"
		if strings.Contains(lower, "candidate") {
			source = "POLICY_SOURCE_CANDIDATE"
		}
		step.Method, step.Path = "GET", "/v1/policy?source="+source
	case strings.Contains(lower, " commit"):
		step.Method, step.Path = "POST", "/v1/commit"
		step.Body = map[string]any{"ackRisk": strings.Contains(lower, "--ack-risk"), "ackRuntime": strings.Contains(lower, "--ack-runtime")}
	case strings.Contains(lower, " rollback"):
		step.Method, step.Path = "POST", "/v1/rollback"
		step.Body = map[string]any{"ackRisk": strings.Contains(lower, "--ack-risk"), "ackRuntime": strings.Contains(lower, "--ack-runtime")}
	case strings.Contains(lower, " system capture") && strings.Contains(lower, "--start"):
		step.Method, step.Path = "POST", "/v1/system/packet-captures"
		step.Body = map[string]any{"ackCapture": strings.Contains(lower, "--ack-capture")}
	case strings.Contains(lower, " system capture"):
		step.Method, step.Path = "POST", "/v1/system/packet-captures/plan"
	case strings.Contains(lower, " system tune"):
		step.Method, step.Path = "POST", "/v1/system/tune"
		step.Body = map[string]any{"ackHostTuning": strings.Contains(lower, "--ack")}
	case strings.Contains(lower, " alerts"):
		step.Path = "/v1/alerts"
	case strings.Contains(lower, " flows"):
		step.Path = "/v1/flows"
	case strings.Contains(lower, " sessions"):
		step.Path = "/v1/sessions"
	case strings.Contains(lower, " explain"):
		step.Method, step.Path = "POST", "/v1/explain/flow"
	case strings.Contains(lower, " status"):
		step.Path = "/v1/system/status"
	case strings.Contains(lower, " whoami"):
		step.Path = "/v1/system/identity"
	case strings.Contains(lower, " policy set") || strings.Contains(lower, " policy baseline") || strings.Contains(lower, " policy route add") || strings.Contains(lower, " policy route delete"):
		step.Method, step.Path = "PUT", "/v1/candidate"
	default:
		step.Kind = "unknown-cli"
	}
	return step
}

func validateStep(step Step, state State, requireAcks, requireRevision, allowUnknownReadOnly bool) Step {
	step.Method = strings.ToUpper(strings.TrimSpace(firstNonEmpty(step.Method, "GET")))
	step.Path = normalizePath(step.Path)
	step.RouteClass = routeClass(step.Path)
	step.KnownRoute = step.RouteClass != "unknown"
	step.ReadOnly = !unsafeMethodSet[step.Method] || readOnlyAction(step.Path)
	step.WouldMutate = unsafeMethodSet[step.Method] && !step.ReadOnly
	step.WouldApplyRunning = step.WouldMutate && appliesRunning(step.Path)
	step.WouldMutateCandidate = step.WouldMutate && mutatesCandidate(step.Path)
	if step.Kind == "" {
		if step.ReadOnly {
			step.Kind = "read-only"
		} else if step.WouldApplyRunning {
			step.Kind = "running-mutation"
		} else if step.WouldMutateCandidate {
			step.Kind = "candidate-mutation"
		} else {
			step.Kind = "system-mutation"
		}
	}
	if !step.KnownRoute && !(allowUnknownReadOnly && step.ReadOnly) {
		step.Warnings = append(step.Warnings, "unknown route is not part of the bounded replay safety table")
	}
	if step.WouldMutate {
		switch {
		case step.WouldApplyRunning:
			step.Warnings = append(step.Warnings, "live apply step would mutate running policy or host/runtime state if replayed")
		case step.WouldMutateCandidate:
			step.Warnings = append(step.Warnings, "candidate-only step requires bounded replay authority before replay")
		default:
			step.Warnings = append(step.Warnings, "unsafe method would mutate appliance state if replayed")
		}
	}
	if step.WouldApplyRunning && !state.HasCandidate && strings.Contains(step.Path, "/v1/commit") {
		step.Warnings = append(step.Warnings, "commit step targets running policy but no candidate is currently staged")
	}
	step.RequiredAcks = requiredAcks(step.Path)
	step.PresentAcks = presentAcks(step.Body, step.RequiredAcks)
	if requireAcks {
		step.MissingAcks = missingStrings(step.RequiredAcks, step.PresentAcks)
		if len(step.MissingAcks) > 0 {
			step.Warnings = append(step.Warnings, "required acknowledgement fields are missing or false: "+strings.Join(step.MissingAcks, ", "))
		}
	}
	if step.WouldMutateCandidate {
		step.ExpectedRevision = candidateRevisionFromStep(step)
		if step.ExpectedRevision == "" {
			step.ExpectedRevision = state.ExpectedRevision
		}
		if requireRevision && strings.TrimSpace(step.ExpectedRevision) == "" {
			step.Warnings = append(step.Warnings, "candidate mutation is missing expectedCandidateRevision")
		}
		if state.CandidateRevision != "" && step.ExpectedRevision != "" && step.ExpectedRevision != state.CandidateRevision {
			step.Warnings = append(step.Warnings, "candidate revision does not match current candidate state")
		}
	}
	return step
}

func routeClass(path string) string {
	base := strings.Split(path, "?")[0]
	switch {
	case base == "/v1/candidate" || base == "/v1/candidate/status" || base == "/v1/candidate/validate":
		return "candidate"
	case base == "/v1/commit" || base == "/v1/rollback":
		return "running-policy"
	case strings.HasPrefix(base, "/v1/policy"):
		return "policy-read"
	case strings.HasPrefix(base, "/v1/explain/"):
		return "explain"
	case strings.HasPrefix(base, "/v1/alerts") || strings.HasPrefix(base, "/v1/flows") || strings.HasPrefix(base, "/v1/sessions") || strings.HasPrefix(base, "/v1/app-id/"):
		return "telemetry"
	case strings.HasPrefix(base, "/v1/system/packet-captures"):
		return "packet-capture"
	case strings.HasPrefix(base, "/v1/system/") || strings.HasPrefix(base, "/v1/auth/"):
		return "system"
	case strings.HasPrefix(base, "/v1/change-approvals"):
		return "change-approval"
	case strings.HasPrefix(base, "/v1/threat-exceptions"):
		return "threat-exception"
	case strings.HasPrefix(base, "/v1/fleet/") || strings.HasPrefix(base, "/v1/investigation/") || strings.HasPrefix(base, "/v1/compliance/"):
		return "custody"
	default:
		return "unknown"
	}
}

func appliesRunning(path string) bool {
	base := strings.Split(path, "?")[0]
	return base == "/v1/commit" || base == "/v1/rollback" || base == "/v1/system/packet-captures" || strings.Contains(base, ":verify") || strings.Contains(base, ":activate") || strings.Contains(base, ":pull") || base == "/v1/system/tune"
}

func mutatesCandidate(path string) bool {
	base := strings.Split(path, "?")[0]
	return base == "/v1/candidate" || strings.Contains(base, ":stage") || strings.HasPrefix(base, "/v1/threat-exceptions") || strings.Contains(base, ":apply-preview")
}

func readOnlyAction(path string) bool {
	base := strings.Split(path, "?")[0]
	return base == "/v1/candidate/validate" ||
		base == "/v1/explain/flow" ||
		base == "/v1/system/packet-captures/plan" ||
		base == "/v1/system/runtime-readiness:check" ||
		base == "/v1/system/network-path:prove" ||
		base == "/v1/system/automation/replay:validate" ||
		strings.HasSuffix(base, ":validate") ||
		strings.HasSuffix(base, ":preflight") ||
		strings.HasSuffix(base, ":restore-preview") ||
		strings.HasSuffix(base, ":apply-preview")
}

func requiredAcks(path string) []string {
	base := strings.Split(path, "?")[0]
	switch {
	case base == "/v1/commit" || base == "/v1/rollback":
		return []string{"ackRisk", "ackRuntime"}
	case base == "/v1/system/packet-captures":
		return []string{"ackCapture"}
	case base == "/v1/system/tune":
		return []string{"ackHostTuning"}
	case strings.Contains(base, "retention"):
		return []string{"ackRetentionChange"}
	case strings.Contains(base, "disable"):
		return []string{"ackDisableUser"}
	default:
		return nil
	}
}

func presentAcks(body map[string]any, required []string) []string {
	var present []string
	for _, key := range required {
		if boolValue(body[key]) {
			present = append(present, key)
		}
	}
	return present
}

func candidateRevisionFromStep(step Step) string {
	if v := stringValue(step.Body["expectedCandidateRevision"]); v != "" {
		return v
	}
	if v := stringValue(step.Body["expected_candidate_revision"]); v != "" {
		return v
	}
	return ""
}

func bodyMap(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err == nil {
		return body
	}
	return map[string]any{"_raw": string(raw)}
}

func normalizePath(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "\"'")
	if value == "" || strings.HasPrefix(value, "${") {
		return ""
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		if u, err := url.Parse(value); err == nil {
			value = u.EscapedPath()
			if u.RawQuery != "" {
				value += "?" + u.RawQuery
			}
		}
	}
	if !strings.HasPrefix(value, "/v1/") {
		if m := apiPathRE.FindString(value); m != "" {
			value = m
		}
	}
	if !strings.HasPrefix(value, "/v1/") {
		return ""
	}
	return value
}

func shellTokens(command string) []string {
	var out []string
	for _, match := range shellTokenRE.FindAllStringSubmatch(command, -1) {
		switch {
		case match[1] != "":
			out = append(out, strings.ReplaceAll(match[1], `\"`, `"`))
		case match[2] != "":
			out = append(out, match[2])
		default:
			out = append(out, match[3])
		}
	}
	return out
}

func missingStrings(required, present []string) []string {
	presentSet := map[string]bool{}
	for _, v := range present {
		presentSet[v] = true
	}
	var missing []string
	for _, v := range required {
		if !presentSet[v] {
			missing = append(missing, v)
		}
	}
	return missing
}

func warningCode(warning string) string {
	switch {
	case strings.Contains(warning, "unknown route"):
		return "UNKNOWN_ROUTE"
	case strings.Contains(warning, "live apply"):
		return "LIVE_APPLY_BLOCKED"
	case strings.Contains(warning, "candidate-only"):
		return "CANDIDATE_ONLY_AUTHORITY_REQUIRED"
	case strings.Contains(warning, "unsafe method"):
		return "UNSAFE_MUTATION"
	case strings.Contains(warning, "acknowledgement"):
		return "MISSING_ACKNOWLEDGEMENT"
	case strings.Contains(warning, "candidate revision"):
		return "CANDIDATE_REVISION_REQUIRED"
	default:
		return "REPLAY_WARNING"
	}
}

func issueSeverity(warning string) string {
	if strings.Contains(warning, "candidate-only") {
		return "warning"
	}
	if strings.Contains(warning, "live apply") || strings.Contains(warning, "unsafe method") || strings.Contains(warning, "acknowledgement") || strings.Contains(warning, "revision") || strings.Contains(warning, "unknown route") {
		return "error"
	}
	return "warning"
}

func presentAckMap(acks map[string]bool, required []string) []string {
	var present []string
	for _, key := range required {
		if acks[key] {
			present = append(present, key)
		}
	}
	return present
}

func boolValue(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		parsed, _ := strconv.ParseBool(v)
		return parsed
	default:
		return false
	}
}

func stringValue(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func truncate(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) <= max {
		return value
	}
	return value[:max]
}
