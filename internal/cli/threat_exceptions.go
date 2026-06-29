package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

type threatExceptionClient interface {
	ListThreatExceptions(context.Context, *openngfwv1.ListThreatExceptionsRequest, ...grpc.CallOption) (*openngfwv1.ListThreatExceptionsResponse, error)
	StageThreatException(context.Context, *openngfwv1.StageThreatExceptionRequest, ...grpc.CallOption) (*openngfwv1.StageThreatExceptionResponse, error)
	UpdateThreatException(context.Context, *openngfwv1.UpdateThreatExceptionRequest, ...grpc.CallOption) (*openngfwv1.UpdateThreatExceptionResponse, error)
	SetThreatExceptionState(context.Context, *openngfwv1.SetThreatExceptionStateRequest, ...grpc.CallOption) (*openngfwv1.SetThreatExceptionStateResponse, error)
	RemoveThreatException(context.Context, *openngfwv1.RemoveThreatExceptionRequest, ...grpc.CallOption) (*openngfwv1.RemoveThreatExceptionResponse, error)
}

type threatExceptionListOptions struct {
	source  string
	version uint64
	outJSON bool
}

type threatExceptionStageOptions struct {
	name          string
	signatureID   int64
	threatID      string
	threatName    string
	scope         string
	sourceIP      string
	destinationIP string
	reason        string
	confirmGlobal bool
	owner         string
	ticketID      string
	reviewDate    string
	expiresAt     string
	pcapSHA256    string
	regressionRef string
	outJSON       bool
}

type threatExceptionUpdateOptions struct {
	newName            string
	signatureIDSet     bool
	signatureID        int64
	threatID           string
	threatIDSet        bool
	scope              string
	scopeSet           bool
	sourceAddress      string
	destinationAddress string
	description        string
	descriptionSet     bool
	disabledSet        bool
	disabled           bool
	reason             string
	confirmGlobal      bool
	owner              string
	ownerSet           bool
	ticketID           string
	ticketIDSet        bool
	reviewDate         string
	reviewDateSet      bool
	expiresAt          string
	expiresAtSet       bool
	pcapSHA256         string
	pcapSHA256Set      bool
	regressionRef      string
	regressionRefSet   bool
	outJSON            bool
}

type threatExceptionStateOptions struct {
	reason        string
	confirmGlobal bool
	outJSON       bool
}

type threatExceptionRemoveOptions struct {
	reason  string
	outJSON bool
}

func newThreatExceptionsCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "threat-exceptions",
		Short: "Review and stage Threat-ID false-positive exception lifecycle changes",
		Long: "Review and stage Threat-ID false-positive exceptions in the candidate policy. " +
			"Lifecycle mutations are candidate-only until the normal validate and commit path succeeds.",
	}
	cmd.AddCommand(
		newThreatExceptionsListCommand(server),
		newThreatExceptionStageCommand(server),
		newThreatExceptionUpdateCommand(server),
		newThreatExceptionStateCommand(server, "disable", true),
		newThreatExceptionStateCommand(server, "enable", false),
		newThreatExceptionRemoveCommand(server),
	)
	return cmd
}

func newThreatExceptionsListCommand(server *string) *cobra.Command {
	opts := threatExceptionListOptions{}
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List Threat-ID false-positive exceptions",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runThreatExceptionsList(ctx, cmd, openngfwv1.NewThreatTuningServiceClient(conn), opts)
		},
	}
	cmd.Flags().StringVar(&opts.source, "source", "", "policy source: effective (default), running, candidate, or version")
	cmd.Flags().Uint64Var(&opts.version, "version", 0, "policy version when --source=version")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func newThreatExceptionStageCommand(server *string) *cobra.Command {
	opts := threatExceptionStageOptions{scope: "source"}
	cmd := &cobra.Command{
		Use:   "stage",
		Short: "Stage a new Threat-ID false-positive exception",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runThreatExceptionStage(ctx, cmd, openngfwv1.NewThreatTuningServiceClient(conn), opts)
		},
	}
	addThreatExceptionMetadataFlags(cmd, &opts.owner, &opts.ticketID, &opts.reviewDate, &opts.expiresAt, &opts.pcapSHA256, &opts.regressionRef)
	cmd.Flags().StringVar(&opts.name, "name", "", "optional exception object name")
	cmd.Flags().Int64Var(&opts.signatureID, "signature-id", 0, "required Suricata signature ID")
	cmd.Flags().StringVar(&opts.threatID, "threat-id", "", "Phragma Threat-ID metadata")
	cmd.Flags().StringVar(&opts.threatName, "threat-name", "", "operator-facing threat name")
	cmd.Flags().StringVar(&opts.scope, "scope", opts.scope, "exception scope: source, destination, or global")
	cmd.Flags().StringVar(&opts.sourceIP, "src-ip", "", "source IP for source-scoped staging")
	cmd.Flags().StringVar(&opts.destinationIP, "dest-ip", "", "destination IP for destination-scoped staging")
	cmd.Flags().StringVarP(&opts.reason, "reason", "m", "", "required audit reason")
	cmd.Flags().BoolVar(&opts.confirmGlobal, "confirm-global", false, "acknowledge active global signature suppression")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func newThreatExceptionUpdateCommand(server *string) *cobra.Command {
	opts := threatExceptionUpdateOptions{scope: "global"}
	cmd := &cobra.Command{
		Use:   "update NAME",
		Short: "Replace one staged Threat-ID exception object",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runThreatExceptionUpdate(ctx, cmd, openngfwv1.NewThreatTuningServiceClient(conn), args[0], opts)
		},
	}
	addThreatExceptionMetadataFlags(cmd, &opts.owner, &opts.ticketID, &opts.reviewDate, &opts.expiresAt, &opts.pcapSHA256, &opts.regressionRef)
	cmd.Flags().StringVar(&opts.newName, "new-name", "", "replacement exception name (defaults to NAME)")
	cmd.Flags().Int64Var(&opts.signatureID, "signature-id", 0, "required Suricata signature ID")
	cmd.Flags().StringVar(&opts.threatID, "threat-id", "", "Phragma Threat-ID metadata")
	cmd.Flags().StringVar(&opts.scope, "scope", opts.scope, "replacement scope: source, destination, or global")
	cmd.Flags().StringVar(&opts.sourceAddress, "source-address", "", "source Address object name for source scope")
	cmd.Flags().StringVar(&opts.destinationAddress, "destination-address", "", "destination Address object name for destination scope")
	cmd.Flags().StringVar(&opts.description, "description", "", "replacement exception description")
	cmd.Flags().BoolVar(&opts.disabled, "disabled", false, "stage replacement in disabled state")
	cmd.Flags().StringVarP(&opts.reason, "reason", "m", "", "required audit reason")
	cmd.Flags().BoolVar(&opts.confirmGlobal, "confirm-global", false, "acknowledge active global signature suppression")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	recordThreatExceptionUpdateFlagChanges(cmd, &opts)
	return cmd
}

func newThreatExceptionStateCommand(server *string, action string, disabled bool) *cobra.Command {
	opts := threatExceptionStateOptions{}
	titleAction := action
	if titleAction != "" {
		titleAction = strings.ToUpper(titleAction[:1]) + titleAction[1:]
	}
	cmd := &cobra.Command{
		Use:   action + " NAME",
		Short: titleAction + " one Threat-ID exception in the candidate policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runThreatExceptionState(ctx, cmd, openngfwv1.NewThreatTuningServiceClient(conn), args[0], disabled, opts)
		},
	}
	cmd.Flags().StringVarP(&opts.reason, "reason", "m", "", "required audit reason")
	cmd.Flags().BoolVar(&opts.confirmGlobal, "confirm-global", false, "acknowledge re-enabling an active global signature suppression")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func newThreatExceptionRemoveCommand(server *string) *cobra.Command {
	opts := threatExceptionRemoveOptions{}
	cmd := &cobra.Command{
		Use:   "remove NAME",
		Short: "Remove one Threat-ID exception from the candidate policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			return runThreatExceptionRemove(ctx, cmd, openngfwv1.NewThreatTuningServiceClient(conn), args[0], opts)
		},
	}
	cmd.Flags().StringVarP(&opts.reason, "reason", "m", "", "required audit reason")
	cmd.Flags().BoolVar(&opts.outJSON, "json", false, "output JSON")
	return cmd
}

func addThreatExceptionMetadataFlags(cmd *cobra.Command, owner, ticketID, reviewDate, expiresAt, pcapSHA256, regressionRef *string) {
	cmd.Flags().StringVar(owner, "owner", "", "operator or team responsible for review")
	cmd.Flags().StringVar(ticketID, "ticket-id", "", "change, incident, or CAB reference")
	cmd.Flags().StringVar(reviewDate, "review-date", "", "review date YYYY-MM-DD")
	cmd.Flags().StringVar(expiresAt, "expires-at", "", "expiration date YYYY-MM-DD")
	cmd.Flags().StringVar(pcapSHA256, "pcap-sha256", "", "representative PCAP SHA-256")
	cmd.Flags().StringVar(regressionRef, "regression-ref", "", "package-local regression evidence reference")
}

func recordThreatExceptionUpdateFlagChanges(cmd *cobra.Command, opts *threatExceptionUpdateOptions) {
	cmd.PreRun = func(cmd *cobra.Command, _ []string) {
		opts.signatureIDSet = cmd.Flags().Changed("signature-id")
		opts.threatIDSet = cmd.Flags().Changed("threat-id")
		opts.scopeSet = cmd.Flags().Changed("scope")
		opts.descriptionSet = cmd.Flags().Changed("description")
		opts.disabledSet = cmd.Flags().Changed("disabled")
		opts.ownerSet = cmd.Flags().Changed("owner")
		opts.ticketIDSet = cmd.Flags().Changed("ticket-id")
		opts.reviewDateSet = cmd.Flags().Changed("review-date")
		opts.expiresAtSet = cmd.Flags().Changed("expires-at")
		opts.pcapSHA256Set = cmd.Flags().Changed("pcap-sha256")
		opts.regressionRefSet = cmd.Flags().Changed("regression-ref")
	}
}

func runThreatExceptionsList(ctx context.Context, cmd *cobra.Command, client threatExceptionClient, opts threatExceptionListOptions) error {
	source, err := threatExceptionListSource(opts.source)
	if err != nil {
		return err
	}
	if source == openngfwv1.PolicySource_POLICY_SOURCE_VERSION && opts.version == 0 {
		return fmt.Errorf("--version is required when --source=version")
	}
	resp, err := client.ListThreatExceptions(ctx, &openngfwv1.ListThreatExceptionsRequest{Source: source, Version: opts.version})
	if err != nil {
		return fmt.Errorf("list threat exceptions: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printThreatExceptions(cmd, resp)
	return nil
}

func runThreatExceptionStage(ctx context.Context, cmd *cobra.Command, client threatExceptionClient, opts threatExceptionStageOptions) error {
	if opts.signatureID <= 0 {
		return fmt.Errorf("--signature-id is required")
	}
	if strings.TrimSpace(opts.reason) == "" {
		return fmt.Errorf("--reason is required")
	}
	scope, err := parseThreatExceptionScope(opts.scope)
	if err != nil {
		return err
	}
	req := &openngfwv1.StageThreatExceptionRequest{
		Name:          strings.TrimSpace(opts.name),
		ThreatId:      strings.TrimSpace(opts.threatID),
		ThreatName:    strings.TrimSpace(opts.threatName),
		EngineSignals: []*openngfwv1.ThreatEngineSignal{{Engine: "suricata", Kind: "signature_id", Value: strconv.FormatInt(opts.signatureID, 10)}},
		Scope:         scope,
		SourceIp:      strings.TrimSpace(opts.sourceIP),
		DestinationIp: strings.TrimSpace(opts.destinationIP),
		Reason:        strings.TrimSpace(opts.reason),
		ConfirmGlobal: opts.confirmGlobal,
		Owner:         strings.TrimSpace(opts.owner),
		TicketId:      strings.TrimSpace(opts.ticketID),
		ReviewDate:    strings.TrimSpace(opts.reviewDate),
		ExpiresAt:     strings.TrimSpace(opts.expiresAt),
		PcapSha256:    strings.TrimSpace(opts.pcapSHA256),
		RegressionRef: strings.TrimSpace(opts.regressionRef),
	}
	if err := validateThreatExceptionStageScope(req); err != nil {
		return err
	}
	resp, err := client.StageThreatException(ctx, req)
	if err != nil {
		return fmt.Errorf("stage threat exception: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printThreatExceptionMutation(cmd, "staged", resp.GetException(), resp.GetCandidateStatus(), resp.GetValidation())
	return threatExceptionValidationError("threat exception staging", resp.GetValidation())
}

func runThreatExceptionUpdate(ctx context.Context, cmd *cobra.Command, client threatExceptionClient, name string, opts threatExceptionUpdateOptions) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("NAME is required")
	}
	if strings.TrimSpace(opts.reason) == "" {
		return fmt.Errorf("--reason is required")
	}
	current, err := loadThreatExceptionForUpdate(ctx, client, name)
	if err != nil {
		return err
	}
	ex, err := replacementThreatException(current, opts)
	if err != nil {
		return err
	}
	req := &openngfwv1.UpdateThreatExceptionRequest{
		Name:          strings.TrimSpace(name),
		Exception:     ex,
		Reason:        strings.TrimSpace(opts.reason),
		ConfirmGlobal: opts.confirmGlobal,
	}
	resp, err := client.UpdateThreatException(ctx, req)
	if err != nil {
		return fmt.Errorf("update threat exception: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printThreatExceptionMutation(cmd, "updated", resp.GetException(), resp.GetCandidateStatus(), resp.GetValidation())
	return threatExceptionValidationError("threat exception update", resp.GetValidation())
}

func runThreatExceptionState(ctx context.Context, cmd *cobra.Command, client threatExceptionClient, name string, disabled bool, opts threatExceptionStateOptions) error {
	if strings.TrimSpace(opts.reason) == "" {
		return fmt.Errorf("--reason is required")
	}
	resp, err := client.SetThreatExceptionState(ctx, &openngfwv1.SetThreatExceptionStateRequest{
		Name:          strings.TrimSpace(name),
		Disabled:      disabled,
		Reason:        strings.TrimSpace(opts.reason),
		ConfirmGlobal: opts.confirmGlobal,
	})
	if err != nil {
		return fmt.Errorf("set threat exception state: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	action := "enabled"
	if disabled {
		action = "disabled"
	}
	printThreatExceptionMutation(cmd, action, resp.GetException(), resp.GetCandidateStatus(), resp.GetValidation())
	return threatExceptionValidationError("threat exception state change", resp.GetValidation())
}

func runThreatExceptionRemove(ctx context.Context, cmd *cobra.Command, client threatExceptionClient, name string, opts threatExceptionRemoveOptions) error {
	if strings.TrimSpace(opts.reason) == "" {
		return fmt.Errorf("--reason is required")
	}
	resp, err := client.RemoveThreatException(ctx, &openngfwv1.RemoveThreatExceptionRequest{
		Name:   strings.TrimSpace(name),
		Reason: strings.TrimSpace(opts.reason),
	})
	if err != nil {
		return fmt.Errorf("remove threat exception: %w", err)
	}
	if opts.outJSON {
		return printProtoJSON(cmd, resp)
	}
	printThreatExceptionMutation(cmd, "removed", resp.GetPreviousException(), resp.GetCandidateStatus(), resp.GetValidation())
	return threatExceptionValidationError("threat exception removal", resp.GetValidation())
}

func threatExceptionListSource(raw string) (openngfwv1.PolicySource, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" || raw == "effective" {
		return openngfwv1.PolicySource_POLICY_SOURCE_UNSPECIFIED, nil
	}
	return parsePolicySource(raw)
}

func parseThreatExceptionScope(raw string) (openngfwv1.ThreatExceptionScope, error) {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "source":
		return openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_SOURCE, nil
	case "destination":
		return openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_DESTINATION, nil
	case "global":
		return openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_GLOBAL, nil
	default:
		return openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_UNSPECIFIED, fmt.Errorf("--scope must be source, destination, or global")
	}
}

func validateThreatExceptionStageScope(req *openngfwv1.StageThreatExceptionRequest) error {
	switch req.GetScope() {
	case openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_SOURCE:
		if strings.TrimSpace(req.GetSourceIp()) == "" {
			return fmt.Errorf("--src-ip is required when --scope=source")
		}
	case openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_DESTINATION:
		if strings.TrimSpace(req.GetDestinationIp()) == "" {
			return fmt.Errorf("--dest-ip is required when --scope=destination")
		}
	case openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_GLOBAL:
		if !req.GetConfirmGlobal() {
			return fmt.Errorf("--confirm-global is required when --scope=global")
		}
	}
	return nil
}

func loadThreatExceptionForUpdate(ctx context.Context, client threatExceptionClient, name string) (*openngfwv1.IdsException, error) {
	name = strings.TrimSpace(name)
	resp, err := client.ListThreatExceptions(ctx, &openngfwv1.ListThreatExceptionsRequest{})
	if err != nil {
		return nil, fmt.Errorf("load current threat exception %q: %w", name, err)
	}
	for _, record := range resp.GetExceptions() {
		if record.GetException().GetName() == name {
			return proto.Clone(record.GetException()).(*openngfwv1.IdsException), nil
		}
	}
	return nil, fmt.Errorf("threat exception %q not found", name)
}

func replacementThreatException(current *openngfwv1.IdsException, opts threatExceptionUpdateOptions) (*openngfwv1.IdsException, error) {
	ex := proto.Clone(current).(*openngfwv1.IdsException)
	if strings.TrimSpace(opts.newName) != "" {
		ex.Name = strings.TrimSpace(opts.newName)
	}
	if opts.signatureIDSet {
		if opts.signatureID <= 0 {
			return nil, fmt.Errorf("--signature-id must be greater than zero")
		}
		ex.SignatureId = opts.signatureID
	}
	if opts.threatIDSet {
		ex.ThreatId = strings.TrimSpace(opts.threatID)
	}
	if opts.descriptionSet {
		ex.Description = strings.TrimSpace(opts.description)
	}
	if opts.disabledSet {
		ex.Disabled = opts.disabled
	}
	if opts.ownerSet {
		ex.Owner = strings.TrimSpace(opts.owner)
	}
	if opts.ticketIDSet {
		ex.TicketId = strings.TrimSpace(opts.ticketID)
	}
	if opts.reviewDateSet {
		ex.ReviewDate = strings.TrimSpace(opts.reviewDate)
	}
	if opts.expiresAtSet {
		ex.ExpiresAt = strings.TrimSpace(opts.expiresAt)
	}
	if opts.pcapSHA256Set {
		ex.PcapSha256 = strings.TrimSpace(opts.pcapSHA256)
	}
	if opts.regressionRefSet {
		ex.RegressionRef = strings.TrimSpace(opts.regressionRef)
	}
	if opts.scopeSet {
		scope, err := parseThreatExceptionScope(opts.scope)
		if err != nil {
			return nil, err
		}
		ex.SourceAddress = ""
		ex.DestinationAddress = ""
		switch scope {
		case openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_SOURCE:
			ex.SourceAddress = strings.TrimSpace(opts.sourceAddress)
			if ex.SourceAddress == "" {
				return nil, fmt.Errorf("--source-address is required when --scope=source")
			}
		case openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_DESTINATION:
			ex.DestinationAddress = strings.TrimSpace(opts.destinationAddress)
			if ex.DestinationAddress == "" {
				return nil, fmt.Errorf("--destination-address is required when --scope=destination")
			}
		case openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_GLOBAL:
			if !ex.GetDisabled() && !opts.confirmGlobal {
				return nil, fmt.Errorf("--confirm-global is required when --scope=global and exception is active")
			}
		}
	} else if !ex.GetDisabled() && ex.GetSourceAddress() == "" && ex.GetDestinationAddress() == "" && !opts.confirmGlobal {
		return nil, fmt.Errorf("--confirm-global is required when updating an active global threat exception")
	}
	if ex.Description == "" {
		ex.Description = strings.TrimSpace(opts.reason)
	}
	return ex, nil
}

func printThreatExceptions(cmd *cobra.Command, resp *openngfwv1.ListThreatExceptionsResponse) {
	cmd.Println("Threat-ID exceptions")
	if resp == nil || len(resp.GetExceptions()) == 0 {
		cmd.Println("no threat exceptions")
		return
	}
	cmd.Printf("source: %s", shortEnum(resp.GetSource().String(), "POLICY_SOURCE_"))
	if resp.GetVersion() > 0 {
		cmd.Printf(" version=%d", resp.GetVersion())
	}
	cmd.Println()
	for _, record := range resp.GetExceptions() {
		ex := record.GetException()
		cmd.Printf("%-28s %-10s %-18s sid=%d threat=%s state=%s\n",
			valueOrDash(ex.GetName()),
			threatExceptionEnabledLabel(ex),
			threatExceptionScopeLabel(record.GetScope(), ex),
			ex.GetSignatureId(),
			valueOrDash(ex.GetThreatId()),
			threatExceptionRecordState(record))
	}
}

func printThreatExceptionMutation(cmd *cobra.Command, action string, ex *openngfwv1.IdsException, status *openngfwv1.GetCandidateStatusResponse, validation *openngfwv1.ValidateResponse) {
	cmd.Printf("threat exception %s: %s\n", action, valueOrDash(ex.GetName()))
	cmd.Printf("scope: %s  sid=%d  threat=%s  state=%s\n", threatExceptionScopeLabel(openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_UNSPECIFIED, ex), ex.GetSignatureId(), valueOrDash(ex.GetThreatId()), threatExceptionEnabledLabel(ex))
	if validation != nil {
		cmd.Printf("validation: %s\n", validationStateLabel(validation))
	}
	if status != nil {
		cmd.Printf("candidate: dirty=%t changes=%d\n", status.GetDirty(), status.GetChangeCount())
	}
	cmd.Println("candidate-only: review with `ngfwctl policy validate` and `ngfwctl policy diff`, then commit when approved.")
}

func threatExceptionEnabledLabel(ex *openngfwv1.IdsException) string {
	if ex.GetDisabled() {
		return "disabled"
	}
	return "active"
}

func threatExceptionScopeLabel(scope openngfwv1.ThreatExceptionScope, ex *openngfwv1.IdsException) string {
	if scope == openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_SOURCE || ex.GetSourceAddress() != "" {
		return "source:" + valueOrDash(ex.GetSourceAddress())
	}
	if scope == openngfwv1.ThreatExceptionScope_THREAT_EXCEPTION_SCOPE_DESTINATION || ex.GetDestinationAddress() != "" {
		return "destination:" + valueOrDash(ex.GetDestinationAddress())
	}
	return "global"
}

func threatExceptionRecordState(record *openngfwv1.ThreatExceptionRecord) string {
	if record.GetCandidateOnly() {
		return "candidate-only"
	}
	if record.GetChangedFromRunning() {
		return "candidate-edit"
	}
	if record.GetPresentInRunning() {
		return "running"
	}
	return "candidate"
}

func validationStateLabel(resp *openngfwv1.ValidateResponse) string {
	if resp.GetValid() {
		return "valid"
	}
	return fmt.Sprintf("invalid (%d errors)", len(validationErrors(resp)))
}

func threatExceptionValidationError(action string, validation *openngfwv1.ValidateResponse) error {
	if validation != nil && !validation.GetValid() {
		return fmt.Errorf("%s candidate is invalid (%d errors)", action, len(validationErrors(validation)))
	}
	return nil
}
