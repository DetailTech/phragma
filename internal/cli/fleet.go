package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

const defaultFleetGatewayPort = "8080"

type fleetHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type fleetClient struct {
	baseURL    string
	token      string
	httpClient fleetHTTPClient
}

type fleetCommandOptions struct {
	gateway          string
	insecureTLS      bool
	expectedRevision string
	comment          string
	peers            []string
	outJSON          bool
}

type fleetTemplateCreateOptions struct {
	name        string
	description string
	scope       string
	labels      []string
	policyFile  string
	outJSON     bool
}

func newFleetCommand(server *string) *cobra.Command {
	opts := fleetCommandOptions{}
	cmd := &cobra.Command{
		Use:   "fleet",
		Short: "Operate bounded local-appliance fleet inventory and templates",
		Long: "Operate the current bounded Fleet/HA surface for the connected local appliance. " +
			"These commands do not enroll peers, fan out applies, control HA traffic, or retain distributed result custody.",
	}
	cmd.PersistentFlags().StringVar(&opts.gateway, "gateway", "", "REST gateway base URL (default: derive http://<server-host>:8080 from --server)")
	cmd.PersistentFlags().BoolVar(&opts.insecureTLS, "gateway-insecure-tls", false, "skip REST gateway TLS verification for self-signed lab certificates")
	cmd.AddCommand(
		newFleetNodesCommand(server, &opts),
		newFleetTemplatesCommand(server, &opts),
	)
	return cmd
}

func newFleetNodesCommand(server *string, opts *fleetCommandOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nodes",
		Short: "List connected local-appliance fleet node state",
	}
	cmd.AddCommand(newFleetNodesListCommand(server, opts))
	return cmd
}

func newFleetNodesListCommand(server *string, opts *fleetCommandOptions) *cobra.Command {
	var outJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the connected local appliance as the bounded fleet node",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := newFleetClient(*server, opts.gateway, opts.insecureTLS)
			if err != nil {
				return err
			}
			return runFleetNodesList(cmd.Context(), cmd, client, outJSON)
		},
	}
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

func newFleetTemplatesCommand(server *string, opts *fleetCommandOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "templates",
		Short: "List, create, inspect, validate, preview, and stage local fleet templates",
	}
	cmd.AddCommand(
		newFleetTemplatesListCommand(server, opts),
		newFleetTemplatesGetCommand(server, opts),
		newFleetTemplatesCreateCommand(server, opts),
		newFleetTemplatesValidateCommand(server, opts),
		newFleetTemplatesApplyPreviewCommand(server, opts),
		newFleetTemplatesApplyPlanCommand(server, opts),
		newFleetTemplatesApplyCommand(server, opts),
		newFleetTemplatesResultsCommand(server, opts),
		newFleetTemplatesStageCandidateCommand(server, opts),
	)
	return cmd
}

func newFleetTemplatesListCommand(server *string, opts *fleetCommandOptions) *cobra.Command {
	var outJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List local fleet policy templates",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := newFleetClient(*server, opts.gateway, opts.insecureTLS)
			if err != nil {
				return err
			}
			return runFleetTemplatesList(cmd.Context(), cmd, client, outJSON)
		},
	}
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

func newFleetTemplatesGetCommand(server *string, opts *fleetCommandOptions) *cobra.Command {
	var outJSON bool
	cmd := &cobra.Command{
		Use:   "get TEMPLATE_ID",
		Short: "Show one local fleet policy template from the template list API",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newFleetClient(*server, opts.gateway, opts.insecureTLS)
			if err != nil {
				return err
			}
			return runFleetTemplatesGet(cmd.Context(), cmd, client, args[0], outJSON)
		},
	}
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

func newFleetTemplatesCreateCommand(server *string, opts *fleetCommandOptions) *cobra.Command {
	create := fleetTemplateCreateOptions{scope: "local-appliance"}
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a local fleet policy template from a YAML/JSON policy file",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := newFleetClient(*server, opts.gateway, opts.insecureTLS)
			if err != nil {
				return err
			}
			return runFleetTemplatesCreate(cmd.Context(), cmd, client, create)
		},
	}
	cmd.Flags().StringVar(&create.name, "name", "", "template name")
	cmd.Flags().StringVar(&create.description, "description", "", "template description")
	cmd.Flags().StringVar(&create.scope, "scope", create.scope, "template scope")
	cmd.Flags().StringArrayVar(&create.labels, "label", nil, "template label; repeat for multiple labels")
	cmd.Flags().StringVarP(&create.policyFile, "file", "f", "", "policy file (YAML or JSON)")
	cmd.Flags().BoolVar(&create.outJSON, "json", false, "output JSON")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func newFleetTemplatesValidateCommand(server *string, opts *fleetCommandOptions) *cobra.Command {
	var outJSON bool
	cmd := &cobra.Command{
		Use:   "validate TEMPLATE_ID",
		Short: "Validate a local fleet template policy without mutating candidate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newFleetClient(*server, opts.gateway, opts.insecureTLS)
			if err != nil {
				return err
			}
			return runFleetTemplatesValidate(cmd.Context(), cmd, client, args[0], outJSON)
		},
	}
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

func newFleetTemplatesApplyPreviewCommand(server *string, opts *fleetCommandOptions) *cobra.Command {
	preview := fleetCommandOptions{}
	cmd := &cobra.Command{
		Use:   "apply-preview TEMPLATE_ID",
		Short: "Preview local candidate impact for a fleet template without mutating candidate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newFleetClient(*server, opts.gateway, opts.insecureTLS)
			if err != nil {
				return err
			}
			return runFleetTemplatesApplyPreview(cmd.Context(), cmd, client, args[0], preview)
		},
	}
	cmd.Flags().StringVar(&preview.expectedRevision, "expected-candidate-revision", "", "candidate revision from 'ngfwctl policy status --json' to guard preview freshness")
	cmd.Flags().BoolVar(&preview.outJSON, "json", false, "output JSON")
	return cmd
}

func newFleetTemplatesApplyPlanCommand(server *string, opts *fleetCommandOptions) *cobra.Command {
	plan := fleetCommandOptions{}
	cmd := &cobra.Command{
		Use:   "apply-plan TEMPLATE_ID",
		Short: "Build a bounded multi-node template apply plan without peer RPC or running apply",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newFleetClient(*server, opts.gateway, opts.insecureTLS)
			if err != nil {
				return err
			}
			return runFleetTemplatesApplyPlan(cmd.Context(), cmd, client, args[0], plan)
		},
	}
	cmd.Flags().StringVar(&plan.expectedRevision, "expected-candidate-revision", "", "candidate revision from 'ngfwctl policy status --json' to guard apply-plan freshness")
	cmd.Flags().StringArrayVar(&plan.peers, "peer", nil, "peer inventory as id=<id>,name=<name>,role=<role>,runtime=<ready|healthy|active>,running=<version>,haReady=<true|false>; repeat for multiple peers")
	cmd.Flags().BoolVar(&plan.outJSON, "json", false, "output JSON")
	return cmd
}

func newFleetTemplatesApplyCommand(server *string, opts *fleetCommandOptions) *cobra.Command {
	apply := fleetCommandOptions{}
	cmd := &cobra.Command{
		Use:   "apply TEMPLATE_ID",
		Short: "Apply a fleet template to the local candidate and retain bounded per-peer results",
		Long: "Apply a Fleet template to the local candidate with a candidate revision guard, then retain explicit per-peer result records. " +
			"Peer inventory is recorded as skipped or blocked; this command does not call peer RPC, apply running policy, or claim signed distributed custody.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newFleetClient(*server, opts.gateway, opts.insecureTLS)
			if err != nil {
				return err
			}
			return runFleetTemplatesApply(cmd.Context(), cmd, client, args[0], apply)
		},
	}
	cmd.Flags().StringVar(&apply.expectedRevision, "expected-candidate-revision", "", "required candidate revision from 'ngfwctl policy status --json'")
	cmd.Flags().StringVarP(&apply.comment, "message", "m", "", "required apply custody comment")
	cmd.Flags().StringArrayVar(&apply.peers, "peer", nil, "peer inventory as id=<id>,name=<name>,role=<role>,runtime=<ready|healthy|active>,running=<version>,haReady=<true|false>; repeat for multiple peers")
	cmd.Flags().BoolVar(&apply.outJSON, "json", false, "output JSON")
	_ = cmd.MarkFlagRequired("expected-candidate-revision")
	_ = cmd.MarkFlagRequired("message")
	return cmd
}

func newFleetTemplatesResultsCommand(server *string, opts *fleetCommandOptions) *cobra.Command {
	var templateID string
	var outJSON bool
	cmd := &cobra.Command{
		Use:   "results",
		Short: "List retained Fleet template apply results",
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := newFleetClient(*server, opts.gateway, opts.insecureTLS)
			if err != nil {
				return err
			}
			return runFleetTemplateResults(cmd.Context(), cmd, client, templateID, outJSON)
		},
	}
	cmd.Flags().StringVar(&templateID, "template", "", "filter results by template id")
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON")
	return cmd
}

func newFleetTemplatesStageCandidateCommand(server *string, opts *fleetCommandOptions) *cobra.Command {
	stage := fleetCommandOptions{}
	cmd := &cobra.Command{
		Use:   "stage-candidate TEMPLATE_ID",
		Short: "Stage a local fleet template as the candidate policy with a revision guard",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newFleetClient(*server, opts.gateway, opts.insecureTLS)
			if err != nil {
				return err
			}
			return runFleetTemplatesStageCandidate(cmd.Context(), cmd, client, args[0], stage)
		},
	}
	cmd.Flags().StringVar(&stage.expectedRevision, "expected-candidate-revision", "", "required candidate revision from 'ngfwctl policy status --json'")
	cmd.Flags().StringVarP(&stage.comment, "message", "m", "", "required audit comment for staging the template")
	cmd.Flags().BoolVar(&stage.outJSON, "json", false, "output JSON")
	_ = cmd.MarkFlagRequired("expected-candidate-revision")
	_ = cmd.MarkFlagRequired("message")
	return cmd
}

func newFleetClient(server, gateway string, insecureTLS bool) (*fleetClient, error) {
	baseURL, err := fleetGatewayURL(server, gateway)
	if err != nil {
		return nil, err
	}
	token, err := resolveAPIToken()
	if err != nil {
		return nil, err
	}
	if err := validateFleetTokenTransport(baseURL, token); err != nil {
		return nil, err
	}
	transport := http.DefaultTransport
	if insecureTLS {
		transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // explicit operator flag for self-signed lab gateways
	}
	return &fleetClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}, nil
}

func fleetGatewayURL(server, explicit string) (string, error) {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		u, err := url.Parse(explicit)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return "", fmt.Errorf("--gateway must be an absolute http(s) URL")
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return "", fmt.Errorf("--gateway scheme must be http or https")
		}
		return strings.TrimRight(u.String(), "/"), nil
	}
	host := "127.0.0.1"
	if h, ok := targetHost(server); ok && h != "" {
		host = h
	}
	return "http://" + net.JoinHostPort(host, defaultFleetGatewayPort), nil
}

func validateFleetTokenTransport(baseURL, token string) error {
	if token == "" || allowInsecureTokenTransport {
		return nil
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("parse fleet gateway URL: %w", err)
	}
	if u.Scheme == "https" || isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("refusing to send bearer token over insecure HTTP to non-loopback gateway %q; use HTTPS, loopback, or --allow-insecure-token if you accept the risk", baseURL)
}

func (c *fleetClient) get(ctx context.Context, endpoint string) (map[string]any, error) {
	return c.do(ctx, http.MethodGet, endpoint, nil)
}

func (c *fleetClient) post(ctx context.Context, endpoint string, body any) (map[string]any, error) {
	return c.do(ctx, http.MethodPost, endpoint, body)
}

func (c *fleetClient) do(ctx context.Context, method, endpoint string, body any) (map[string]any, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal fleet request: %w", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path.Clean("/"+strings.TrimLeft(endpoint, "/")), reader)
	if err != nil {
		return nil, fmt.Errorf("build fleet request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call fleet API %s %s: %w", method, endpoint, err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	closeErr := resp.Body.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read fleet API response: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close fleet API response: %w", closeErr)
	}
	var decoded map[string]any
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return nil, fmt.Errorf("decode fleet API response status=%d: %w", resp.StatusCode, err)
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fleetAPIError(resp.StatusCode, decoded)
	}
	if decoded == nil {
		decoded = map[string]any{}
	}
	return decoded, nil
}

func fleetAPIError(statusCode int, body map[string]any) error {
	code, message := "", ""
	if errMap, ok := body["error"].(map[string]any); ok {
		code, _ = errMap["code"].(string)
		message, _ = errMap["message"].(string)
	}
	if message == "" {
		message = http.StatusText(statusCode)
	}
	if code != "" {
		return fmt.Errorf("fleet API status %d %s: %s", statusCode, code, message)
	}
	return fmt.Errorf("fleet API status %d: %s", statusCode, message)
}

func runFleetNodesList(ctx context.Context, cmd *cobra.Command, client *fleetClient, outJSON bool) error {
	body, err := client.get(ctx, "/v1/fleet/nodes")
	if err != nil {
		return err
	}
	if outJSON {
		return printJSONMap(cmd, body)
	}
	nodes, _ := body["nodes"].([]any)
	if len(nodes) == 0 {
		cmd.Println("no fleet nodes")
		return nil
	}
	cmd.Println("fleet nodes")
	for _, item := range nodes {
		node, _ := item.(map[string]any)
		cmd.Printf("%s  name=%s role=%s state=%s running=v%s authoritative=%s\n",
			jsonString(node, "id"),
			valueOrDash(jsonString(node, "name")),
			valueOrDash(jsonString(node, "role")),
			valueOrDash(firstNonEmpty(jsonString(node, "haState"), jsonString(node, "runtimeState"))),
			valueOrDash(jsonValueString(node["runningVersion"])),
			yesNo(jsonBool(node, "authoritative")),
		)
	}
	printFleetBoundaries(cmd, body)
	return nil
}

func runFleetTemplatesList(ctx context.Context, cmd *cobra.Command, client *fleetClient, outJSON bool) error {
	body, err := client.get(ctx, "/v1/fleet/templates")
	if err != nil {
		return err
	}
	if outJSON {
		return printJSONMap(cmd, body)
	}
	templates := fleetTemplates(body)
	if len(templates) == 0 {
		cmd.Println("no fleet templates")
		return nil
	}
	cmd.Println("fleet templates")
	for _, template := range templates {
		printFleetTemplateLine(cmd, template)
	}
	printFleetBoundaries(cmd, body)
	return nil
}

func runFleetTemplatesGet(ctx context.Context, cmd *cobra.Command, client *fleetClient, id string, outJSON bool) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("template id is required")
	}
	body, err := client.get(ctx, "/v1/fleet/templates")
	if err != nil {
		return err
	}
	for _, template := range fleetTemplates(body) {
		if jsonString(template, "id") == id {
			if outJSON {
				return printJSONMap(cmd, map[string]any{"template": template})
			}
			printFleetTemplateDetail(cmd, template)
			return nil
		}
	}
	return fmt.Errorf("fleet template %q not found", id)
}

func runFleetTemplatesCreate(ctx context.Context, cmd *cobra.Command, client *fleetClient, opts fleetTemplateCreateOptions) error {
	req, err := fleetTemplateCreateRequest(opts)
	if err != nil {
		return err
	}
	body, err := client.post(ctx, "/v1/fleet/templates", req)
	if err != nil {
		return err
	}
	if opts.outJSON {
		return printJSONMap(cmd, body)
	}
	cmd.Println("created fleet template")
	if template, _ := body["template"].(map[string]any); template != nil {
		printFleetTemplateDetail(cmd, template)
	}
	return nil
}

func fleetTemplateCreateRequest(opts fleetTemplateCreateOptions) (map[string]any, error) {
	name := strings.TrimSpace(opts.name)
	if name == "" {
		return nil, fmt.Errorf("--name is required")
	}
	file := strings.TrimSpace(opts.policyFile)
	if file == "" {
		return nil, fmt.Errorf("--file is required")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read policy file %s: %w", file, err)
	}
	policyJSON, err := yaml.YAMLToJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("parse policy file %s: %w", file, err)
	}
	var policy any
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		return nil, fmt.Errorf("policy schema JSON in %s: %w", file, err)
	}
	return map[string]any{
		"name":        name,
		"description": strings.TrimSpace(opts.description),
		"scope":       strings.TrimSpace(opts.scope),
		"labels":      cleanFleetLabels(opts.labels),
		"policy":      policy,
	}, nil
}

func runFleetTemplatesValidate(ctx context.Context, cmd *cobra.Command, client *fleetClient, id string, outJSON bool) error {
	body, err := client.post(ctx, "/v1/fleet/templates/"+url.PathEscape(strings.TrimSpace(id))+":validate", map[string]any{})
	if err != nil {
		return err
	}
	if outJSON {
		return printJSONMap(cmd, body)
	}
	printFleetTemplateOperation(cmd, "fleet template validation", body)
	return nil
}

func runFleetTemplatesApplyPreview(ctx context.Context, cmd *cobra.Command, client *fleetClient, id string, opts fleetCommandOptions) error {
	body, err := client.post(ctx, "/v1/fleet/templates/"+url.PathEscape(strings.TrimSpace(id))+":apply-preview", map[string]any{
		"expectedCandidateRevision": strings.TrimSpace(opts.expectedRevision),
	})
	if err != nil {
		return err
	}
	if opts.outJSON {
		return printJSONMap(cmd, body)
	}
	printFleetTemplateOperation(cmd, "fleet template apply preview", body)
	return nil
}

func runFleetTemplatesApplyPlan(ctx context.Context, cmd *cobra.Command, client *fleetClient, id string, opts fleetCommandOptions) error {
	nodes, err := fleetPeerInventory(opts.peers)
	if err != nil {
		return err
	}
	body, err := client.post(ctx, "/v1/fleet/templates/"+url.PathEscape(strings.TrimSpace(id))+":apply-plan", map[string]any{
		"expectedCandidateRevision": strings.TrimSpace(opts.expectedRevision),
		"nodes":                     nodes,
	})
	if err != nil {
		return err
	}
	if opts.outJSON {
		return printJSONMap(cmd, body)
	}
	printFleetTemplateOperation(cmd, "fleet template apply plan", body)
	printFleetApplyPlan(cmd, body)
	return nil
}

func runFleetTemplatesApply(ctx context.Context, cmd *cobra.Command, client *fleetClient, id string, opts fleetCommandOptions) error {
	revision := strings.TrimSpace(opts.expectedRevision)
	if revision == "" {
		return fmt.Errorf("--expected-candidate-revision is required")
	}
	comment := strings.TrimSpace(opts.comment)
	if comment == "" {
		return fmt.Errorf("--message/-m is required")
	}
	nodes, err := fleetPeerInventory(opts.peers)
	if err != nil {
		return err
	}
	body, err := client.post(ctx, "/v1/fleet/templates/"+url.PathEscape(strings.TrimSpace(id))+":apply", map[string]any{
		"expectedCandidateRevision": revision,
		"comment":                   comment,
		"nodes":                     nodes,
	})
	if err != nil {
		return err
	}
	if opts.outJSON {
		return printJSONMap(cmd, body)
	}
	printFleetTemplateOperation(cmd, "fleet template apply", body)
	printFleetApplyResult(cmd, body)
	cmd.Println("next: review retained result custody, then ngfwctl policy validate && ngfwctl policy diff && ngfwctl commit --message <reason>")
	return nil
}

func runFleetTemplateResults(ctx context.Context, cmd *cobra.Command, client *fleetClient, templateID string, outJSON bool) error {
	endpoint := "/v1/fleet/template-results"
	if strings.TrimSpace(templateID) != "" {
		endpoint += "?templateId=" + url.QueryEscape(strings.TrimSpace(templateID))
	}
	body, err := client.get(ctx, endpoint)
	if err != nil {
		return err
	}
	if outJSON {
		return printJSONMap(cmd, body)
	}
	results, _ := body["results"].([]any)
	if len(results) == 0 {
		cmd.Println("no fleet template apply results")
		printFleetBoundaries(cmd, body)
		return nil
	}
	cmd.Println("fleet template apply results")
	for _, raw := range results {
		result, _ := raw.(map[string]any)
		cmd.Printf("%s  template=%s status=%s candidate=%s\n",
			valueOrDash(jsonString(result, "id")),
			valueOrDash(jsonString(result, "templateId")),
			valueOrDash(jsonString(result, "status")),
			valueOrDash(jsonString(result, "candidateRevisionAfter")),
		)
		printFleetApplyResult(cmd, map[string]any{"applyResult": result})
	}
	printFleetBoundaries(cmd, body)
	return nil
}

func runFleetTemplatesStageCandidate(ctx context.Context, cmd *cobra.Command, client *fleetClient, id string, opts fleetCommandOptions) error {
	revision := strings.TrimSpace(opts.expectedRevision)
	if revision == "" {
		return fmt.Errorf("--expected-candidate-revision is required")
	}
	comment := strings.TrimSpace(opts.comment)
	if comment == "" {
		return fmt.Errorf("--message/-m is required")
	}
	body, err := client.post(ctx, "/v1/fleet/templates/"+url.PathEscape(strings.TrimSpace(id))+":stage-candidate", map[string]any{
		"expectedCandidateRevision": revision,
		"comment":                   comment,
	})
	if err != nil {
		return err
	}
	if opts.outJSON {
		return printJSONMap(cmd, body)
	}
	printFleetTemplateOperation(cmd, "fleet template staged as candidate", body)
	cmd.Println("next: ngfwctl policy validate && ngfwctl policy diff && ngfwctl commit --message <reason>")
	return nil
}

func fleetPeerInventory(values []string) ([]map[string]any, error) {
	nodes := make([]map[string]any, 0, len(values))
	for _, raw := range values {
		fields := map[string]string{}
		for _, part := range strings.Split(raw, ",") {
			key, value, ok := strings.Cut(part, "=")
			if !ok {
				return nil, fmt.Errorf("--peer entries must be key=value pairs separated by commas")
			}
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			if key != "" {
				fields[key] = value
			}
		}
		id := strings.TrimSpace(fields["id"])
		if id == "" {
			return nil, fmt.Errorf("--peer requires id=<node-id>")
		}
		node := map[string]any{
			"id":             id,
			"name":           firstNonEmpty(fields["name"], id),
			"role":           firstNonEmpty(fields["role"], "peer"),
			"runtimeState":   firstNonEmpty(fields["runtime"], fields["runtimeState"]),
			"runningVersion": fields["running"],
			"haState":        fields["haState"],
			"authoritative":  false,
		}
		if haReady := strings.TrimSpace(fields["haReady"]); haReady != "" {
			node["haReady"] = strings.EqualFold(haReady, "true") || haReady == "1" || strings.EqualFold(haReady, "yes")
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func printFleetApplyPlan(cmd *cobra.Command, body map[string]any) {
	if result := jsonString(body, "result"); result != "" {
		cmd.Printf("  result:          %s\n", result)
	}
	cmd.Printf("  nodes:           %s eligible / %s total\n",
		valueOrDash(jsonValueString(body["eligibleNodeCount"])),
		valueOrDash(jsonValueString(body["nodeCount"])))
	nodes, _ := body["nodes"].([]any)
	if len(nodes) > 0 {
		cmd.Println("  node plan:")
		for _, raw := range nodes {
			node, _ := raw.(map[string]any)
			cmd.Printf("    - %s  status=%s action=%s\n",
				valueOrDash(firstNonEmpty(jsonString(node, "name"), jsonString(node, "id"))),
				valueOrDash(jsonString(node, "status")),
				valueOrDash(jsonString(node, "plannedAction")),
			)
			if blockers := jsonStringList(node["blockers"]); len(blockers) > 0 {
				cmd.Printf("      blockers=%s\n", strings.Join(blockers, "; "))
			}
		}
	}
	if jsonBool(body, "wouldCallPeerRPC") || jsonBool(body, "wouldApplyRunningPolicy") || jsonBool(body, "wouldMutateCandidate") {
		cmd.Println("  warning: response reported mutation-capable flags; inspect JSON before proceeding")
	}
}

func printFleetApplyResult(cmd *cobra.Command, body map[string]any) {
	result, _ := body["applyResult"].(map[string]any)
	if result == nil {
		return
	}
	cmd.Printf("  apply result:    %s status=%s\n",
		valueOrDash(jsonString(result, "id")),
		valueOrDash(jsonString(result, "status")),
	)
	if custody := jsonString(result, "custodyBoundary"); custody != "" {
		cmd.Printf("  custody:         %s\n", custody)
	}
	nodes, _ := result["nodeResults"].([]any)
	if len(nodes) > 0 {
		cmd.Println("  node results:")
		for _, raw := range nodes {
			node, _ := raw.(map[string]any)
			cmd.Printf("    - %s  result=%s mutation=%s\n",
				valueOrDash(firstNonEmpty(jsonString(node, "nodeName"), jsonString(node, "nodeId"))),
				valueOrDash(jsonString(node, "result")),
				valueOrDash(jsonString(node, "mutation")),
			)
			if reason := jsonString(node, "reason"); reason != "" {
				cmd.Printf("      reason=%s\n", reason)
			}
		}
	}
}

func printFleetTemplateOperation(cmd *cobra.Command, title string, body map[string]any) {
	cmd.Println(title)
	if template, _ := body["template"].(map[string]any); template != nil {
		cmd.Printf("  template:        %s (%s)\n", valueOrDash(jsonString(template, "id")), valueOrDash(jsonString(template, "name")))
		cmd.Printf("  revision:        %s\n", valueOrDash(jsonString(template, "revision")))
	}
	if rev := jsonString(body, "candidateRevision"); rev != "" {
		cmd.Printf("  candidate:       %s\n", rev)
	}
	if prev := jsonString(body, "previousCandidateRevision"); prev != "" {
		cmd.Printf("  previous:        %s\n", prev)
	}
	if validation, _ := body["validation"].(map[string]any); validation != nil {
		cmd.Printf("  valid:           %s\n", yesNo(jsonBool(validation, "valid")))
		if errorsList := jsonStringList(validation["errors"]); len(errorsList) > 0 {
			cmd.Println("  errors:")
			for _, item := range errorsList {
				cmd.Printf("    - %s\n", item)
			}
		}
	}
	if impact, _ := body["impact"].(map[string]any); impact != nil {
		cmd.Printf("  impact:          %s\n", valueOrDash(jsonString(impact, "risk")))
	}
	if applyPath := jsonString(body, "applyPath"); applyPath != "" {
		cmd.Printf("  apply path:      %s\n", applyPath)
	}
	if boundary := jsonString(body, "orchestrationBoundary"); boundary != "" {
		cmd.Printf("  boundary:        %s\n", boundary)
	}
}

func printFleetTemplateLine(cmd *cobra.Command, template map[string]any) {
	summary, _ := template["policySummary"].(map[string]any)
	cmd.Printf("%s  name=%s scope=%s revision=%s rules=%s zones=%s updated=%s\n",
		valueOrDash(jsonString(template, "id")),
		valueOrDash(jsonString(template, "name")),
		valueOrDash(jsonString(template, "scope")),
		valueOrDash(jsonString(template, "revision")),
		valueOrDash(jsonValueString(summary["rules"])),
		valueOrDash(jsonValueString(summary["zones"])),
		valueOrDash(jsonString(template, "updatedAt")),
	)
}

func printFleetTemplateDetail(cmd *cobra.Command, template map[string]any) {
	printFleetTemplateLine(cmd, template)
	if desc := jsonString(template, "description"); desc != "" {
		cmd.Printf("  description: %s\n", desc)
	}
	if labels := jsonStringList(template["labels"]); len(labels) > 0 {
		cmd.Printf("  labels:      %s\n", strings.Join(labels, ", "))
	}
	if createdBy := jsonString(template, "createdBy"); createdBy != "" {
		cmd.Printf("  created:     %s by %s/%s\n", valueOrDash(jsonString(template, "createdAt")), createdBy, valueOrDash(jsonString(template, "createdByRole")))
	}
}

func printFleetBoundaries(cmd *cobra.Command, body map[string]any) {
	boundaries := jsonStringList(body["boundaries"])
	if len(boundaries) == 0 {
		return
	}
	cmd.Println("boundaries:")
	for _, boundary := range boundaries {
		cmd.Printf("- %s\n", boundary)
	}
}

func fleetTemplates(body map[string]any) []map[string]any {
	raw, _ := body["templates"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if template, ok := item.(map[string]any); ok {
			out = append(out, template)
		}
	}
	return out
}

func cleanFleetLabels(values []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			label := strings.TrimSpace(part)
			if label == "" || seen[label] {
				continue
			}
			seen[label] = true
			out = append(out, label)
		}
	}
	return out
}

func printJSONMap(cmd *cobra.Command, body map[string]any) error {
	raw, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return err
	}
	cmd.Println(string(raw))
	return nil
}

func jsonString(body map[string]any, key string) string {
	if body == nil {
		return ""
	}
	value, _ := body[key].(string)
	return value
}

func jsonBool(body map[string]any, key string) bool {
	if body == nil {
		return false
	}
	value, _ := body[key].(bool)
	return value
}

func jsonValueString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	case int:
		return fmt.Sprint(v)
	case int64:
		return fmt.Sprint(v)
	case uint64:
		return fmt.Sprint(v)
	case bool:
		return yesNo(v)
	default:
		return ""
	}
}

func jsonStringList(value any) []string {
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
