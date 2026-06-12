package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"sigs.k8s.io/yaml"

	openngfwv1 "github.com/detailtech/oss-ngfw/api/gen/openngfw/v1"
)

func newPolicyCommand(server *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage the declarative policy (candidate workflow)",
	}
	cmd.AddCommand(
		newPolicySetCommand(server),
		newPolicyShowCommand(server),
		newPolicyValidateCommand(server),
	)
	return cmd
}

func newPolicySetCommand(server *string) *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Load a YAML/JSON policy file as the candidate",
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			jsonBytes, err := yaml.YAMLToJSON(raw)
			if err != nil {
				return fmt.Errorf("parse %s: %w", file, err)
			}
			pol := &openngfwv1.Policy{}
			if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(jsonBytes, pol); err != nil {
				return fmt.Errorf("policy schema error in %s: %w", file, err)
			}

			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			client := openngfwv1.NewPolicyServiceClient(conn)
			if _, err := client.SetCandidate(ctx, &openngfwv1.SetCandidateRequest{Policy: pol}); err != nil {
				return fmt.Errorf("set candidate: %w", err)
			}
			cmd.Println("candidate updated; run 'ngfwctl policy validate' then 'ngfwctl commit'")
			return nil
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "policy file (YAML or JSON)")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

func newPolicyShowCommand(server *string) *cobra.Command {
	var (
		source  string
		ver     uint64
		outJSON bool
	)
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the running, candidate, or a historical policy",
		RunE: func(cmd *cobra.Command, _ []string) error {
			req := &openngfwv1.GetPolicyRequest{}
			switch source {
			case "running":
				req.Source = openngfwv1.PolicySource_POLICY_SOURCE_RUNNING
			case "candidate":
				req.Source = openngfwv1.PolicySource_POLICY_SOURCE_CANDIDATE
			case "version":
				req.Source = openngfwv1.PolicySource_POLICY_SOURCE_VERSION
				req.Version = ver
			default:
				return fmt.Errorf("--source must be running, candidate, or version")
			}

			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewPolicyServiceClient(conn).GetPolicy(ctx, req)
			if err != nil {
				return err
			}

			jsonBytes, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(resp.GetPolicy())
			if err != nil {
				return err
			}
			if outJSON {
				cmd.Println(string(jsonBytes))
				return nil
			}
			y, err := yaml.JSONToYAML(jsonBytes)
			if err != nil {
				return err
			}
			cmd.Print(string(y))
			return nil
		},
	}
	cmd.Flags().StringVar(&source, "source", "running", "running | candidate | version")
	cmd.Flags().Uint64Var(&ver, "version", 0, "version id (with --source version)")
	cmd.Flags().BoolVar(&outJSON, "json", false, "output JSON instead of YAML")
	return cmd
}

func newPolicyValidateCommand(server *string) *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate the candidate policy without applying it",
		RunE: func(cmd *cobra.Command, _ []string) error {
			conn, ctx, cancel, err := dial(cmd.Context(), *server)
			if err != nil {
				return err
			}
			defer func() { cancel(); _ = conn.Close() }()
			resp, err := openngfwv1.NewPolicyServiceClient(conn).Validate(ctx, &openngfwv1.ValidateRequest{})
			if err != nil {
				return err
			}
			if !resp.GetValid() {
				for _, e := range resp.GetErrors() {
					cmd.PrintErrln("error: " + e)
				}
				return fmt.Errorf("candidate is invalid (%d errors)", len(resp.GetErrors()))
			}
			cmd.Println("candidate is valid")
			return nil
		},
	}
}
