// ngfwrelease verifies release acceptance evidence before artifacts are signed.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/detailtech/oss-ngfw/internal/releaseacceptance"
)

type acceptanceManifest = releaseacceptance.Manifest
type acceptanceCheck = releaseacceptance.Check
type evidenceRecord = releaseacceptance.EvidenceRecord
type contentReadinessEvidence = releaseacceptance.ContentReadinessEvidence

type verifyOptions = releaseacceptance.VerifyOptions

type statusOptions struct {
	ManifestPath                string
	EvidenceDir                 string
	ExpectedCommit              string
	ExpectedVersion             string
	AllowNoPerformanceClaims    bool
	FunctionalHardeningDeferred bool
	JSON                        bool
	Strict                      bool
	Recordability               bool
}

type recordabilityOptions struct {
	EvidenceDir    string
	ExpectedCommit string
	Strict         bool
}

type assembleOptions struct {
	ManifestPath                string
	ReleaseVersion              string
	Commit                      string
	Operator                    string
	EvidenceDir                 string
	BenchmarkSummary            string
	NoPerformanceClaims         bool
	NoPerformanceDetail         string
	FunctionalHardeningDeferred bool
	Overwrite                   bool
}

type recordOptions struct {
	EvidenceDir string
	CheckName   string
	Commit      string
	Detail      string
	Overwrite   bool
	Command     []string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	return runWithIO(args, os.Stdout, os.Stderr)
}

func runWithIO(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: ngfwrelease <record|assemble|verify|status|recordability|template>")
	}
	switch args[0] {
	case "record":
		fs := flag.NewFlagSet("record", flag.ContinueOnError)
		fs.SetOutput(stderr)
		var opts recordOptions
		fs.StringVar(&opts.EvidenceDir, "evidence-dir", "release/evidence", "directory for <check>.txt evidence files")
		fs.StringVar(&opts.CheckName, "check", "", "required release check name to record")
		fs.StringVar(&opts.Commit, "commit", "", "full release git commit SHA; defaults to git rev-parse HEAD")
		fs.StringVar(&opts.Detail, "detail", "", "operator context for the evidence")
		fs.BoolVar(&opts.Overwrite, "overwrite", false, "replace an existing evidence artifact")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		opts.Command = fs.Args()
		return recordAcceptanceEvidence(stdout, opts)
	case "assemble":
		fs := flag.NewFlagSet("assemble", flag.ContinueOnError)
		fs.SetOutput(stderr)
		var opts assembleOptions
		fs.StringVar(&opts.ManifestPath, "manifest", "release/acceptance.json", "release acceptance manifest path")
		fs.StringVar(&opts.ReleaseVersion, "version", "", "release version/tag")
		fs.StringVar(&opts.Commit, "commit", "", "full release git commit SHA")
		fs.StringVar(&opts.Operator, "operator", "", "person or automation account assembling release evidence")
		fs.StringVar(&opts.EvidenceDir, "evidence-dir", "release/evidence", "directory containing existing <check>.txt evidence files")
		fs.StringVar(&opts.BenchmarkSummary, "benchmark-summary", "", "repository-relative perf/release-results/<run>/summary.json")
		fs.BoolVar(&opts.NoPerformanceClaims, "no-performance-claims", false, "assemble a release manifest that publishes no performance claims")
		fs.StringVar(&opts.NoPerformanceDetail, "no-performance-detail", releaseacceptance.DefaultNoPerformanceDetail, "detail text for no-performance-claims mode")
		fs.BoolVar(&opts.FunctionalHardeningDeferred, "functional-hardening-deferred", false, "assemble functional release acceptance with production-certification hardening gates explicitly deferred")
		fs.BoolVar(&opts.Overwrite, "overwrite", false, "replace an existing release acceptance manifest")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := rejectStrayArgs("assemble", fs.Args()); err != nil {
			return err
		}
		return assembleAcceptance(stdout, opts)
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ContinueOnError)
		fs.SetOutput(stderr)
		var opts verifyOptions
		fs.StringVar(&opts.ManifestPath, "manifest", "release/acceptance.json", "release acceptance manifest path")
		fs.StringVar(&opts.ExpectedCommit, "commit", "", "expected full git commit SHA")
		fs.StringVar(&opts.ExpectedVersion, "version", "", "expected release version/tag")
		fs.BoolVar(&opts.AllowNoPerformanceClaims, "allow-no-performance-claims", false, "allow release-benchmark to be not_applicable when the manifest declares no performance claims")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := rejectStrayArgs("verify", fs.Args()); err != nil {
			return err
		}
		return verifyAcceptanceWithIO(stdout, opts)
	case "status":
		fs := flag.NewFlagSet("status", flag.ContinueOnError)
		fs.SetOutput(stderr)
		var opts statusOptions
		fs.StringVar(&opts.ManifestPath, "manifest", "release/acceptance.json", "release acceptance manifest path")
		fs.StringVar(&opts.EvidenceDir, "evidence-dir", "release/evidence", "directory containing existing <check>.txt evidence files")
		fs.StringVar(&opts.ExpectedCommit, "commit", "", "expected full git commit SHA")
		fs.StringVar(&opts.ExpectedVersion, "version", "", "expected release version/tag")
		fs.BoolVar(&opts.AllowNoPerformanceClaims, "allow-no-performance-claims", false, "allow release-benchmark to be not_applicable when the manifest declares no performance claims")
		fs.BoolVar(&opts.FunctionalHardeningDeferred, "functional-hardening-deferred", false, "treat only allowlisted production-certification gaps as hardening_deferred while reporting functional acceptance status")
		fs.BoolVar(&opts.JSON, "json", false, "write a machine-readable status report")
		fs.BoolVar(&opts.Strict, "strict", false, "return non-zero unless release acceptance is ready, and recordability is ready when --recordability is set")
		fs.BoolVar(&opts.Recordability, "recordability", false, "also report whether ngfwrelease record can write evidence from the current git checkout")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := rejectStrayArgs("status", fs.Args()); err != nil {
			return err
		}
		return reportAcceptanceStatus(stdout, opts)
	case "recordability":
		fs := flag.NewFlagSet("recordability", flag.ContinueOnError)
		fs.SetOutput(stderr)
		var opts recordabilityOptions
		fs.StringVar(&opts.EvidenceDir, "evidence-dir", "release/evidence", "directory where release evidence would be recorded")
		fs.StringVar(&opts.ExpectedCommit, "commit", "", "full release git commit SHA; defaults to git rev-parse HEAD")
		fs.BoolVar(&opts.Strict, "strict", false, "return non-zero unless release evidence can be recorded from the current checkout")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := rejectStrayArgs("recordability", fs.Args()); err != nil {
			return err
		}
		return reportRecordability(stdout, statusOptions{
			EvidenceDir:    opts.EvidenceDir,
			ExpectedCommit: opts.ExpectedCommit,
			Strict:         opts.Strict,
		})
	case "template":
		fs := flag.NewFlagSet("template", flag.ContinueOnError)
		fs.SetOutput(stderr)
		var opts templateOptions
		fs.StringVar(&opts.OutputPath, "output", "", "write non-passing template to this path instead of stdout")
		fs.StringVar(&opts.EvidenceDir, "evidence-dir", "evidence", "manifest-relative evidence directory used in artifact placeholders")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := rejectStrayArgs("template", fs.Args()); err != nil {
			return err
		}
		return writeAcceptanceTemplate(stdout, stderr, opts)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func recordAcceptanceEvidence(stdout io.Writer, opts recordOptions) error {
	opts.EvidenceDir = strings.TrimSpace(opts.EvidenceDir)
	if opts.EvidenceDir == "" {
		opts.EvidenceDir = "release/evidence"
	}
	opts.CheckName = strings.TrimSpace(opts.CheckName)
	opts.Detail = strings.TrimSpace(opts.Detail)
	if opts.CheckName == "" {
		return errors.New("record requires --check")
	}
	if !releaseacceptance.IsRequiredCheck(opts.CheckName) {
		return fmt.Errorf("record check %q is not one of required release checks: %s", opts.CheckName, strings.Join(releaseacceptance.RequiredChecks(), ", "))
	}
	opts.Commit = normalizeCommit(opts.Commit)
	if opts.Commit == "" {
		commit, err := currentGitCommit()
		if err != nil {
			return fmt.Errorf("record requires --commit or a readable git checkout: %w", err)
		}
		opts.Commit = commit
	}
	if !isFullCommitHex(opts.Commit) {
		return errors.New("record commit must be a full 40-character hex git commit")
	}
	if problems := releaseacceptance.ValidateEvidenceMetadataRedaction(opts.CheckName, "detail", opts.Detail); len(problems) > 0 {
		return fmt.Errorf("record %s evidence rejected: %s; passing evidence was not written", opts.CheckName, strings.Join(problems, "; "))
	}
	if len(opts.Command) == 0 {
		return errors.New("record requires a command after --")
	}
	for _, arg := range opts.Command {
		if strings.TrimSpace(arg) == "" {
			return errors.New("record command must not contain empty arguments")
		}
	}
	if !releaseacceptance.AllowedEvidenceCommand(opts.CheckName, opts.Command) {
		return fmt.Errorf("record command for %s is not an approved release evidence command; passing evidence was not written", opts.CheckName)
	}
	if err := ensureRecordSourceClean(opts.EvidenceDir, opts.Commit); err != nil {
		return err
	}
	if err := ensureEvidenceDir(opts.EvidenceDir); err != nil {
		return err
	}

	start := time.Now().UTC()
	cmd := exec.Command(opts.Command[0], opts.Command[1:]...)
	var cmdStdout strings.Builder
	var cmdStderr strings.Builder
	cmd.Stdout = &cmdStdout
	cmd.Stderr = &cmdStderr
	err := cmd.Run()
	duration := time.Since(start)
	if err != nil {
		return commandFailureError(opts.CheckName, err, cmdStderr.String())
	}
	if problems := releaseacceptance.ValidateEvidenceStdout(opts.CheckName, cmdStdout.String()); len(problems) > 0 {
		return fmt.Errorf("record %s evidence rejected: %s; passing evidence was not written", opts.CheckName, strings.Join(problems, "; "))
	}
	if problems := releaseacceptance.ValidateEvidenceOutputRedaction(opts.CheckName, cmdStdout.String(), cmdStderr.String()); len(problems) > 0 {
		return fmt.Errorf("record %s evidence rejected: %s; passing evidence was not written", opts.CheckName, strings.Join(problems, "; "))
	}
	if err := ensureRecordSourceClean(opts.EvidenceDir, opts.Commit); err != nil {
		return err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("record current working directory: %w", err)
	}
	record := evidenceRecord{
		SchemaVersion: releaseacceptance.EvidenceSchemaVersion,
		Check:         opts.CheckName,
		Commit:        opts.Commit,
		RanAt:         start.Format(time.RFC3339),
		DurationMS:    duration.Milliseconds(),
		CWD:           cwd,
		Command:       append([]string(nil), opts.Command...),
		Detail:        opts.Detail,
		ExitCode:      0,
		Stdout:        cmdStdout.String(),
		Stderr:        cmdStderr.String(),
	}
	contentReadiness, err := releaseacceptance.ContentReadinessForRecordedEvidence(record)
	if err != nil {
		return fmt.Errorf("record %s evidence: %w", opts.CheckName, err)
	}
	record.ContentReadiness = contentReadiness
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal release evidence: %w", err)
	}
	path := filepath.Join(opts.EvidenceDir, opts.CheckName+".txt")
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if opts.Overwrite {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite existing evidence artifact %s", path)
		}
		return fmt.Errorf("create release evidence artifact %s: %w", path, err)
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("write release evidence artifact %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close release evidence artifact %s: %w", path, err)
	}
	if _, err := fmt.Fprintf(stdout, "recorded release evidence: %s\n", path); err != nil {
		return fmt.Errorf("write record result: %w", err)
	}
	return nil
}

func ensureEvidenceDir(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("create evidence directory %s: %w", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat evidence directory %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("evidence directory %s must not be a symlink", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("evidence directory %s must be a directory", path)
	}
	return nil
}

func ensureRecordSourceClean(evidenceDir, commit string) error {
	status := releaseacceptance.EvaluateRecordability(evidenceDir, commit)
	if status.Ready {
		return nil
	}
	if len(status.DirtySourcePaths) > 0 {
		return fmt.Errorf(
			"release source tree has uncommitted changes outside allowed release artifact paths; passing evidence was not written; allowed dirty paths: %s; dirty source paths: %s; commit or stash source changes before recording release evidence",
			strings.Join(status.AllowedDirtyPaths, ", "),
			strings.Join(releaseacceptance.LimitStrings(status.DirtySourcePaths, 20), ", "),
		)
	}
	if len(status.StaleEvidencePaths) > 0 {
		return fmt.Errorf(
			"release evidence directory contains artifacts recorded for a different commit; passing evidence was not written; stale evidence paths: %s; move stale evidence out of release/evidence or re-record it with --overwrite for the accepted release commit before assembling acceptance",
			strings.Join(releaseacceptance.LimitStrings(status.StaleEvidencePaths, 20), ", "),
		)
	}
	if len(status.Problems) > 0 {
		return fmt.Errorf("%s; passing evidence was not written", strings.Join(status.Problems, "; "))
	}
	return errors.New("recordability preflight failed; passing evidence was not written")
}

func recordDirtyPathAllowed(path string, allowedPrefixes []string) bool {
	return releaseacceptance.RecordDirtyPathAllowed(path, allowedPrefixes)
}

func limitStrings(values []string, limit int) []string {
	return releaseacceptance.LimitStrings(values, limit)
}

func commandFailureError(check string, err error, stderr string) error {
	stderr = strings.TrimSpace(stderr)
	if exitErr := new(exec.ExitError); errors.As(err, &exitErr) {
		msg := fmt.Sprintf("release evidence command for %s failed with exit code %d; passing evidence was not written", check, exitErr.ExitCode())
		if stderr != "" {
			return fmt.Errorf("%s; stderr: %s", msg, truncateEvidenceError(releaseacceptance.RedactEvidenceSecrets(stderr)))
		}
		return errors.New(msg)
	}
	return fmt.Errorf("run release evidence command for %s: %w", check, err)
}

func truncateEvidenceError(s string) string {
	const maxLen = 500
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...(truncated)"
}

func currentGitCommit() (string, error) {
	raw, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return "", err
	}
	commit := normalizeCommit(string(raw))
	if !isFullCommitHex(commit) {
		return "", fmt.Errorf("git rev-parse HEAD returned %q", strings.TrimSpace(string(raw)))
	}
	return commit, nil
}

func rejectStrayArgs(command string, args []string) error {
	if len(args) == 0 {
		return nil
	}
	return fmt.Errorf("%s does not accept positional arguments: %s", command, strings.Join(args, " "))
}

type templateOptions struct {
	OutputPath  string
	EvidenceDir string
}

func assembleAcceptance(stdout io.Writer, opts assembleOptions) error {
	opts.ManifestPath = strings.TrimSpace(opts.ManifestPath)
	if opts.ManifestPath == "" {
		opts.ManifestPath = "release/acceptance.json"
	}
	opts.ReleaseVersion = strings.TrimSpace(opts.ReleaseVersion)
	opts.Commit = normalizeCommit(opts.Commit)
	opts.Operator = strings.TrimSpace(opts.Operator)
	opts.EvidenceDir = strings.TrimSpace(opts.EvidenceDir)
	if opts.EvidenceDir == "" {
		opts.EvidenceDir = "release/evidence"
	}
	opts.BenchmarkSummary = strings.TrimSpace(opts.BenchmarkSummary)
	opts.NoPerformanceDetail = strings.TrimSpace(opts.NoPerformanceDetail)
	if opts.NoPerformanceClaims && opts.NoPerformanceDetail == "" {
		opts.NoPerformanceDetail = releaseacceptance.DefaultNoPerformanceDetail
	}

	var problems []string
	if opts.ReleaseVersion == "" {
		problems = append(problems, "version is required")
	}
	if !isFullCommitHex(opts.Commit) {
		problems = append(problems, "commit must be a full 40-character hex git commit")
	}
	if opts.Operator == "" {
		problems = append(problems, "operator is required")
	}
	if opts.NoPerformanceClaims {
		if opts.BenchmarkSummary != "" {
			problems = append(problems, "benchmark-summary must be omitted when --no-performance-claims is set")
		}
		if opts.NoPerformanceDetail == "" {
			problems = append(problems, "no-performance-detail is required when --no-performance-claims is set")
		}
	} else if opts.BenchmarkSummary == "" {
		problems = append(problems, "benchmark-summary is required unless --no-performance-claims is set")
	}
	if _, err := os.Stat(opts.ManifestPath); err == nil && !opts.Overwrite {
		problems = append(problems, fmt.Sprintf("refusing to overwrite existing manifest %s", opts.ManifestPath))
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		problems = append(problems, fmt.Sprintf("stat manifest %s: %v", opts.ManifestPath, err))
	}

	absManifest, err := filepath.Abs(opts.ManifestPath)
	if err != nil {
		problems = append(problems, fmt.Sprintf("resolve manifest path: %v", err))
	}
	absEvidence, err := filepath.Abs(opts.EvidenceDir)
	if err != nil {
		problems = append(problems, fmt.Sprintf("resolve evidence-dir: %v", err))
	}
	manifestDir := filepath.Dir(absManifest)
	if info, err := os.Stat(absEvidence); err != nil {
		problems = append(problems, fmt.Sprintf("evidence-dir %s is not readable: %v", opts.EvidenceDir, err))
	} else if !info.IsDir() {
		problems = append(problems, fmt.Sprintf("evidence-dir %s must be a directory", opts.EvidenceDir))
	}

	relEvidenceDir := ""
	if absManifest != "" && absEvidence != "" {
		rel, err := filepath.Rel(manifestDir, absEvidence)
		if err != nil {
			problems = append(problems, fmt.Sprintf("make evidence-dir manifest-relative: %v", err))
		} else if clean, err := cleanManifestRelativeDir(rel); err != nil {
			problems = append(problems, err.Error())
		} else if clean != "evidence" && !strings.HasPrefix(clean, "evidence/") {
			problems = append(problems, fmt.Sprintf("evidence-dir %q must resolve under the manifest evidence/ directory", opts.EvidenceDir))
		} else {
			relEvidenceDir = clean
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("release acceptance assembly failed:\n- %s", strings.Join(problems, "\n- "))
	}

	generatedAt := time.Now().UTC().Format(time.RFC3339)
	checks := make([]acceptanceCheck, 0, len(releaseacceptance.RequiredChecks()))
	for _, name := range releaseacceptance.RequiredChecks() {
		if opts.NoPerformanceClaims && name == "release-benchmark" {
			checks = append(checks, acceptanceCheck{
				Name:   name,
				Status: "not_applicable",
				RanAt:  generatedAt,
				Detail: opts.NoPerformanceDetail,
			})
			continue
		}
		artifact := filepath.ToSlash(filepath.Join(relEvidenceDir, name+".txt"))
		path := filepath.Join(absEvidence, name+".txt")
		info, err := os.Stat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && opts.FunctionalHardeningDeferred && releaseacceptance.HardeningDeferredAllowed(name) {
				checks = append(checks, acceptanceCheck{
					Name:   name,
					Status: "hardening_deferred",
					RanAt:  generatedAt,
					Detail: releaseacceptance.HardeningDeferredDetail(name),
				})
				continue
			}
			return fmt.Errorf("release acceptance assembly failed:\n- %s evidence artifact %q is not readable: %v", name, path, err)
		}
		digest, err := fileSHA256(path)
		if err != nil {
			return fmt.Errorf("release acceptance assembly failed:\n- %s artifact digest could not be computed: %v", name, err)
		}
		check := acceptanceCheck{
			Name:           name,
			Status:         "passed",
			Artifact:       artifact,
			ArtifactSHA256: digest,
			RanAt:          info.ModTime().UTC().Format(time.RFC3339),
		}
		if name == releaseacceptance.ContentPackageCheckName || name == releaseacceptance.ContentProductionReadinessCheckName {
			if rec, err := releaseacceptance.ReadEvidenceRecordFile(path); err == nil && rec.ContentReadiness != nil {
				check.Detail = releaseacceptance.ContentReadinessAcceptanceDetail(name, *rec.ContentReadiness)
			}
		}
		if name == "release-benchmark" {
			check.BenchmarkSummary = opts.BenchmarkSummary
			check.Detail = "benchmark summary: " + opts.BenchmarkSummary
		}
		checks = append(checks, check)
	}
	m := acceptanceManifest{
		SchemaVersion:       releaseacceptance.AcceptanceSchemaVersion,
		ReleaseVersion:      opts.ReleaseVersion,
		Commit:              opts.Commit,
		GeneratedAt:         generatedAt,
		Operator:            opts.Operator,
		NoPerformanceClaims: opts.NoPerformanceClaims,
		Checks:              checks,
	}
	verifyOpts := verifyOptions{
		ExpectedCommit:           opts.Commit,
		ExpectedVersion:          opts.ReleaseVersion,
		AllowNoPerformanceClaims: opts.NoPerformanceClaims,
		AllowHardeningDeferred:   opts.FunctionalHardeningDeferred,
	}
	if problems := releaseacceptance.ValidateManifest(m, manifestDir, verifyOpts); len(problems) > 0 {
		return fmt.Errorf("release acceptance assembly failed:\n- %s", strings.Join(problems, "\n- "))
	}

	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal release acceptance manifest: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absManifest), 0o755); err != nil {
		return fmt.Errorf("create release acceptance directory: %w", err)
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if opts.Overwrite {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(absManifest, flags, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite existing manifest %s", opts.ManifestPath)
		}
		return fmt.Errorf("create release acceptance manifest %s: %w", opts.ManifestPath, err)
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("write release acceptance manifest %s: %w", opts.ManifestPath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close release acceptance manifest %s: %w", opts.ManifestPath, err)
	}
	if _, err := fmt.Fprintf(stdout, "assembled release acceptance manifest: %s\n", opts.ManifestPath); err != nil {
		return fmt.Errorf("write assemble result: %w", err)
	}
	return nil
}

func writeAcceptanceTemplate(stdout, stderr io.Writer, opts templateOptions) error {
	raw, evidenceDir, err := renderAcceptanceTemplate(opts)
	if err != nil {
		return err
	}
	outputPath := strings.TrimSpace(opts.OutputPath)
	if outputPath == "" {
		if _, err := stdout.Write(raw); err != nil {
			return fmt.Errorf("write release acceptance template to stdout: %w", err)
		}
		printTemplateGuidance(stderr, "", evidenceDir)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create template output directory: %w", err)
	}
	f, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite existing template %s", outputPath)
		}
		return fmt.Errorf("create release acceptance template %s: %w", outputPath, err)
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return fmt.Errorf("write release acceptance template %s: %w", outputPath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close release acceptance template %s: %w", outputPath, err)
	}
	if _, err := fmt.Fprintf(stderr, "wrote non-passing release acceptance template to %s\n", outputPath); err != nil {
		return fmt.Errorf("write template result: %w", err)
	}
	printTemplateGuidance(stderr, outputPath, evidenceDir)
	return nil
}

func renderAcceptanceTemplate(opts templateOptions) ([]byte, string, error) {
	evidenceDir, err := cleanManifestRelativeDir(opts.EvidenceDir)
	if err != nil {
		return nil, "", err
	}
	checks := make([]acceptanceCheck, 0, len(releaseacceptance.RequiredChecks()))
	for _, name := range releaseacceptance.RequiredChecks() {
		check := acceptanceCheck{
			Name:           name,
			Status:         "todo",
			Artifact:       filepath.ToSlash(filepath.Join(evidenceDir, name+".txt")),
			ArtifactSHA256: strings.Repeat("0", sha256.Size*2),
			RanAt:          "YYYY-MM-DDTHH:MM:SSZ",
			Detail:         templateCheckDetail(name),
		}
		if name == "release-benchmark" {
			check.BenchmarkSummary = "perf/release-results/<run>/summary.json"
		}
		checks = append(checks, check)
	}
	m := acceptanceManifest{
		SchemaVersion:       releaseacceptance.AcceptanceTemplateSchemaVersion,
		ReleaseVersion:      "vX.Y.Z",
		Commit:              "<release-commit>",
		GeneratedAt:         "YYYY-MM-DDTHH:MM:SSZ",
		Operator:            "<operator>",
		NoPerformanceClaims: false,
		Checks:              checks,
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("marshal release acceptance template: %w", err)
	}
	return append(raw, '\n'), evidenceDir, nil
}

func cleanManifestRelativeDir(dir string) (string, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		dir = "evidence"
	}
	if filepath.IsAbs(dir) {
		return "", fmt.Errorf("evidence-dir %q must be relative to the manifest", dir)
	}
	clean := filepath.Clean(dir)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("evidence-dir %q must not escape the manifest directory", dir)
	}
	return filepath.ToSlash(clean), nil
}

func templateCheckDetail(name string) string {
	if name == "release-benchmark" {
		return "replace with selected perf/release-results run and benchmark verifier output"
	}
	if name == "deploy-hardening" {
		return "replace with deploy/systemd and installer hardening preflight evidence"
	}
	if name == "policy-restore-drill" {
		return "replace with rootless emergency policy restore drill evidence from make release-evidence-policy-restore-drill"
	}
	if name == "ha-readiness-recovery" {
		return "replace with rootless active/passive HA readiness and control-plane recovery evidence from make release-evidence-ha-readiness-recovery"
	}
	if name == "m3-field-evidence" {
		return "run make release-evidence-m3-field-evidence after release/field-evidence/m3 validates external BGP, IPsec, and WireGuard"
	}
	if name == "ebpf-ol9-field-evidence" {
		return "run make release-evidence-ebpf-ol9-field-evidence after release/field-evidence/ebpf-ol9 validates OL9/root XDP/tc attach and ngfwctl status evidence"
	}
	if name == releaseacceptance.ContentProductionReadinessCheckName {
		return "run make release-evidence-content-production-readiness after release/field-evidence/content-production/<kind>/status.json validates App-ID, Threat-ID, and intel-feeds"
	}
	if name == "m5-auth-ui" {
		return "run make release-evidence-m5-auth-ui after e2e-auth-runtime-smoke proves authenticated loopback UI/runtime posture"
	}
	if name == "m5-oidc-provider" {
		return "replace with OIDC authorization-code provider and runtime provider lifecycle smoke output"
	}
	if name == releaseacceptance.WebUIEnterpriseSmokeCheckName {
		return "run make release-evidence-webui-enterprise-smoke after browser-required broad desktop enterprise WebUI smoke passes for the accepted source snapshot"
	}
	if name == releaseacceptance.OIDCFieldEvidenceCheckName {
		return "run make release-evidence-m5-oidc-field-evidence after release/field-evidence/oidc validates redacted real-provider browser SSO"
	}
	if name == releaseacceptance.SAMLFieldEvidenceCheckName {
		return "run make release-evidence-m5-saml-field-evidence after release/field-evidence/saml validates redacted real-provider SAML browser SSO"
	}
	return "replace with real release evidence before changing status to passed"
}

func printTemplateGuidance(stderr io.Writer, outputPath, evidenceDir string) {
	_, _ = fmt.Fprintf(stderr, "template only: verifier rejects schema_version %q and todo checks until real evidence is supplied\n", releaseacceptance.AcceptanceTemplateSchemaVersion)
	_, _ = fmt.Fprintf(stderr, "capture release-local evidence under %s and reference files relative to the manifest\n", evidenceDirHint(outputPath, evidenceDir))
}

func evidenceDirHint(outputPath, evidenceDir string) string {
	if strings.TrimSpace(outputPath) == "" {
		return evidenceDir + "/ next to the eventual manifest"
	}
	baseDir := filepath.Dir(outputPath)
	if baseDir == "." {
		return evidenceDir + "/"
	}
	return filepath.ToSlash(filepath.Join(baseDir, filepath.FromSlash(evidenceDir))) + "/"
}

func verifyAcceptance(opts verifyOptions) error {
	return verifyAcceptanceWithIO(io.Discard, opts)
}

func verifyAcceptanceWithIO(stdout io.Writer, opts verifyOptions) error {
	raw, err := os.ReadFile(opts.ManifestPath)
	if err != nil {
		return fmt.Errorf("read release acceptance manifest %s: %w", opts.ManifestPath, err)
	}
	var m acceptanceManifest
	if err := releaseacceptance.DecodeManifest(raw, &m); err != nil {
		return fmt.Errorf("parse release acceptance manifest: %w", err)
	}
	baseDir := filepath.Dir(opts.ManifestPath)
	problems := releaseacceptance.ValidateManifest(m, baseDir, opts)
	if len(problems) > 0 {
		return fmt.Errorf("release acceptance verification failed:\n- %s", strings.Join(problems, "\n- "))
	}
	if _, err := fmt.Fprintf(stdout, "release acceptance verified: %s (%s), %d required check(s)\n", m.ReleaseVersion, shortCommit(m.Commit), len(releaseacceptance.RequiredChecks())); err != nil {
		return fmt.Errorf("write verification result: %w", err)
	}
	if m.NoPerformanceClaims {
		if _, err := fmt.Fprintln(stdout, "release acceptance: no performance claims declared"); err != nil {
			return fmt.Errorf("write performance-claim result: %w", err)
		}
	}
	return nil
}

func reportAcceptanceStatus(stdout io.Writer, opts statusOptions) error {
	if opts.Recordability && opts.JSON {
		return errors.New("status --recordability cannot be combined with --json; use human output for the git checkout preflight")
	}
	if err := releaseacceptance.ReportStatus(stdout, releaseacceptance.StatusOptions{
		ManifestPath:             opts.ManifestPath,
		EvidenceDir:              opts.EvidenceDir,
		ExpectedCommit:           opts.ExpectedCommit,
		ExpectedVersion:          opts.ExpectedVersion,
		AllowNoPerformanceClaims: opts.AllowNoPerformanceClaims,
		AllowHardeningDeferred:   opts.FunctionalHardeningDeferred,
		JSON:                     opts.JSON,
		Strict:                   opts.Strict,
	}); err != nil {
		return err
	}
	if opts.Recordability {
		return reportRecordability(stdout, opts)
	}
	return nil
}

func reportRecordability(stdout io.Writer, opts statusOptions) error {
	status := releaseacceptance.EvaluateRecordability(opts.EvidenceDir, opts.ExpectedCommit)
	if err := releaseacceptance.WriteRecordabilityText(stdout, status); err != nil {
		return err
	}
	if opts.Strict && !status.Ready {
		return errors.New("release evidence recordability is blocked; commit or stash source changes before recording release evidence")
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return fmt.Sprintf("%x", digest[:]), nil
}

func normalizeCommit(commit string) string {
	return strings.ToLower(strings.TrimSpace(commit))
}

func isFullCommitHex(commit string) bool {
	commit = normalizeCommit(commit)
	if len(commit) != 40 {
		return false
	}
	for _, r := range commit {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func shortCommit(commit string) string {
	commit = strings.TrimSpace(commit)
	if len(commit) <= 12 {
		return commit
	}
	return commit[:12]
}
