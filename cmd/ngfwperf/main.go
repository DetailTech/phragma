// ngfwperf validates OpenNGFW performance evidence.
package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/detailtech/oss-ngfw/internal/perfreport"
)

func main() {
	if err := newRoot().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRoot() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ngfwperf",
		Short: "OpenNGFW performance evidence tools",
	}
	cmd.AddCommand(newVerifyCommand())
	cmd.AddCommand(newStageReleaseCommand())
	cmd.AddCommand(newCheckCitationsCommand())
	return cmd
}

func newVerifyCommand() *cobra.Command {
	var strict bool
	var quiet bool
	var publishable bool
	cmd := &cobra.Command{
		Use:          "verify [summary.json|result-dir|results-dir ...]",
		Short:        "Validate benchmark summary evidence",
		Args:         cobra.ArbitraryArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				args = []string{"perf/results"}
			}
			files, err := summaryFiles(args)
			if err != nil {
				return err
			}
			if len(files) == 0 {
				return fmt.Errorf("no summary.json files found")
			}
			var errors, warnings, gateFailures int
			for _, path := range files {
				result, err := perfreport.ValidateSummaryFile(path)
				if err != nil {
					errors++
					if !quiet {
						cmd.Printf("%s: error: load evidence: %v\n", path, err)
					}
					continue
				}
				if result.Valid() && len(result.Warnings) == 0 {
					if !quiet {
						cmd.Printf("%s: ok (%s, %.3f Gbps, %s)\n", path, result.Summary.Profile, result.Summary.TCPGbps, result.Summary.InspectionState)
					}
				}
				for _, msg := range result.Errors {
					errors++
					if !quiet {
						cmd.Printf("%s: error: %s\n", path, msg)
					}
				}
				for _, msg := range result.Warnings {
					warnings++
					if !quiet {
						cmd.Printf("%s: warning: %s\n", path, msg)
					}
				}
				var gate perfreport.PublicationGate
				if publishable {
					gate = perfreport.EvaluatePublicationGate(result, strict)
					if !quiet {
						printPublicationGate(cmd, path, gate)
					}
					if !gate.Publishable() {
						gateFailures++
					}
				}
				if !quiet && shouldPrintRepairSteps(result, publishable, gate) {
					printRepairSteps(cmd, path, perfreport.RecommendRepairSteps(result, strict))
				}
			}
			if !quiet {
				cmd.Printf("verified %d summary file(s): %d error(s), %d warning(s)\n", len(files), errors, warnings)
				if publishable {
					cmd.Printf("publication gate: %d failure(s)\n", gateFailures)
				}
			}
			if errors > 0 {
				return fmt.Errorf("benchmark evidence verification failed")
			}
			if publishable && gateFailures > 0 {
				return fmt.Errorf("benchmark evidence is not publishable")
			}
			if strict && warnings > 0 {
				return fmt.Errorf("benchmark evidence verification failed in strict mode")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&strict, "strict", false, "fail on warnings as well as errors")
	cmd.Flags().BoolVar(&publishable, "publishable", false, "fail unless each artifact is suitable for scoped publication or release use")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "print only command errors")
	return cmd
}

func newStageReleaseCommand() *cobra.Command {
	var releaseDir string
	var name string
	cmd := &cobra.Command{
		Use:          "stage-release [summary.json|result-dir]",
		Short:        "Copy one publishable benchmark run into perf/release-results",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			srcDir, summaryPath, err := releaseCandidateRun(args[0])
			if err != nil {
				return err
			}
			result, err := perfreport.ValidateSummaryFile(summaryPath)
			if err != nil {
				return fmt.Errorf("load benchmark evidence: %w", err)
			}
			gate := perfreport.EvaluatePublicationGate(result, true)
			if len(result.Errors) > 0 || len(result.Warnings) > 0 || !gate.Publishable() {
				printPublicationGate(cmd, summaryPath, gate)
				if shouldPrintRepairSteps(result, true, gate) {
					printRepairSteps(cmd, summaryPath, perfreport.RecommendRepairSteps(result, true))
				}
				return fmt.Errorf("benchmark evidence is not publishable; refusing to stage release evidence")
			}

			runName := strings.TrimSpace(name)
			if runName == "" {
				runName = filepath.Base(srcDir)
			}
			if runName == "." || runName == string(filepath.Separator) || filepath.IsAbs(runName) || strings.Contains(runName, string(filepath.Separator)) {
				return fmt.Errorf("stage name %q must be a single directory name", runName)
			}
			destDir := filepath.Join(releaseDir, runName)
			if err := copyReleaseRun(srcDir, destDir); err != nil {
				return err
			}
			cmd.Printf("staged publishable benchmark evidence: %s -> %s\n", srcDir, destDir)
			cmd.Printf("release benchmark summary: %s\n", filepath.ToSlash(filepath.Join(destDir, "summary.json")))
			return nil
		},
	}
	cmd.Flags().StringVar(&releaseDir, "release-dir", "perf/release-results", "release benchmark evidence directory")
	cmd.Flags().StringVar(&name, "name", "", "destination run directory name; defaults to source directory base name")
	return cmd
}

func newCheckCitationsCommand() *cobra.Command {
	var root string
	var noPerformanceClaims bool
	cmd := &cobra.Command{
		Use:          "check-citations [file ...]",
		Short:        "Verify benchmark summary citations are release-citable",
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var failures int
			var citations int
			for _, path := range args {
				fileCitations, fileFailures, err := checkCitationFile(cmd, root, path, noPerformanceClaims)
				if err != nil {
					return err
				}
				citations += fileCitations
				failures += fileFailures
			}
			cmd.Printf("checked %d benchmark citation(s): %d failure(s)\n", citations, failures)
			if failures > 0 {
				return fmt.Errorf("benchmark citation check failed")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&root, "root", ".", "repository root used to resolve perf/release-results citations")
	cmd.Flags().BoolVar(&noPerformanceClaims, "no-performance-claims", false, "fail if release-note text contains throughput, latency, connection-rate, benchmark, or comparison performance claims")
	return cmd
}

func releaseCandidateRun(arg string) (string, string, error) {
	info, err := os.Stat(arg)
	if err != nil {
		return "", "", err
	}
	if !info.IsDir() {
		if filepath.Base(arg) != "summary.json" {
			return "", "", fmt.Errorf("%s is not a summary.json file", arg)
		}
		return filepath.Dir(arg), arg, nil
	}
	summaryPath := filepath.Join(arg, "summary.json")
	if _, err := os.Stat(summaryPath); err != nil {
		return "", "", fmt.Errorf("stage-release requires a single result directory with top-level summary.json: %w", err)
	}
	return arg, summaryPath, nil
}

func copyReleaseRun(srcDir, destDir string) error {
	srcAbs, err := filepath.Abs(srcDir)
	if err != nil {
		return fmt.Errorf("resolve source run: %w", err)
	}
	destAbs, err := filepath.Abs(destDir)
	if err != nil {
		return fmt.Errorf("resolve destination run: %w", err)
	}
	if srcAbs == destAbs {
		return fmt.Errorf("source and destination are the same directory: %s", srcDir)
	}
	if _, err := os.Stat(destAbs); err == nil {
		return fmt.Errorf("refusing to overwrite existing release benchmark directory %s", destDir)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("stat release benchmark directory %s: %w", destDir, err)
	}
	if err := os.MkdirAll(filepath.Dir(destAbs), 0o755); err != nil {
		return fmt.Errorf("create release benchmark root: %w", err)
	}
	return filepath.WalkDir(srcAbs, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcAbs, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destAbs, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to stage symlinked benchmark artifact %s", path)
		}
		if d.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to stage non-regular benchmark artifact %s", path)
		}
		return copyFile(path, target, info.Mode().Perm())
	})
}

var benchmarkSummaryCitationRE = regexp.MustCompile(`perf/(?:results|release-results)/[A-Za-z0-9][A-Za-z0-9._/-]*/summary\.json`)

func checkCitationFile(cmd *cobra.Command, root, path string, noPerformanceClaims bool) (int, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, fmt.Errorf("read citation file %s: %w", path, err)
	}
	var citations int
	var failures int
	text := string(data)
	if noPerformanceClaims {
		for _, finding := range perfreport.PerformanceClaimFindings(text) {
			failures++
			cmd.Printf("%s:%d: error: performance claim is not allowed because release-benchmark evidence is missing/not_applicable: %s\n", path, finding.Line, finding.String())
		}
	}
	for lineNo, line := range strings.Split(text, "\n") {
		for _, ref := range benchmarkSummaryCitationRE.FindAllString(line, -1) {
			citations++
			if err := checkBenchmarkCitation(root, ref); err != nil {
				failures++
				cmd.Printf("%s:%d: error: %s\n", path, lineNo+1, err)
				cmd.Printf("%s:%d: command: ngfwperf verify --strict --publishable %s\n", path, lineNo+1, ref)
				continue
			}
			cmd.Printf("%s:%d: ok: %s is release-citable\n", path, lineNo+1, ref)
		}
	}
	return citations, failures, nil
}

func checkBenchmarkCitation(root, ref string) error {
	if strings.HasPrefix(ref, "perf/results/") {
		return fmt.Errorf("%s cites the engineering benchmark archive; stage publishable evidence under perf/release-results before using it in release notes, external publication, or comparison claims", ref)
	}
	if !strings.HasPrefix(ref, "perf/release-results/") {
		return nil
	}
	path := filepath.Join(root, filepath.FromSlash(ref))
	result, err := perfreport.ValidateSummaryFile(path)
	if err != nil {
		return fmt.Errorf("%s cannot be loaded: %w", ref, err)
	}
	gate := perfreport.EvaluatePublicationGate(result, true)
	if len(result.Errors) > 0 || len(result.Warnings) > 0 || !gate.Publishable() {
		return fmt.Errorf("%s is not release-citable: %d error(s), %d warning(s), publication gate=%s", ref, len(result.Errors), len(result.Warnings), gate.Label)
	}
	return nil
}

func copyFile(src, dest string, perm fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", dest, err)
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return fmt.Errorf("copy %s to %s: %w", src, dest, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close %s: %w", dest, closeErr)
	}
	return nil
}

func shouldPrintRepairSteps(result perfreport.ValidationResult, publishable bool, gate perfreport.PublicationGate) bool {
	if len(result.Errors) > 0 || len(result.Warnings) > 0 {
		return true
	}
	return publishable && !gate.Publishable()
}

func printPublicationGate(cmd *cobra.Command, path string, gate perfreport.PublicationGate) {
	cmd.Printf("%s: gate: %s (%s): %s\n", path, gate.Label, gate.State, gate.Title)
	for _, item := range gate.Items {
		if item.State == perfreport.GateOK {
			continue
		}
		if item.Detail != "" {
			cmd.Printf("%s: gate %s: %s: %s - %s\n", path, item.State, item.Label, item.Title, item.Detail)
		} else {
			cmd.Printf("%s: gate %s: %s: %s\n", path, item.State, item.Label, item.Title)
		}
	}
}

func printRepairSteps(cmd *cobra.Command, path string, steps []perfreport.RepairStep) {
	for _, step := range steps {
		if step.Level == "low" {
			continue
		}
		if step.Detail != "" {
			cmd.Printf("%s: next action %s: %s - %s\n", path, step.Level, step.Title, step.Detail)
		} else {
			cmd.Printf("%s: next action %s: %s\n", path, step.Level, step.Title)
		}
		if step.Command != "" {
			cmd.Printf("%s: command: %s\n", path, step.Command)
		}
	}
}

func summaryFiles(args []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			if filepath.Base(arg) != "summary.json" {
				return nil, fmt.Errorf("%s is not a summary.json file", arg)
			}
			if !seen[arg] {
				seen[arg] = true
				out = append(out, arg)
			}
			continue
		}
		if err := filepath.WalkDir(arg, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || filepath.Base(path) != "summary.json" {
				return nil
			}
			if !seen[path] {
				seen[path] = true
				out = append(out, path)
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}
