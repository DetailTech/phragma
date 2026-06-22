package releaseacceptance

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// RecordabilityStatus reports whether release evidence can be recorded from
// the current source checkout. It is advisory preflight state, not release
// evidence and not part of the release-acceptance ready calculation.
type RecordabilityStatus struct {
	Ready              bool     `json:"ready"`
	GitHead            string   `json:"git_head,omitempty"`
	RecordCommit       string   `json:"record_commit,omitempty"`
	AllowedDirtyPaths  []string `json:"allowed_dirty_paths,omitempty"`
	DirtySourcePaths   []string `json:"dirty_source_paths,omitempty"`
	StaleEvidencePaths []string `json:"stale_evidence_paths,omitempty"`
	Problems           []string `json:"problems,omitempty"`
}

// EvaluateRecordability checks whether ngfwrelease record can safely write
// passing evidence from the current git checkout.
func EvaluateRecordability(evidenceDir, commit string) RecordabilityStatus {
	status := RecordabilityStatus{RecordCommit: normalizeCommit(commit)}
	root, err := currentGitRoot()
	if err != nil {
		status.Problems = append(status.Problems, fmt.Sprintf("record requires a readable git checkout to verify source-tree cleanliness: %v", err))
		return status
	}
	head, err := currentGitHead(root)
	if err != nil {
		status.Problems = append(status.Problems, fmt.Sprintf("record requires a readable git checkout to verify source-tree cleanliness: %v", err))
		return status
	}
	status.GitHead = head
	if status.RecordCommit == "" {
		status.RecordCommit = head
	} else if !isFullCommitHex(status.RecordCommit) {
		status.Problems = append(status.Problems, "record commit must be a full 40-character hex git commit")
	} else if status.RecordCommit != head {
		status.Problems = append(status.Problems, fmt.Sprintf("record commit %s does not match git HEAD %s", status.RecordCommit, head))
	}
	allowedPrefixes, err := recordAllowedDirtyPrefixes(evidenceDir, root)
	if err != nil {
		status.Problems = append(status.Problems, err.Error())
	} else {
		status.AllowedDirtyPaths = allowedPrefixes
	}
	dirtyPaths, err := currentGitDirtyPaths(root)
	if err != nil {
		status.Problems = append(status.Problems, fmt.Sprintf("record requires a readable git checkout to verify source-tree cleanliness: %v", err))
		return status
	}
	for _, entry := range dirtyPaths {
		if recordDirtyPathAllowed(entry.Path, allowedPrefixes) {
			continue
		}
		status.DirtySourcePaths = append(status.DirtySourcePaths, formatDirtyPath(entry))
	}
	sort.Strings(status.DirtySourcePaths)
	if len(status.DirtySourcePaths) > 0 {
		status.Problems = append(status.Problems, "release source tree has uncommitted changes outside allowed release artifact paths")
	}
	if isFullCommitHex(status.RecordCommit) && len(allowedPrefixes) > 0 {
		staleEvidence, err := staleEvidencePaths(evidenceDir, root, status.RecordCommit)
		if err != nil {
			status.Problems = append(status.Problems, err.Error())
		} else {
			status.StaleEvidencePaths = staleEvidence
		}
	}
	if len(status.StaleEvidencePaths) > 0 {
		status.Problems = append(status.Problems, "release evidence directory contains artifacts recorded for a different commit")
	}
	status.Ready = len(status.Problems) == 0
	return status
}

// WriteRecordabilityText writes the human-readable checkout preflight used by
// ngfwrelease status --recordability.
func WriteRecordabilityText(stdout io.Writer, status RecordabilityStatus) error {
	state := "ready"
	if !status.Ready {
		state = "blocked"
	}
	if _, err := fmt.Fprintf(stdout, "\nrecordability: %s\n", state); err != nil {
		return fmt.Errorf("write release recordability status: %w", err)
	}
	if status.GitHead != "" {
		if _, err := fmt.Fprintf(stdout, "  git_head: %s\n", status.GitHead); err != nil {
			return fmt.Errorf("write release recordability status: %w", err)
		}
	}
	if status.RecordCommit != "" {
		if _, err := fmt.Fprintf(stdout, "  record_commit: %s\n", status.RecordCommit); err != nil {
			return fmt.Errorf("write release recordability status: %w", err)
		}
	}
	if len(status.AllowedDirtyPaths) > 0 {
		if _, err := fmt.Fprintf(stdout, "  allowed_dirty_paths: %s\n", strings.Join(status.AllowedDirtyPaths, ", ")); err != nil {
			return fmt.Errorf("write release recordability status: %w", err)
		}
	}
	for _, problem := range status.Problems {
		if _, err := fmt.Fprintf(stdout, "  problem: %s\n", problem); err != nil {
			return fmt.Errorf("write release recordability status: %w", err)
		}
	}
	if len(status.DirtySourcePaths) > 0 {
		if _, err := fmt.Fprintf(stdout, "  dirty_source_paths: %s\n", strings.Join(LimitStrings(status.DirtySourcePaths, 20), ", ")); err != nil {
			return fmt.Errorf("write release recordability status: %w", err)
		}
		if _, err := fmt.Fprintln(stdout, "  next: commit or stash source changes before recording release evidence"); err != nil {
			return fmt.Errorf("write release recordability status: %w", err)
		}
	}
	if len(status.StaleEvidencePaths) > 0 {
		if _, err := fmt.Fprintf(stdout, "  stale_evidence_paths: %s\n", strings.Join(LimitStrings(status.StaleEvidencePaths, 20), ", ")); err != nil {
			return fmt.Errorf("write release recordability status: %w", err)
		}
		if _, err := fmt.Fprintln(stdout, "  next: move stale evidence out of release/evidence or re-record it with --overwrite for the accepted release commit before assembling acceptance"); err != nil {
			return fmt.Errorf("write release recordability status: %w", err)
		}
	}
	return nil
}

type dirtyGitPath struct {
	Status string
	Path   string
}

func currentGitRoot() (string, error) {
	raw, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", err
	}
	root := strings.TrimSpace(string(raw))
	if root == "" {
		return "", errors.New("git rev-parse --show-toplevel returned an empty path")
	}
	return canonicalPathAllowMissing(root), nil
}

func currentGitHead(root string) (string, error) {
	raw, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", err
	}
	commit := normalizeCommit(string(raw))
	if !isFullCommitHex(commit) {
		return "", fmt.Errorf("git rev-parse HEAD returned %q", strings.TrimSpace(string(raw)))
	}
	return commit, nil
}

func currentGitDirtyPaths(root string) ([]dirtyGitPath, error) {
	cmd := exec.Command("git", "-C", root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
	raw, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	entries := bytes.Split(raw, []byte{0})
	var out []dirtyGitPath
	for i := 0; i < len(entries); i++ {
		entry := entries[i]
		if len(entry) < 4 {
			continue
		}
		status := string(entry[:2])
		path := cleanGitStatusPath(string(entry[3:]))
		if path == "" {
			continue
		}
		out = append(out, dirtyGitPath{Status: status, Path: path})
		if gitStatusIncludesRenameOrCopy(status) && i+1 < len(entries) {
			i++
			oldPath := cleanGitStatusPath(string(entries[i]))
			if oldPath != "" {
				out = append(out, dirtyGitPath{Status: status, Path: oldPath})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path == out[j].Path {
			return out[i].Status < out[j].Status
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}

func gitStatusIncludesRenameOrCopy(status string) bool {
	return strings.ContainsAny(status, "RC")
}

func cleanGitStatusPath(path string) string {
	if path == "" {
		return ""
	}
	path = filepath.ToSlash(filepath.Clean(path))
	if path == "." {
		return ""
	}
	return path
}

func recordAllowedDirtyPrefixes(evidenceDir, root string) ([]string, error) {
	evidencePrefix := repoRelativePrefix(evidenceDir, root)
	if evidencePrefix == "" || !recordDirtyPathAllowed(evidencePrefix, []string{"release/evidence"}) {
		return nil, fmt.Errorf("record evidence directory %q must resolve inside release/evidence; passing evidence was not written", evidenceDir)
	}
	prefixes := []string{
		evidencePrefix,
		"perf/release-results",
		"release/field-evidence",
	}
	sort.Strings(prefixes)
	return compactStrings(prefixes), nil
}

func staleEvidencePaths(evidenceDir, root, commit string) ([]string, error) {
	evidencePrefix := repoRelativePrefix(evidenceDir, root)
	if evidencePrefix == "" {
		return nil, nil
	}
	evidencePath := filepath.Join(root, filepath.FromSlash(evidencePrefix))
	info, err := os.Stat(evidencePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("record requires a readable release evidence directory to detect stale evidence: %v", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("record evidence directory %q is not a directory", evidenceDir)
	}
	entries, err := os.ReadDir(evidencePath)
	if err != nil {
		return nil, fmt.Errorf("record requires a readable release evidence directory to detect stale evidence: %v", err)
	}
	var stale []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".txt") {
			continue
		}
		path := filepath.Join(evidencePath, name)
		rec, err := readEvidenceRecordFile(path)
		if err != nil {
			continue
		}
		rec.Commit = normalizeCommit(rec.Commit)
		if rec.Commit == "" || rec.Commit == commit {
			continue
		}
		repoPath := filepath.ToSlash(filepath.Join(evidencePrefix, name))
		stale = append(stale, fmt.Sprintf("%s (evidence commit %s != record commit %s)", repoPath, rec.Commit, commit))
	}
	sort.Strings(stale)
	return stale, nil
}

func repoRelativePrefix(path, root string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	var abs string
	if filepath.IsAbs(path) {
		abs = filepath.Clean(path)
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			return ""
		}
		abs = filepath.Clean(filepath.Join(cwd, path))
	}
	root = canonicalPathAllowMissing(root)
	abs = canonicalPathAllowMissing(abs)
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(rel))
}

func canonicalPathAllowMissing(path string) string {
	path = filepath.Clean(path)
	if path == "" {
		return path
	}
	var suffix []string
	for current := path; ; current = filepath.Dir(current) {
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return path
		}
		suffix = append(suffix, filepath.Base(current))
	}
}

func recordDirtyPathAllowed(path string, allowedPrefixes []string) bool {
	return RecordDirtyPathAllowed(path, allowedPrefixes)
}

// RecordDirtyPathAllowed reports whether a git status path may be dirty while
// recording release evidence.
func RecordDirtyPathAllowed(path string, allowedPrefixes []string) bool {
	path = filepath.ToSlash(filepath.Clean(path))
	for _, prefix := range allowedPrefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func compactStrings(values []string) []string {
	var out []string
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}

func formatDirtyPath(entry dirtyGitPath) string {
	status := strings.TrimSpace(entry.Status)
	if status == "" {
		return entry.Path
	}
	return status + " " + entry.Path
}

// LimitStrings returns values capped at limit with a final remainder marker.
func LimitStrings(values []string, limit int) []string {
	if limit <= 0 || len(values) <= limit {
		return values
	}
	out := append([]string(nil), values[:limit]...)
	out = append(out, fmt.Sprintf("...and %d more", len(values)-limit))
	return out
}
