//go:build integration

package integration

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyRestoreDrillCheckReportsReleaseEvidenceSentinels(t *testing.T) {
	root := releaseRepoRoot(t)
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not found")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not found")
	}

	cmd := exec.Command("bash", filepath.Join(root, "release", "policy-restore-drill.sh"), "--check")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		t.Fatalf("policy restore drill failed: %v\n%s", err, output)
	}
	for _, want := range []string{
		"check=policy-restore-drill",
		"mode=check",
		"restore_drill_scope=policy-version-rollback,validation,impact-ack,runtime-ack,audit-comment,audit-log,running-pointer,last-known-good,engine-apply",
		"automated_tests=TestPolicyRollbackRecordsIntentAuditAndAppliesEngines,TestPolicyRollbackRequiresAckRiskForHighRiskImpact,TestPolicyRollbackRequiresAckRuntimeForRuntimeWarnings,TestPolicyRollbackUsesOperatorComment",
		"restore_surface=PolicyService.Rollback,ngfwctl-rollback-preflight,store-version-history,audit-chain",
		"run_requires=rootless,go-test,temp-boltdb,in-process-policy-server,recording-engine",
		"status=passed",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("policy restore drill output missing %q:\n%s", want, output)
		}
	}
}
