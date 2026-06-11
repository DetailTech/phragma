package engines

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeEngine records applied configs and can be told to fail.
type fakeEngine struct {
	name        string
	failApply   bool
	failRestore bool
	applied     []string
}

func (f *fakeEngine) Name() string                           { return f.name }
func (f *fakeEngine) Validate(context.Context, []byte) error { return nil }
func (f *fakeEngine) Apply(_ context.Context, cfg []byte) error {
	if f.failApply && string(cfg) != "prev" {
		return errors.New("boom")
	}
	if f.failRestore && string(cfg) == "prev" {
		return errors.New("restore boom")
	}
	f.applied = append(f.applied, string(cfg))
	return nil
}

func TestSupervisorApplyHappyPath(t *testing.T) {
	a, b := &fakeEngine{name: "a"}, &fakeEngine{name: "b"}
	sup := NewSupervisor(a, b)
	next := map[string][]byte{"a": []byte("new"), "b": []byte("new")}
	if err := sup.Apply(context.Background(), next, nil); err != nil {
		t.Fatal(err)
	}
	if len(a.applied) != 1 || len(b.applied) != 1 {
		t.Fatalf("applied: a=%v b=%v", a.applied, b.applied)
	}
}

func TestSupervisorRestoresOnFailure(t *testing.T) {
	a, b := &fakeEngine{name: "a"}, &fakeEngine{name: "b", failApply: true}
	sup := NewSupervisor(a, b)
	next := map[string][]byte{"a": []byte("new"), "b": []byte("new")}
	prev := map[string][]byte{"a": []byte("prev"), "b": []byte("prev")}

	err := sup.Apply(context.Background(), next, prev)
	if err == nil {
		t.Fatal("expected apply error")
	}
	// a was applied, then restored to prev.
	if len(a.applied) != 2 || a.applied[1] != "prev" {
		t.Fatalf("engine a not restored: %v", a.applied)
	}
}

func TestSupervisorReportsRestoreFailure(t *testing.T) {
	a := &fakeEngine{name: "a", failRestore: true}
	b := &fakeEngine{name: "b", failApply: true}
	sup := NewSupervisor(a, b)
	next := map[string][]byte{"a": []byte("new"), "b": []byte("new")}
	prev := map[string][]byte{"a": []byte("prev"), "b": []byte("prev")}

	err := sup.Apply(context.Background(), next, prev)
	if err == nil || !strings.Contains(err.Error(), "RESTORE FAILED") {
		t.Fatalf("restore failure must be surfaced, got: %v", err)
	}
}

func TestSupervisorSkipsEnginesWithoutArtifacts(t *testing.T) {
	a := &fakeEngine{name: "a"}
	sup := NewSupervisor(a)
	if err := sup.Apply(context.Background(), map[string][]byte{"other": []byte("x")}, nil); err != nil {
		t.Fatal(err)
	}
	if len(a.applied) != 0 {
		t.Fatalf("engine a should not have been applied: %v", a.applied)
	}
}

func TestRoutesValidate(t *testing.T) {
	r := &Routes{}
	good := []byte("route replace 10.0.0.0/8 via 10.0.0.1\n\nroute replace 0.0.0.0/0 dev eth0\n")
	if err := r.Validate(context.Background(), good); err != nil {
		t.Fatal(err)
	}
	bad := []byte("route del 10.0.0.0/8\n")
	if err := r.Validate(context.Background(), bad); err == nil {
		t.Fatal("expected validation error for non-replace statement")
	}
}
