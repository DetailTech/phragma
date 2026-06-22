package engines

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVectorWriteConfigRestrictsExistingFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vector.yaml")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	v := &Vector{StateDir: dir}
	gotPath, err := v.writeConfig([]byte("# openngfw-mode: enabled\n"))
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != path {
		t.Fatalf("config path = %q, want %q", gotPath, path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != vectorConfigFileMode {
		t.Fatalf("vector.yaml mode = %04o, want %04o", got, vectorConfigFileMode)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "# openngfw-mode: enabled\n" {
		t.Fatalf("vector.yaml content = %q", content)
	}
}
