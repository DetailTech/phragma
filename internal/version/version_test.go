package version

import "testing"

func TestString(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		commit    string
		buildDate string
		want      string
	}{
		{
			name:      "defaults",
			version:   "dev",
			commit:    "unknown",
			buildDate: "unknown",
			want:      "dev (commit unknown, built unknown)",
		},
		{
			name:      "release",
			version:   "v0.1.0",
			commit:    "abc1234",
			buildDate: "2026-06-10T00:00:00Z",
			want:      "v0.1.0 (commit abc1234, built 2026-06-10T00:00:00Z)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origVersion, origCommit, origDate := Version, Commit, BuildDate
			t.Cleanup(func() { Version, Commit, BuildDate = origVersion, origCommit, origDate })
			Version, Commit, BuildDate = tt.version, tt.commit, tt.buildDate
			if got := String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
