package rules

import (
	"testing"

	"github.com/monikabelote20/kube-hygiene/internal/manifest"
)

func TestSplitImage(t *testing.T) {
	cases := []struct {
		image  string
		tag    string
		digest bool
	}{
		{"nginx", "", false},
		{"nginx:1.27", "1.27", false},
		{"nginx:latest", "latest", false},
		{"ghcr.io/org/app:v2.0.1", "v2.0.1", false},
		{"localhost:5000/app", "", false},
		{"localhost:5000/app:dev", "dev", false},
		{"nginx@sha256:0f2a", "", true},
		{"registry.example.com:443/team/app:1.0@sha256:abcd", "", true},
	}
	for _, tc := range cases {
		tag, digest := splitImage(tc.image)
		if tag != tc.tag || digest != tc.digest {
			t.Errorf("splitImage(%q) = (%q, %v), want (%q, %v)", tc.image, tag, digest, tc.tag, tc.digest)
		}
	}
}

func TestImageTagRule(t *testing.T) {
	w := workload("Deployment",
		manifest.Container{Name: "untagged", Image: "redis"},
		manifest.Container{Name: "latest", Image: "busybox:latest"},
		manifest.Container{Name: "pinned", Image: "busybox:1.36"},
		manifest.Container{Name: "digest", Image: "busybox@sha256:abc"},
	)

	got := ImageTag{}.Check(w)

	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(got), got)
	}
	if got[0].Container != "untagged" || got[1].Container != "latest" {
		t.Errorf("unexpected findings: %+v", got)
	}
}
