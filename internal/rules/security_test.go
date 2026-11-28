package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/monikabelote20/kube-hygiene/internal/manifest"
)

func ptr[T any](v T) *T { return &v }

func TestRunAsRoot(t *testing.T) {
	cases := []struct {
		name string
		pod  *manifest.PodSecurityContext
		ctr  *manifest.SecurityContext
		want string // "" means no finding
	}{
		{"nothing set", nil, nil, "may run as root"},
		{"pod runAsNonRoot", &manifest.PodSecurityContext{RunAsNonRoot: ptr(true)}, nil, ""},
		{"pod uid", &manifest.PodSecurityContext{RunAsUser: ptr(int64(10001))}, nil, ""},
		{"container overrides pod to root", &manifest.PodSecurityContext{RunAsNonRoot: ptr(true)},
			&manifest.SecurityContext{RunAsUser: ptr(int64(0))}, "runs as root (runAsUser: 0)"},
		{"container nonroot false", nil, &manifest.SecurityContext{RunAsNonRoot: ptr(false)}, "may run as root"},
		{"container uid", nil, &manifest.SecurityContext{RunAsUser: ptr(int64(1000))}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := workload("Deployment", manifest.Container{Name: "app", SecurityContext: tc.ctr})
			w.PodSpec.SecurityContext = tc.pod

			got := RunAsRoot{}.Check(w)

			if tc.want == "" {
				if len(got) != 0 {
					t.Errorf("expected no finding, got %+v", got)
				}
				return
			}
			if len(got) != 1 || !strings.HasPrefix(got[0].Message, tc.want) {
				t.Errorf("got %+v, want message starting %q", got, tc.want)
			}
		})
	}
}

func TestPrivileged(t *testing.T) {
	w := workload("DaemonSet",
		manifest.Container{Name: "unset"},
		manifest.Container{Name: "locked", SecurityContext: &manifest.SecurityContext{AllowPrivilegeEscalation: ptr(false)}},
		manifest.Container{Name: "priv", SecurityContext: &manifest.SecurityContext{
			Privileged: ptr(true), AllowPrivilegeEscalation: ptr(true)}},
	)

	got := Privileged{}.Check(w)

	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(got), got)
	}
	if got[0].Container != "unset" || got[0].Message != "allowPrivilegeEscalation is not false" {
		t.Errorf("unexpected finding: %+v", got[0])
	}
	if got[1].Message != "privileged: true; allowPrivilegeEscalation is not false" {
		t.Errorf("unexpected finding: %+v", got[1])
	}
}

func TestHostAccess(t *testing.T) {
	w := workload("DaemonSet", manifest.Container{Name: "agent"})
	w.PodSpec.Volumes = []manifest.Volume{
		{Name: "docker-sock", HostPath: &manifest.HostPath{Path: "/var/run/docker.sock"}},
		{Name: "config"},
	}
	w.PodSpec.HostNetwork = true

	got := HostAccess{}.Check(w)

	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(got), got)
	}
	if got[0].Message != `volume "docker-sock" mounts host path /var/run/docker.sock` || got[0].Container != "" {
		t.Errorf("unexpected finding: %+v", got[0])
	}
	if got[1].Message != "uses hostNetwork: true" {
		t.Errorf("unexpected finding: %+v", got[1])
	}
}

func TestSecurityFieldsDecodeFromJSON(t *testing.T) {
	in := `{"kind":"Deployment","metadata":{"name":"api"},"spec":{"template":{"spec":{
"securityContext":{"runAsNonRoot":true},
"volumes":[{"name":"logs","hostPath":{"path":"/var/log"}}],
"containers":[{"name":"api","image":"api:1","securityContext":{"allowPrivilegeEscalation":false,"runAsUser":0}}]}}}}`
	var obj manifest.Object
	if err := json.Unmarshal([]byte(in), &obj); err != nil {
		t.Fatal(err)
	}
	ws, err := manifest.Workloads([]manifest.Object{obj})
	if err != nil {
		t.Fatal(err)
	}
	w := ws[0]

	if got := (RunAsRoot{}).Check(w); len(got) != 1 || got[0].Message != "runs as root (runAsUser: 0)" {
		t.Errorf("run-as-root: %+v", got)
	}
	if got := (Privileged{}).Check(w); len(got) != 0 {
		t.Errorf("privileged: %+v", got)
	}
	if got := (HostAccess{}).Check(w); len(got) != 1 {
		t.Errorf("host-access: %+v", got)
	}
}
