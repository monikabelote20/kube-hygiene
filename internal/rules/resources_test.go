package rules

import (
	"testing"

	"github.com/monikabelote20/kube-hygiene/internal/manifest"
)

func workload(kind string, containers ...manifest.Container) manifest.Workload {
	return manifest.Workload{
		Object:  manifest.Object{Kind: kind, Metadata: manifest.Metadata{Name: "app", Namespace: "prod"}},
		PodSpec: manifest.PodSpec{Containers: containers},
	}
}

func TestResourcesFlagsMissingRequestsAndMemoryLimit(t *testing.T) {
	w := workload("Deployment", manifest.Container{Name: "web", Image: "web:1"})

	got := Resources{}.Check(w)

	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	want := "missing requests.cpu, requests.memory, limits.memory"
	if got[0].Message != want || got[0].Container != "web" || got[0].Workload != "Deployment/prod/app" {
		t.Errorf("unexpected finding: %+v", got[0])
	}
}

func TestResourcesAcceptsRequestsWithMemoryLimit(t *testing.T) {
	c := manifest.Container{
		Name:  "web",
		Image: "web:1",
		Resources: manifest.Resources{
			Requests: map[string]string{"cpu": "100m", "memory": "128Mi"},
			Limits:   map[string]string{"memory": "256Mi"},
		},
	}

	if got := (Resources{}).Check(workload("Deployment", c)); len(got) != 0 {
		t.Errorf("expected no findings, got %+v", got)
	}
}

func TestResourcesChecksInitContainers(t *testing.T) {
	ok := manifest.Container{Name: "app", Resources: manifest.Resources{
		Requests: map[string]string{"cpu": "1", "memory": "1Gi"},
		Limits:   map[string]string{"memory": "1Gi"},
	}}
	w := workload("StatefulSet", ok)
	w.PodSpec.InitContainers = []manifest.Container{{Name: "init-db"}}

	got := Resources{}.Check(w)

	if len(got) != 1 || got[0].Container != "init-db" {
		t.Errorf("expected one finding for init-db, got %+v", got)
	}
}

func TestRunSortsFindings(t *testing.T) {
	a := workload("Deployment", manifest.Container{Name: "z"}, manifest.Container{Name: "a"})
	b := workload("DaemonSet", manifest.Container{Name: "m"})

	got := Run([]Rule{Resources{}}, []manifest.Workload{a, b})

	if len(got) != 3 {
		t.Fatalf("got %d findings, want 3", len(got))
	}
	if got[0].Workload != "DaemonSet/prod/app" || got[1].Container != "a" || got[2].Container != "z" {
		t.Errorf("findings not sorted: %+v", got)
	}
}
