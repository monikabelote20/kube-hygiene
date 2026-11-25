package rules

import (
	"encoding/json"
	"testing"

	"github.com/monikabelote20/kube-hygiene/internal/manifest"
)

func probe() *json.RawMessage {
	raw := json.RawMessage(`{"httpGet":{"path":"/healthz","port":8080}}`)
	return &raw
}

func TestProbesFlagsMissingProbes(t *testing.T) {
	w := workload("Deployment",
		manifest.Container{Name: "none"},
		manifest.Container{Name: "ready-only", ReadinessProbe: probe()},
		manifest.Container{Name: "both", ReadinessProbe: probe(), LivenessProbe: probe()},
	)

	got := Probes{}.Check(w)

	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(got), got)
	}
	if got[0].Message != "missing readinessProbe, livenessProbe" {
		t.Errorf("message = %q", got[0].Message)
	}
	if got[1].Container != "ready-only" || got[1].Message != "missing livenessProbe" {
		t.Errorf("unexpected finding: %+v", got[1])
	}
}

func TestProbesSkipsRunToCompletionWorkloads(t *testing.T) {
	for _, kind := range []string{"Job", "CronJob"} {
		if got := (Probes{}).Check(workload(kind, manifest.Container{Name: "task"})); len(got) != 0 {
			t.Errorf("%s: expected no findings, got %+v", kind, got)
		}
	}
}

func TestProbesIgnoresInitContainers(t *testing.T) {
	w := workload("StatefulSet", manifest.Container{Name: "db", ReadinessProbe: probe(), LivenessProbe: probe()})
	w.PodSpec.InitContainers = []manifest.Container{{Name: "init-perms"}}

	if got := (Probes{}).Check(w); len(got) != 0 {
		t.Errorf("expected no findings, got %+v", got)
	}
}

func TestProbesDecodedFromJSON(t *testing.T) {
	in := `{"kind":"Deployment","metadata":{"name":"api"},"spec":{"template":{"spec":{"containers":[
{"name":"api","image":"api:1","livenessProbe":{"tcpSocket":{"port":80}},"readinessProbe":{"tcpSocket":{"port":80}}}]}}}}`
	var obj manifest.Object
	if err := json.Unmarshal([]byte(in), &obj); err != nil {
		t.Fatal(err)
	}
	ws, err := manifest.Workloads([]manifest.Object{obj})
	if err != nil {
		t.Fatal(err)
	}
	if got := (Probes{}).Check(ws[0]); len(got) != 0 {
		t.Errorf("expected probes to be detected from JSON, got %+v", got)
	}
}
