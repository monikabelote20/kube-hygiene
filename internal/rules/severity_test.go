package rules

import (
	"encoding/json"
	"testing"

	"github.com/monikabelote20/kube-hygiene/internal/manifest"
)

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{"info": Info, "WARNING": Warning, "warn": Warning, " error ": Error} {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("ParseSeverity(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseSeverity("critical"); err == nil {
		t.Error("expected an error for an unknown severity")
	}
}

func TestSeverityJSONRoundTrip(t *testing.T) {
	b, err := json.Marshal(Finding{Rule: "privileged", Severity: Error})
	if err != nil {
		t.Fatal(err)
	}
	var f Finding
	if err := json.Unmarshal(b, &f); err != nil || f.Severity != Error {
		t.Fatalf("round trip failed: %s -> %+v (%v)", b, f, err)
	}
}

func TestEveryDefaultRuleHasASeverity(t *testing.T) {
	for _, r := range Default() {
		if r.Severity() < Info || r.Severity() > Error {
			t.Errorf("%s has invalid severity %v", r.ID(), r.Severity())
		}
	}
}

func TestEvaluateFiltersBySeverity(t *testing.T) {
	w := workload("Deployment", manifest.Container{Name: "app", Image: "app"})

	all := Evaluate(Default(), []manifest.Workload{w}, Info).Findings
	errorsOnly := Evaluate(Default(), []manifest.Workload{w}, Error).Findings

	if len(errorsOnly) == 0 || len(errorsOnly) >= len(all) {
		t.Fatalf("expected a strict subset: all=%d errors=%d", len(all), len(errorsOnly))
	}
	for _, f := range errorsOnly {
		if f.Severity != Error {
			t.Errorf("finding below threshold: %+v", f)
		}
	}
}

func TestIgnoreAnnotation(t *testing.T) {
	w := workload("Deployment", manifest.Container{Name: "app", Image: "app:latest"})
	w.Object.Metadata.Annotations = map[string]string{IgnoreAnnotation: "image-tag, probes"}

	res := Evaluate([]Rule{ImageTag{}, Probes{}, Resources{}}, []manifest.Workload{w}, Info)

	if len(res.Findings) != 1 || res.Findings[0].Rule != "resources" {
		t.Errorf("unexpected findings: %+v", res.Findings)
	}
	if res.Suppressed != 2 {
		t.Errorf("suppressed = %d, want 2", res.Suppressed)
	}

	w.Object.Metadata.Annotations[IgnoreAnnotation] = "*"
	if got := Evaluate(Default(), []manifest.Workload{w}, Info).Findings; len(got) != 0 {
		t.Errorf("* should suppress everything, got %+v", got)
	}
}
