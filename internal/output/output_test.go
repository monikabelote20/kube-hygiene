package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/monikabelote20/kube-hygiene/internal/rules"
)

func sample() Report {
	return Report{
		Source:    "workloads.json",
		Workloads: 2,
		Version:   "1.2.3",
		Rules:     rules.Default(),
		Findings: []rules.Finding{
			{Rule: "resources", Severity: rules.Warning, Workload: "Deployment/shop/api", Container: "api", Message: "missing limits.memory"},
			{Rule: "privileged", Severity: rules.Error, Workload: "Deployment/shop/api", Container: "api", Message: "privileged: true"},
		},
	}
}

func TestTextAlignsColumnsAndSummarises(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "warning  resources   Deployment/shop/api  [api]  missing limits.memory") {
		t.Errorf("unexpected text output:\n%s", out)
	}
	if !strings.HasSuffix(out, "2 workloads checked, 2 findings (1 error, 1 warning)\n") {
		t.Errorf("missing summary:\n%s", out)
	}
}

func TestJSONReport(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	var got jsonReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Summary.Total != 2 || got.Summary.ByRule["resources"] != 1 || got.Summary.BySeverity["error"] != 1 ||
		got.Source != "workloads.json" {
		t.Errorf("unexpected report: %+v", got)
	}
}

func TestJSONEmptyFindingsIsAnArray(t *testing.T) {
	var buf bytes.Buffer
	r := sample()
	r.Findings = nil
	if err := JSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Errorf("findings should be [] not null:\n%s", buf.String())
	}
}

func TestSARIFStructure(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("bad envelope: %+v", log)
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "kube-hygiene" || run.Tool.Driver.Version != "1.2.3" {
		t.Errorf("bad driver: %+v", run.Tool.Driver)
	}
	if len(run.Tool.Driver.Rules) != len(rules.Default()) {
		t.Errorf("expected every rule described, got %d", len(run.Tool.Driver.Rules))
	}
	res := run.Results[0]
	if res.RuleID != "resources" || res.Locations[0].PhysicalLocation.ArtifactLocation.URI != "workloads.json" {
		t.Errorf("bad result: %+v", res)
	}
	if res.Message.Text != "Deployment/shop/api/api: missing limits.memory" || res.Level != "warning" {
		t.Errorf("unexpected result: %+v", res)
	}
	if run.Results[1].Level != "error" {
		t.Errorf("privileged should map to error, got %q", run.Results[1].Level)
	}
}

func TestFingerprintIsStableAndDistinct(t *testing.T) {
	a := rules.Finding{Rule: "resources", Workload: "Deployment/a/b", Container: "c"}
	b := a
	b.Container = "d"
	if fingerprint(a) != fingerprint(a) || fingerprint(a) == fingerprint(b) {
		t.Error("fingerprint must be deterministic and differ per container")
	}
}

func TestUnknownFormat(t *testing.T) {
	if err := Write(&bytes.Buffer{}, "yaml", sample()); err == nil {
		t.Error("expected an error for an unknown format")
	}
}

func TestSummaryLineMentionsSuppressed(t *testing.T) {
	r := sample()
	r.Suppressed = 3
	if got := summaryLine(r); got != "2 findings (1 error, 1 warning), 3 suppressed" {
		t.Errorf("summaryLine = %q", got)
	}
}
