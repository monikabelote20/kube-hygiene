package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestRunReportsFindingsFromStdin(t *testing.T) {
	in := `{"kind":"Deployment","metadata":{"name":"api","namespace":"shop"},
"spec":{"template":{"spec":{"containers":[{"name":"api","image":"shop/api:1"}]}}}}`
	var out, errOut bytes.Buffer

	code := run(nil, strings.NewReader(in), &out, &errOut)

	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Deployment/shop/api  [api]  missing requests.cpu") {
		t.Errorf("unexpected output:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "1 workloads checked, 4 findings") {
		t.Errorf("missing summary line:\n%s", out.String())
	}
}

func TestRunFailsOnBadInput(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(nil, strings.NewReader("not json"), &out, &errOut); code != 2 {
		t.Fatalf("exit code %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "decode manifest") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestRunWritesSARIFWithFileSource(t *testing.T) {
	path := t.TempDir() + "/workloads.json"
	in := `{"kind":"Pod","metadata":{"name":"debug"},"spec":{"containers":[{"name":"sh","image":"busybox"}]}}`
	if err := os.WriteFile(path, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer

	code := run([]string{"-f", path, "-format", "sarif"}, strings.NewReader(""), &out, &errOut)

	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, errOut.String())
	}
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(out.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	results := log.Runs[0].Results
	if len(results) == 0 || results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != path {
		t.Errorf("unexpected results: %+v", results)
	}
}

func TestRunRejectsUnknownFormat(t *testing.T) {
	var out, errOut bytes.Buffer
	in := `{"kind":"Pod","metadata":{"name":"a"},"spec":{"containers":[]}}`
	if code := run([]string{"-format", "yaml"}, strings.NewReader(in), &out, &errOut); code != 2 {
		t.Fatalf("exit code %d, want 2", code)
	}
}
