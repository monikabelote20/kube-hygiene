package main

import (
	"bytes"
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
	if !strings.Contains(out.String(), "Deployment/shop/api [api] missing requests.cpu") {
		t.Errorf("unexpected output:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "1 workloads checked, 2 findings") {
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
