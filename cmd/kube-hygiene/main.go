// Command kube-hygiene lints Kubernetes workloads read from `kubectl get -o json`.
//
//	kubectl get deploy,sts,ds,cronjob -A -o json | kube-hygiene
//	kube-hygiene -f workloads.json -fail-on error
//
// Exit codes: 0 no blocking findings, 1 findings at or above -fail-on,
// 2 usage or input error.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/monikabelote20/kube-hygiene/internal/manifest"
	"github.com/monikabelote20/kube-hygiene/internal/output"
	"github.com/monikabelote20/kube-hygiene/internal/rules"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("kube-hygiene", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("f", "-", "JSON file to read (- for stdin)")
	format := fs.String("format", "text", "output format: "+strings.Join(output.Formats, ", "))
	minSeverity := fs.String("min-severity", "info", "hide findings below this severity: info, warning, error")
	failOn := fs.String("fail-on", "none", "exit 1 if any finding is at or above: none, info, warning, error")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}

	minSev, err := rules.ParseSeverity(*minSeverity)
	if err != nil {
		fmt.Fprintln(stderr, "error: -min-severity:", err)
		return 2
	}
	var failSev rules.Severity // zero means never fail
	if *failOn != "none" {
		if failSev, err = rules.ParseSeverity(*failOn); err != nil {
			fmt.Fprintln(stderr, "error: -fail-on:", err)
			return 2
		}
	}

	in, source := stdin, "stdin"
	if *file != "-" {
		f, err := os.Open(*file)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		defer f.Close()
		in, source = f, *file
	}

	objects, err := manifest.Decode(in)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	workloads, err := manifest.Workloads(objects)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}

	enabled := rules.Default()
	result := rules.Evaluate(enabled, workloads, minSev)
	report := output.Report{
		Source:     source,
		Workloads:  len(workloads),
		Findings:   result.Findings,
		Rules:      enabled,
		Version:    version,
		Suppressed: result.Suppressed,
	}
	if err := output.Write(stdout, *format, report); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	if failSev > 0 {
		for _, f := range result.Findings {
			if f.Severity >= failSev {
				return 1
			}
		}
	}
	return 0
}
