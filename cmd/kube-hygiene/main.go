// Command kube-hygiene lints Kubernetes workloads read from `kubectl get -o json`.
//
//	kubectl get deploy,sts,ds,cronjob -A -o json | kube-hygiene
//	kube-hygiene -f workloads.json
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
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
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
	report := output.Report{
		Source:    source,
		Workloads: len(workloads),
		Findings:  rules.Run(enabled, workloads),
		Rules:     enabled,
		Version:   version,
	}
	if err := output.Write(stdout, *format, report); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	return 0
}
