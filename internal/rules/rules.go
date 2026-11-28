// Package rules contains the hygiene checks applied to each workload.
package rules

import (
	"sort"
	"strings"

	"github.com/monikabelote20/kube-hygiene/internal/manifest"
)

// IgnoreAnnotation lists rule IDs (comma-separated, or "*") to skip for a workload.
const IgnoreAnnotation = "kube-hygiene.io/ignore"

// Finding is one problem found in a workload.
type Finding struct {
	Rule      string   `json:"rule"`
	Severity  Severity `json:"severity"`
	Workload  string   `json:"workload"`
	Container string   `json:"container,omitempty"`
	Message   string   `json:"message"`
}

// Rule inspects a workload and reports findings.
type Rule interface {
	ID() string
	// Description is a one-line summary used in SARIF rule metadata.
	Description() string
	// Severity is applied to every finding the rule reports.
	Severity() Severity
	Check(w manifest.Workload) []Finding
}

// Default returns the rules enabled out of the box.
func Default() []Rule {
	return []Rule{
		Resources{},
		ImageTag{},
		Probes{},
		RunAsRoot{},
		Privileged{},
		HostAccess{},
	}
}

// allContainers returns init containers followed by regular containers.
func allContainers(w manifest.Workload) []manifest.Container {
	out := make([]manifest.Container, 0, len(w.PodSpec.InitContainers)+len(w.PodSpec.Containers))
	out = append(out, w.PodSpec.InitContainers...)
	return append(out, w.PodSpec.Containers...)
}

// Ignored reports whether the workload opts out of a rule via IgnoreAnnotation.
func Ignored(w manifest.Workload, ruleID string) bool {
	value, ok := w.Object.Metadata.Annotations[IgnoreAnnotation]
	if !ok {
		return false
	}
	for _, id := range strings.Split(value, ",") {
		id = strings.TrimSpace(id)
		if id == "*" || id == ruleID {
			return true
		}
	}
	return false
}

// Result is the outcome of evaluating rules against workloads.
type Result struct {
	Findings []Finding
	// Suppressed counts findings skipped because of IgnoreAnnotation.
	Suppressed int
}

// Evaluate applies every rule to every workload, drops findings below
// minSeverity, honours IgnoreAnnotation and sorts the result by workload,
// rule and container so output is stable.
func Evaluate(rules []Rule, workloads []manifest.Workload, minSeverity Severity) Result {
	var res Result
	for _, w := range workloads {
		for _, r := range rules {
			if r.Severity() < minSeverity {
				continue
			}
			found := r.Check(w)
			if Ignored(w, r.ID()) {
				res.Suppressed += len(found)
				continue
			}
			for _, f := range found {
				f.Severity = r.Severity()
				res.Findings = append(res.Findings, f)
			}
		}
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.Workload != b.Workload {
			return a.Workload < b.Workload
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Container < b.Container
	})
	return res
}

// Run evaluates all findings regardless of severity.
func Run(rules []Rule, workloads []manifest.Workload) []Finding {
	return Evaluate(rules, workloads, Info).Findings
}
