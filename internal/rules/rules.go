// Package rules contains the hygiene checks applied to each workload.
package rules

import (
	"sort"

	"github.com/monikabelote20/kube-hygiene/internal/manifest"
)

// Finding is one problem found in a workload.
type Finding struct {
	Rule      string `json:"rule"`
	Workload  string `json:"workload"`
	Container string `json:"container,omitempty"`
	Message   string `json:"message"`
}

// Rule inspects a workload and reports findings.
type Rule interface {
	ID() string
	// Description is a one-line summary used in SARIF rule metadata.
	Description() string
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

// Run applies every rule to every workload. Findings are sorted by workload,
// then rule, then container, so output is stable.
func Run(rules []Rule, workloads []manifest.Workload) []Finding {
	var out []Finding
	for _, w := range workloads {
		for _, r := range rules {
			out = append(out, r.Check(w)...)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Workload != b.Workload {
			return a.Workload < b.Workload
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Container < b.Container
	})
	return out
}
