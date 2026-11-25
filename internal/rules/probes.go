package rules

import (
	"strings"

	"github.com/monikabelote20/kube-hygiene/internal/manifest"
)

// Probes flags long-running containers without liveness or readiness probes.
//
// Without a readiness probe a Service sends traffic to pods that are still
// starting; without a liveness probe a deadlocked process is never restarted.
// Jobs, CronJobs and init containers run to completion, so they are skipped.
type Probes struct{}

// ID implements Rule.
func (Probes) ID() string { return "probes" }

// Description implements Rule.
func (Probes) Description() string {
	return "Long-running containers should define readiness and liveness probes"
}

// Check implements Rule.
func (r Probes) Check(w manifest.Workload) []Finding {
	switch w.Object.Kind {
	case "Job", "CronJob":
		return nil
	}
	var out []Finding
	for _, c := range w.PodSpec.Containers {
		var missing []string
		if c.ReadinessProbe == nil {
			missing = append(missing, "readinessProbe")
		}
		if c.LivenessProbe == nil {
			missing = append(missing, "livenessProbe")
		}
		if len(missing) > 0 {
			out = append(out, Finding{
				Rule:      r.ID(),
				Workload:  w.Ref(),
				Container: c.Name,
				Message:   "missing " + strings.Join(missing, ", "),
			})
		}
	}
	return out
}
