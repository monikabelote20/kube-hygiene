package rules

import (
	"fmt"
	"strings"

	"github.com/monikabelote20/kube-hygiene/internal/manifest"
)

// Resources flags containers without CPU/memory requests or a memory limit.
//
// Missing requests make scheduling and autoscaling guesswork; a missing memory
// limit lets one container starve its neighbours on the node. A CPU limit is
// deliberately not required because CPU throttling often hurts more than it
// helps.
type Resources struct{}

// ID implements Rule.
func (Resources) ID() string { return "resources" }

// Description implements Rule.
func (Resources) Description() string {
	return "Containers should set CPU and memory requests and a memory limit"
}

// Check implements Rule.
func (r Resources) Check(w manifest.Workload) []Finding {
	var out []Finding
	for _, c := range allContainers(w) {
		var missing []string
		for _, res := range []string{"cpu", "memory"} {
			if c.Resources.Requests[res] == "" {
				missing = append(missing, "requests."+res)
			}
		}
		if c.Resources.Limits["memory"] == "" {
			missing = append(missing, "limits.memory")
		}
		if len(missing) > 0 {
			out = append(out, Finding{
				Rule:      r.ID(),
				Workload:  w.Ref(),
				Container: c.Name,
				Message:   fmt.Sprintf("missing %s", strings.Join(missing, ", ")),
			})
		}
	}
	return out
}
