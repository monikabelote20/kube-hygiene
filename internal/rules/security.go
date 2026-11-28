package rules

import (
	"fmt"
	"strings"

	"github.com/monikabelote20/kube-hygiene/internal/manifest"
)

// RunAsRoot flags containers that run, or may run, as UID 0.
//
// A container is considered non-root when runAsNonRoot is true or runAsUser is
// a non-zero UID, at container level or inherited from the pod. Anything else
// depends on the image's USER line, which the cluster cannot vouch for.
type RunAsRoot struct{}

// ID implements Rule.
func (RunAsRoot) ID() string { return "run-as-root" }

// Severity implements Rule.
func (RunAsRoot) Severity() Severity { return Warning }

// Description implements Rule.
func (RunAsRoot) Description() string {
	return "Containers should set runAsNonRoot: true or a non-zero runAsUser"
}

// Check implements Rule.
func (r RunAsRoot) Check(w manifest.Workload) []Finding {
	var out []Finding
	for _, c := range allContainers(w) {
		nonRoot, uid := effectiveUser(w.PodSpec.SecurityContext, c.SecurityContext)
		var msg string
		switch {
		case uid != nil && *uid == 0:
			msg = "runs as root (runAsUser: 0)"
		case uid != nil && *uid > 0:
			continue
		case nonRoot != nil && *nonRoot:
			continue
		default:
			msg = "may run as root: set runAsNonRoot: true or a non-zero runAsUser"
		}
		out = append(out, Finding{Rule: r.ID(), Workload: w.Ref(), Container: c.Name, Message: msg})
	}
	return out
}

// effectiveUser applies Kubernetes precedence: container settings override pod settings.
func effectiveUser(pod *manifest.PodSecurityContext, ctr *manifest.SecurityContext) (*bool, *int64) {
	var nonRoot *bool
	var uid *int64
	if pod != nil {
		nonRoot, uid = pod.RunAsNonRoot, pod.RunAsUser
	}
	if ctr != nil {
		if ctr.RunAsNonRoot != nil {
			nonRoot = ctr.RunAsNonRoot
		}
		if ctr.RunAsUser != nil {
			uid = ctr.RunAsUser
		}
	}
	return nonRoot, uid
}

// Privileged flags privileged containers and containers that allow privilege
// escalation (allowPrivilegeEscalation defaults to true when unset).
type Privileged struct{}

// ID implements Rule.
func (Privileged) ID() string { return "privileged" }

// Severity implements Rule.
func (Privileged) Severity() Severity { return Error }

// Description implements Rule.
func (Privileged) Description() string {
	return "Containers should not be privileged and should set allowPrivilegeEscalation: false"
}

// Check implements Rule.
func (r Privileged) Check(w manifest.Workload) []Finding {
	var out []Finding
	for _, c := range allContainers(w) {
		sc := c.SecurityContext
		var problems []string
		if sc != nil && sc.Privileged != nil && *sc.Privileged {
			problems = append(problems, "privileged: true")
		}
		if sc == nil || sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
			problems = append(problems, "allowPrivilegeEscalation is not false")
		}
		if len(problems) > 0 {
			out = append(out, Finding{
				Rule:      r.ID(),
				Workload:  w.Ref(),
				Container: c.Name,
				Message:   strings.Join(problems, "; "),
			})
		}
	}
	return out
}

// HostAccess flags pods that mount node directories or share the node's network.
type HostAccess struct{}

// ID implements Rule.
func (HostAccess) ID() string { return "host-access" }

// Severity implements Rule.
func (HostAccess) Severity() Severity { return Error }

// Description implements Rule.
func (HostAccess) Description() string {
	return "Pods should not mount hostPath volumes or use the host network"
}

// Check implements Rule.
func (r HostAccess) Check(w manifest.Workload) []Finding {
	var out []Finding
	for _, v := range w.PodSpec.Volumes {
		if v.HostPath != nil {
			out = append(out, Finding{
				Rule:     r.ID(),
				Workload: w.Ref(),
				Message:  fmt.Sprintf("volume %q mounts host path %s", v.Name, v.HostPath.Path),
			})
		}
	}
	if w.PodSpec.HostNetwork {
		out = append(out, Finding{Rule: r.ID(), Workload: w.Ref(), Message: "uses hostNetwork: true"})
	}
	return out
}
