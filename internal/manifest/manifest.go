// Package manifest decodes Kubernetes objects from `kubectl get -o json` output
// and extracts the pod template from each workload kind.
package manifest

import (
	"encoding/json"
	"fmt"
	"io"
)

// Object is the subset of a Kubernetes object that the rules need.
type Object struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	// Spec is decoded lazily because its shape depends on Kind.
	Spec json.RawMessage `json:"spec"`
}

// Metadata holds identifying fields.
type Metadata struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

// PodSpec is the part of a pod template the rules inspect.
type PodSpec struct {
	Containers      []Container         `json:"containers"`
	InitContainers  []Container         `json:"initContainers"`
	SecurityContext *PodSecurityContext `json:"securityContext"`
	Volumes         []Volume            `json:"volumes"`
	HostNetwork     bool                `json:"hostNetwork"`
}

// PodSecurityContext holds pod-level defaults that containers inherit.
type PodSecurityContext struct {
	RunAsNonRoot *bool  `json:"runAsNonRoot"`
	RunAsUser    *int64 `json:"runAsUser"`
}

// SecurityContext holds container-level settings; set fields override the pod's.
type SecurityContext struct {
	Privileged               *bool  `json:"privileged"`
	AllowPrivilegeEscalation *bool  `json:"allowPrivilegeEscalation"`
	RunAsNonRoot             *bool  `json:"runAsNonRoot"`
	RunAsUser                *int64 `json:"runAsUser"`
}

// Volume is a pod volume; only hostPath matters to the rules today.
type Volume struct {
	Name     string    `json:"name"`
	HostPath *HostPath `json:"hostPath"`
}

// HostPath is a volume backed by a directory on the node.
type HostPath struct {
	Path string `json:"path"`
}

// Container describes one container in a pod spec.
type Container struct {
	Name            string           `json:"name"`
	Image           string           `json:"image"`
	Resources       Resources        `json:"resources"`
	LivenessProbe   *json.RawMessage `json:"livenessProbe"`
	ReadinessProbe  *json.RawMessage `json:"readinessProbe"`
	SecurityContext *SecurityContext `json:"securityContext"`
}

// Resources holds container requests and limits, e.g. {"cpu": "100m"}.
type Resources struct {
	Requests map[string]string `json:"requests"`
	Limits   map[string]string `json:"limits"`
}

// Workload is an object paired with its pod spec.
type Workload struct {
	Object  Object
	PodSpec PodSpec
}

// Ref returns "Kind/namespace/name" for messages.
func (w Workload) Ref() string {
	ns := w.Object.Metadata.Namespace
	if ns == "" {
		ns = "default"
	}
	return fmt.Sprintf("%s/%s/%s", w.Object.Kind, ns, w.Object.Metadata.Name)
}

type list struct {
	Kind  string   `json:"kind"`
	Items []Object `json:"items"`
}

// Decode reads one JSON document: a single object or a List (as produced by
// `kubectl get deploy,sts -A -o json`). Several concatenated documents are
// also accepted.
func Decode(r io.Reader) ([]Object, error) {
	dec := json.NewDecoder(r)
	var objects []Object
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("decode manifest: %w", err)
		}
		var l list
		if err := json.Unmarshal(raw, &l); err != nil {
			return nil, fmt.Errorf("decode manifest: %w", err)
		}
		if l.Items != nil || l.Kind == "List" {
			objects = append(objects, l.Items...)
			continue
		}
		var obj Object
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, fmt.Errorf("decode manifest: %w", err)
		}
		objects = append(objects, obj)
	}
	return objects, nil
}

// Workloads keeps the objects that carry a pod template and extracts it.
// Unknown kinds are skipped.
func Workloads(objects []Object) ([]Workload, error) {
	var out []Workload
	for _, obj := range objects {
		spec, ok, err := podSpec(obj)
		if err != nil {
			return nil, fmt.Errorf("%s/%s: %w", obj.Kind, obj.Metadata.Name, err)
		}
		if ok {
			out = append(out, Workload{Object: obj, PodSpec: spec})
		}
	}
	return out, nil
}

func podSpec(obj Object) (PodSpec, bool, error) {
	var spec PodSpec
	switch obj.Kind {
	case "Pod":
		err := json.Unmarshal(obj.Spec, &spec)
		return spec, err == nil, err
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job":
		var s struct {
			Template struct {
				Spec PodSpec `json:"spec"`
			} `json:"template"`
		}
		err := json.Unmarshal(obj.Spec, &s)
		return s.Template.Spec, err == nil, err
	case "CronJob":
		var s struct {
			JobTemplate struct {
				Spec struct {
					Template struct {
						Spec PodSpec `json:"spec"`
					} `json:"template"`
				} `json:"spec"`
			} `json:"jobTemplate"`
		}
		err := json.Unmarshal(obj.Spec, &s)
		return s.JobTemplate.Spec.Template.Spec, err == nil, err
	default:
		return spec, false, nil
	}
}
