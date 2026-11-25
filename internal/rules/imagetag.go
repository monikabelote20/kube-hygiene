package rules

import (
	"strings"

	"github.com/monikabelote20/kube-hygiene/internal/manifest"
)

// ImageTag flags images that use the `latest` tag or no tag at all.
//
// Both make rollouts non-reproducible: a node pulling the image tomorrow can get
// different bits than a node that pulled it today. Digest-pinned images
// (name@sha256:...) always pass.
type ImageTag struct{}

// ID implements Rule.
func (ImageTag) ID() string { return "image-tag" }

// Description implements Rule.
func (ImageTag) Description() string {
	return "Images should be pinned to a tag other than latest, or to a digest"
}

// Check implements Rule.
func (r ImageTag) Check(w manifest.Workload) []Finding {
	var out []Finding
	for _, c := range allContainers(w) {
		tag, digest := splitImage(c.Image)
		var msg string
		switch {
		case digest:
			continue
		case tag == "":
			msg = "image " + c.Image + " has no tag (resolves to :latest)"
		case tag == "latest":
			msg = "image " + c.Image + " uses the :latest tag"
		default:
			continue
		}
		out = append(out, Finding{Rule: r.ID(), Workload: w.Ref(), Container: c.Name, Message: msg})
	}
	return out
}

// splitImage returns the tag of an image reference and whether it is pinned by
// digest. A colon in the registry host (localhost:5000/app) is not a tag.
func splitImage(image string) (tag string, digest bool) {
	if strings.Contains(image, "@") {
		return "", true
	}
	lastSlash := strings.LastIndex(image, "/")
	name := image[lastSlash+1:]
	if i := strings.LastIndex(name, ":"); i >= 0 {
		return name[i+1:], false
	}
	return "", false
}
