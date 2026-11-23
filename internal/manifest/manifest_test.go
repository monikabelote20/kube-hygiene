package manifest

import (
	"strings"
	"testing"
)

const deploymentList = `{
  "apiVersion": "v1",
  "kind": "List",
  "items": [
    {
      "apiVersion": "apps/v1",
      "kind": "Deployment",
      "metadata": {"name": "api", "namespace": "shop"},
      "spec": {"template": {"spec": {"containers": [{"name": "api", "image": "shop/api:1.4.2"}]}}}
    },
    {
      "apiVersion": "v1",
      "kind": "Service",
      "metadata": {"name": "api", "namespace": "shop"},
      "spec": {"ports": [{"port": 80}]}
    },
    {
      "apiVersion": "batch/v1",
      "kind": "CronJob",
      "metadata": {"name": "nightly"},
      "spec": {"jobTemplate": {"spec": {"template": {"spec": {
        "initContainers": [{"name": "migrate", "image": "shop/migrate:2"}],
        "containers": [{"name": "report", "image": "shop/report:2"}]
      }}}}}
    }
  ]
}`

func TestDecodeListAndExtractWorkloads(t *testing.T) {
	objects, err := Decode(strings.NewReader(deploymentList))
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 3 {
		t.Fatalf("got %d objects, want 3", len(objects))
	}
	workloads, err := Workloads(objects)
	if err != nil {
		t.Fatal(err)
	}
	if len(workloads) != 2 {
		t.Fatalf("got %d workloads, want 2 (Service must be skipped)", len(workloads))
	}
	if got := workloads[0].Ref(); got != "Deployment/shop/api" {
		t.Errorf("Ref() = %q", got)
	}
	cron := workloads[1]
	if got := cron.Ref(); got != "CronJob/default/nightly" {
		t.Errorf("Ref() = %q, want default namespace filled in", got)
	}
	if len(cron.PodSpec.InitContainers) != 1 || cron.PodSpec.Containers[0].Image != "shop/report:2" {
		t.Errorf("CronJob pod spec not extracted: %+v", cron.PodSpec)
	}
}

func TestDecodeSingleObjectAndConcatenatedDocuments(t *testing.T) {
	in := `{"kind":"Pod","metadata":{"name":"a"},"spec":{"containers":[{"name":"c","image":"x:1"}]}}
{"kind":"Pod","metadata":{"name":"b"},"spec":{"containers":[{"name":"c","image":"x:1"}]}}`
	objects, err := Decode(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 2 || objects[1].Metadata.Name != "b" {
		t.Fatalf("unexpected objects: %+v", objects)
	}
}

func TestDecodeRejectsInvalidJSON(t *testing.T) {
	if _, err := Decode(strings.NewReader(`{"kind": "Pod",`)); err == nil {
		t.Fatal("expected an error for truncated JSON")
	}
}
