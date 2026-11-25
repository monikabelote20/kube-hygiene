# kube-hygiene

[![ci](https://github.com/monikabelote20/kube-hygiene/actions/workflows/ci.yml/badge.svg)](https://github.com/monikabelote20/kube-hygiene/actions/workflows/ci.yml)

_Built and maintained with an AI coding agent (Claude, by Anthropic) under the direction of [@monikabelote20](https://github.com/monikabelote20)._

A small, zero-dependency Go CLI that lints Kubernetes workloads for reliability and security gaps.

It reads the JSON that `kubectl get -o json` prints, so it works against a live cluster without
needing cluster credentials of its own, and against JSON manifests in CI.

```bash
kubectl get deploy,sts,ds,cronjob -A -o json | kube-hygiene
```

```
resources  Deployment/shop/api [api] missing requests.cpu, limits.memory
resources  CronJob/ops/backup [backup] missing requests.memory, limits.memory
image-tag  CronJob/ops/backup [backup] image bitnami/kubectl:latest uses the :latest tag
probes     Deployment/shop/worker [worker] missing livenessProbe

14 workloads checked, 4 findings
```

## Rules

| Rule | What it checks |
|------|----------------|
| `resources` | Every container (including init containers) sets CPU and memory requests and a memory limit. CPU limits are not required on purpose. |
| `image-tag` | Images are not untagged or `:latest`. Digest-pinned images (`@sha256:...`) always pass. |
| `probes` | Long-running containers define readiness and liveness probes. Jobs, CronJobs and init containers are skipped. |

Supported kinds: Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob. Other objects
in the input are ignored.

## Install

```bash
go install github.com/monikabelote20/kube-hygiene/cmd/kube-hygiene@latest
```

or build from source with `make build`.

## Development

```bash
make test   # go test -race ./...
make lint   # go vet + gofmt check
```

## License

MIT
