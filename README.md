# kube-hygiene

[![ci](https://github.com/monikabelote20/kube-hygiene/actions/workflows/ci.yml/badge.svg)](https://github.com/monikabelote20/kube-hygiene/actions/workflows/ci.yml)

_Built and maintained with an AI coding agent (Claude, by Anthropic) under the direction of [@monikabelote20](https://github.com/monikabelote20)._

A small, zero-dependency Go CLI that lints Kubernetes workloads for reliability and security gaps.

It reads the JSON that `kubectl get -o json` prints, so it works against a live cluster without
needing cluster credentials of its own, and against JSON manifests in CI.

```bash
kubectl get deploy,sts,ds,cronjob -A -o json | kube-hygiene
kube-hygiene -f rendered.json -format json
```

```
image-tag    CronJob/ops/backup               [backup]  image bitnami/kubectl:latest uses the :latest tag
privileged   CronJob/ops/backup               [backup]  allowPrivilegeEscalation is not false
resources    CronJob/ops/backup               [backup]  missing requests.memory, limits.memory
run-as-root  CronJob/ops/backup               [backup]  may run as root: set runAsNonRoot: true or a non-zero runAsUser
host-access  DaemonSet/monitoring/node-agent            volume "proc" mounts host path /proc
resources    Deployment/shop/api              [api]     missing requests.cpu, limits.memory
probes       Deployment/shop/worker           [worker]  missing livenessProbe

14 workloads checked, 7 findings
```

## Output formats

`-format text` (default) prints an aligned table. `-format json` adds a per-rule summary for
scripts and dashboards. `-format sarif` writes SARIF 2.1.0, which GitHub code scanning can show
as alerts on the file you linted:

```yaml
- run: kube-hygiene -f deploy/rendered.json -format sarif > kube-hygiene.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: kube-hygiene.sarif
```

Each SARIF result carries a stable fingerprint (rule + workload + container), so alerts are
tracked across runs instead of reappearing as new.

## Rules

| Rule | What it checks |
|------|----------------|
| `resources` | Every container (including init containers) sets CPU and memory requests and a memory limit. CPU limits are not required on purpose. |
| `image-tag` | Images are not untagged or `:latest`. Digest-pinned images (`@sha256:...`) always pass. |
| `probes` | Long-running containers define readiness and liveness probes. Jobs, CronJobs and init containers are skipped. |
| `run-as-root` | Containers set `runAsNonRoot: true` or a non-zero `runAsUser` (container level, or inherited from the pod). `runAsUser: 0` is reported explicitly. |
| `privileged` | Containers are not `privileged` and set `allowPrivilegeEscalation: false` (it defaults to true when unset). |
| `host-access` | Pods don't mount `hostPath` volumes or use `hostNetwork`. |

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
