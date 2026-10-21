# EnrichedLab OpenShell

A downstream build of [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) for self-hosted Kubernetes clusters
that run research and operations agents. It tracks upstream releases and adds what a shared research cluster needs:
microVM sandboxes, fast starts for many concurrent agents, cluster-owned labels, and a verifiable record of every run.

Upstream's own documentation is in [README.md](../README.md) and at
[docs.nvidia.com/openshell](https://docs.nvidia.com/openshell/). This fork is not affiliated with or endorsed by
NVIDIA.

## Base

| | |
| --- | --- |
| Upstream release | v0.1.5 |
| Default branch | `enrichedlab/main` (upstream release plus the changes below) |
| Images | `ghcr.io/richardstoker-usda/enrichedlab-openshell/{gateway,supervisor,sandbox}`, linux/amd64 and linux/arm64 |
| License | Apache 2.0, as upstream |

## Changes from upstream

| Change | Status |
| --- | --- |
| Images built in this repository's CI with a signed SLSA build provenance attestation per image | available |
| Merge-based tracking of upstream releases, with a preview branch on upstream `main` | available |
| Sandbox Pods run in Kata Containers microVMs (Cloud Hypervisor) through a RuntimeClass | in testing; configuration only, no code change |
| Agent Sandbox warm pools: claim a pre-started sandbox before creating a cold one | in progress |
| Operator-fixed Pod labels and annotations, for clusters whose admission policy requires them | in progress |
| Retention class and expiry on every sandbox object | in progress |
| A run receipt per sandbox: policy and image digests, runtime, OCSF event counts, exit status, output checksums | in progress |

Changes that are useful beyond one site are offered upstream; this table shrinks as they land.

## Verify an image

```shell
gh attestation verify oci://ghcr.io/richardstoker-usda/enrichedlab-openshell/gateway@sha256:<digest> \
  --repo RichardStoker-USDA/enrichedlab-openshell
```

Deploy by digest, never by tag.

## Maintaining

Branch model, sync script and release tags: [FORK.md](../FORK.md).
