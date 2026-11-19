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
| Upstream release | v0.1.9 |
| Fork releases | [Latest release](https://github.com/RichardStoker-USDA/enrichedlab-openshell/releases/latest). Release notes list image digests and verification commands for the CLI and chart. |
| Default branch | `enrichedlab/main` (upstream release plus the changes below) |
| Images | `ghcr.io/richardstoker-usda/enrichedlab-openshell/{gateway,supervisor,sandbox,cli,receipts}`, linux/amd64 and linux/arm64 |
| Chart | `oci://ghcr.io/richardstoker-usda/enrichedlab-openshell/charts/helm-chart` |
| License | Apache 2.0, as upstream |

## Changes from upstream

| Change | Status |
| --- | --- |
| Images, the static CLI and the Helm chart built in this repository's CI, each with a signed SLSA build provenance attestation | available |
| Merge-based tracking of upstream releases, with a preview branch on upstream `main` | available |
| Sandbox Pods run in Kata Containers microVMs (Cloud Hypervisor) through a RuntimeClass | in testing; configuration only, no code change |
| Fast sandbox starts with a shared supervisor | shared topology on v0.1.6 and later, with replica spreading in v0.1.9. The older v0.1.5 line carries warm pools |
| Operator-fixed labels and annotations on every Sandbox, workload and dedicated supervisor Pod and workspace claim (`fixed_pod_labels`, `fixed_pod_annotations`), for clusters whose admission, telemetry or retention policy requires them | available |
| Supervisor telemetry to the gateway's collector, a separate collector, or none (`supervisor_telemetry`), without forwarding the gateway's collector headers or TLS client keys | available |
| Retention class and expiry on every sandbox object | in progress |
| Operator-defined supervisor egress peers and ports | Shared supervisors use the Helm policy. Dedicated supervisors use the same rules from the Kubernetes driver configuration. |
| A failed initial workload Pod is reported during provisioning | The Kubernetes driver preserves the terminal Pod condition while the gateway awaits configuration admission. |
| Reap adopted children on kernels without task children lists | The runtime also reads the kernel process table. |
| Build tools and X server helpers can reapply the workload's current user and group IDs | The child filter checks scalar IDs. The workload listener verifies supplementary groups and acknowledges an unchanged list. [NVIDIA/OpenShell#4104](https://github.com/NVIDIA/OpenShell/pull/4104) |
| Capability-free workloads can repeat a capability drop | An unprivileged child with empty capability sets and an empty bounding set can clear its own capabilities. |
| Numeric workload pins support local account lookup | Two initializers stage the account helper and read the workload image's passwd and group files. The workload mounts read-only account files for the pinned identity. Existing account names, supplementary groups, and workspace ownership are preserved. |
| A run receipt per sandbox: policy and image digests, runtime, OCSF event counts, exit status, output checksums | in progress |

Changes that are useful beyond one site are offered upstream; this table shrinks as they land.

## Install and verify

Use the CLI and Helm chart listed in the same fork release. The release notes give the artifact names, image
digests, and download and verification commands. Follow the [upstream Kubernetes setup guide](https://docs.nvidia.com/openshell/)
for gateway setup and [FORK.md](../FORK.md) for the settings this fork adds.

Verify an image index before deploying it by digest.

```shell
gh attestation verify oci://ghcr.io/richardstoker-usda/enrichedlab-openshell/gateway@sha256:<digest> \
  --repo RichardStoker-USDA/enrichedlab-openshell
```

## Maintaining

Branch model, sync script and release tags: [FORK.md](../FORK.md).
