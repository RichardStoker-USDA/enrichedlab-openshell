# Maintaining this fork

EnrichedLab OpenShell is a downstream fork of [NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell). Upstream's
code, license (Apache 2.0) and contribution rules apply unchanged; this file covers only what the fork adds.

## Branches

| Branch | Content | How it moves |
| --- | --- | --- |
| `main` | upstream `main`, unchanged | fast-forward only; never a local commit |
| `enrichedlab/main` | the newest upstream stable release plus the downstream changes (default branch) | upstream release tags are merged in; never rewritten or force-pushed |
| `enrichedlab/merge-<tag>` | a pending merge of one upstream release | built and tested by CI, then `enrichedlab/main` fast-forwards to it |
| `enrichedlab/next` | `enrichedlab/main` with upstream `main` merged in | rebuilt on every sync to show conflicts before the next release; may be force-updated |
| `upstream/<topic>` | a change offered upstream, cut from upstream `main` | its own pull request to NVIDIA/OpenShell |

Upstream releases come in by merge, not rebase, so anyone tracking `enrichedlab/main` can always pull it. Releases of
the fork are tags `vX.Y.Z-el.N` on `enrichedlab/main`, where `vX.Y.Z` is the upstream release it contains.

## Rules for downstream changes

- Extend through upstream's seams first (compute drivers, supervisor middleware, gateway interceptors, isolation
  backends, providers), in new crates named `crates/enrichedlab-*`, so a merge rarely touches the same lines.
- Patch upstream code only where no extension point exists. Such a commit carries a test and a link to the upstream
  issue or pull request that would make it unnecessary.
- Anything useful outside a single site goes upstream as a pull request from an `upstream/<topic>` branch; the
  downstream set shrinks as those land.
- No site detail: hostnames, addresses, identities, credentials and policies belong in the deploying site's own
  private repository. Examples use reserved values (`example.com`, `192.0.2.0/24`, `2001:db8::/32`).
- Commits carry a DCO sign-off (`git commit -s`), as upstream requires, so any of them can be offered upstream.

## Syncing

```shell
scripts/enrichedlab/sync-upstream.sh                 # fetch, fast-forward main, rebuild enrichedlab/next, report
scripts/enrichedlab/sync-upstream.sh --merge v0.1.6  # also prepare enrichedlab/merge-v0.1.6
scripts/enrichedlab/sync-upstream.sh --merge v0.1.6 --push origin
```

The script refuses to run on a dirty tree, never moves `enrichedlab/main`, and enables `git rerere` for this
repository so a conflict resolved once on `enrichedlab/next` is reused when the release is merged. After a merge
branch passes CI:

```shell
git switch enrichedlab/main
git merge --ff-only enrichedlab/merge-v0.1.6
git push origin enrichedlab/main
```

rerere replays conflicting hunks only. A fork change that has to move to new upstream code without a textual
conflict is listed here and checked by hand on every merge:

- Since v0.1.6 upstream creates every dedicated supervisor Pod in `create_sandbox_runtime_supervisor`; the fixed
  labels and annotations are applied there (`apply_fixed_pod_metadata`). A shared supervisor (`supervisor_topology =
  "gateway"`) is deployed by Helm, not per sandbox, so the fixed metadata does not reach it.
- The restart patch is built by `restart_running_patch`, which carries upstream's bootstrap annotations (including
  the control connection and supervisor topology keys added in v0.1.6) and then the operator's fixed metadata.
- Upstream writes the supervisor's auth bundle into its bootstrap Secret in `install_sandbox_runtime_generation`; the
  fork writes it through `supervisor_auth_json`, so a supervisor whose telemetry goes elsewhere never receives the
  gateway's collector headers.
- A shared supervisor gets its credentials from the gateway's launch bundle at registration, not from that Secret. The
  gateway therefore withholds the collector headers itself: the compute driver factory reports whether supervisors use
  the gateway's collector (`supervisors_use_gateway_collector`), and when they do not, no launch or registration bundle
  carries the headers (`withhold_supervisor_ocsf_headers`).
- Stored launch material never carries headers the gateway withholds: when supervisors export elsewhere, the
  supervisor pool removes them as it records, places or loads material (`launch_material_without_collector_headers`),
  and the Kubernetes driver removes them from a recovered shared generation's Secret. Material without headers is
  kept byte for byte, so a launch and its replay keep one admission fingerprint. While supervisors use the gateway's
  collector, stored material keeps the headers it was launched with until the next launch.
- Driver start validates both upstream's supervisor topology and the fork's fixed metadata.

## Carried upstream pull requests

None on the v0.1.6 line. [NVIDIA/OpenShell#3508](https://github.com/NVIDIA/OpenShell/pull/3508) (template-driven warm
pooling for the Kubernetes driver) was carried on v0.1.5 with three adaptations. v0.1.6 changed the supervisor's
gateway credentials to per-instance credentials for shared supervisors, and the pull request's registration path
depends on the earlier process-wide token, so carrying it is a port of its design, not a merge; its author is
rebasing it upstream. Until a version that applies to the current release exists, the v0.1.6 line has no warm pools:
v0.1.6's shared supervisor (`supervisor_topology = "gateway"`) is the measured alternative for start latency, and a
site that needs warm pools keeps the v0.1.5 line. The run receipt interceptor still matches a warm pair's Pods through
the pair id the Sandbox object names (`openshell.ai/warm-pair-id`); without warm pools that path is unused.

When pushing, the script also disables any upstream workflow GitHub has enabled in the fork. Upstream's workflows
expect NVIDIA's runners and secrets; the fork runs only its own `enrichedlab-*` workflows.

## Images

`.github/workflows/enrichedlab-images.yml` builds the gateway, supervisor, sandbox and CLI images, and the run receipt
interceptor's (`crates/enrichedlab-receipts`), for linux/amd64 and linux/arm64 with upstream's build actions on
GitHub-hosted runners, pushes them to
`ghcr.io/richardstoker-usda/enrichedlab-openshell/<component>`, and signs a SLSA build provenance attestation for each
image index. A release tag produces `<component>:X.Y.Z-el.N`; a push to `enrichedlab/main` produces
`<component>:X.Y.Z-el.dev.g<commit>`. Deploy by digest, after verifying:

```shell
gh attestation verify oci://ghcr.io/richardstoker-usda/enrichedlab-openshell/gateway@sha256:<digest> \
  --repo RichardStoker-USDA/enrichedlab-openshell
```
