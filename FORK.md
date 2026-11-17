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
scripts/enrichedlab/sync-upstream.sh --merge v0.1.8  # also prepare enrichedlab/merge-v0.1.8
scripts/enrichedlab/sync-upstream.sh --merge v0.1.8 --push origin
```

The script refuses to run on a dirty tree, never moves `enrichedlab/main`, and enables `git rerere` for this
repository so a conflict resolved once on `enrichedlab/next` is reused when the release is merged. After a merge
branch passes CI:

```shell
git switch enrichedlab/main
git merge --ff-only enrichedlab/merge-v0.1.8
git push origin enrichedlab/main
```

rerere replays conflicting hunks only. A fork change that has to move to new upstream code without a textual
conflict is listed here and checked by hand on every merge:

- Since v0.1.6 upstream creates every dedicated supervisor Pod in `create_sandbox_runtime_supervisor`; the fixed
  labels and annotations are applied there (`apply_fixed_pod_metadata`), after v0.1.8's app listener and supervisor
  RuntimeClass settings. A shared supervisor (`supervisor_topology =
  "gateway"`) is deployed by Helm, not per sandbox, so the fixed metadata does not reach it.
- The restart patch is built by `restart_running_patch`, which carries upstream's bootstrap annotations (including
  the control connection and supervisor topology keys added in v0.1.6) and then the operator's fixed metadata.
- Since v0.1.8 upstream gives supervisors one export per signal (`SupervisorOtlp`: traces, OCSF and relayed agent
  traces), each with its own endpoint, protocol, headers and TLS material (CA and client certificate and key). The
  fork's `supervisor_telemetry` maps the gateway's exports through `SupervisorTelemetry::resolve`: `gateway` keeps
  them, `"off"` drops them, and a separate endpoint replaces every export's endpoint with OTLP/gRPC.
- "Collector material" is every field in `COLLECTOR_MATERIAL_FIELDS` (`openshell-supervisor-control`): the three
  header sets and the four TLS fields. A new per-signal header or TLS field upstream adds to the auth bundle goes into
  that list, or it reaches supervisors that export elsewhere.
- Upstream writes the supervisor's auth bundle into its bootstrap Secret in `install_sandbox_runtime_generation`; the
  fork writes it through `supervisor_auth_json`, which calls `withhold_collector_material`, so a supervisor whose
  telemetry goes elsewhere never receives the gateway's collector material.
- A shared supervisor gets its credentials from the gateway's launch bundle at registration, not from that Secret. The
  gateway therefore withholds the material itself: the compute driver factory reports whether supervisors use the
  gateway's collector (`supervisors_use_gateway_collector`), and when they do not, `withhold_supervisor_collector_material`
  fills upstream's header and TLS slots with empty values before `configure_supervisor_otlp_headers` and
  `configure_supervisor_otlp_tls` run, so those calls leave them empty. Check on every merge that the compute runtime
  is still built before those two calls; `withheld_collector_material_never_reaches_launch_bundles` fails if it is not.
- Stored launch material never carries material the gateway withholds: when supervisors export elsewhere, the
  supervisor pool removes it as it records, places or loads material (`launch_material_without_collector_headers`),
  and the Kubernetes driver removes it from a recovered shared generation's Secret. Material without collector fields
  is kept byte for byte, so a launch and its replay keep one admission fingerprint. While supervisors use the
  gateway's collector, stored material keeps what it was launched with until the next launch.
- The standalone Kubernetes driver takes `--supervisor-telemetry` (`OPENSHELL_SUPERVISOR_TELEMETRY`) and resolves it
  against its own `--otlp*` exports in `standalone_supervisor_telemetry`; with no export it writes bundles as `off`.
  The gateway treats every remote driver as using its collector (`ConfiguredComputeDriver::Remote` in
  `openshell-server`), so the driver's `supervisor_auth_json` is what withholds the material there.
- Driver start validates upstream's supervisor topology and the fork's fixed metadata and supervisor telemetry; a
  separate telemetry endpoint is refused with a shared supervisor, which exports no supervisor telemetry.

## Carried upstream pull requests

None on the v0.1.8 line. [NVIDIA/OpenShell#3508](https://github.com/NVIDIA/OpenShell/pull/3508) (template-driven warm
pooling for the Kubernetes driver) was carried on v0.1.5 with three adaptations. v0.1.6 changed the supervisor's
gateway credentials to per-instance credentials for shared supervisors, and the pull request's registration path
depends on the earlier process-wide token, so carrying it is a port of its design, not a merge; its author is
rebasing it upstream. Until a version that applies to the current release exists, the v0.1.6 and later lines have no warm
pools: the shared supervisor (`supervisor_topology = "gateway"`) is the measured alternative for start latency, and a
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
