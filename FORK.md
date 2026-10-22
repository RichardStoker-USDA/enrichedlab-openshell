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

- Upstream `main` after v0.1.5 creates every supervisor Pod in `create_sandbox_runtime_supervisor`; the fixed
  labels and annotations are applied there (`apply_fixed_pod_metadata`), as on `enrichedlab/next`.

## Carried upstream pull requests

A pull request upstream has not released yet may be carried on `enrichedlab/main` when a site needs it now. It keeps
the upstream design and interfaces, so the release that contains it replaces the carried commit: on that merge, take
upstream's version of the pull request's code and keep only the adaptations listed here.

- [NVIDIA/OpenShell#3508](https://github.com/NVIDIA/OpenShell/pull/3508), template-driven warm pooling for the
  Kubernetes driver, carried on v0.1.5. Adaptations: supervisors receive their credentials at registration instead
  of in the bootstrap Secret, so the fork's rule that a supervisor sending telemetry elsewhere never receives the
  gateway's collector headers moved from the driver to the gateway (`ComputeDriverFactory::supervisors_use_gateway_collector`);
  the run receipt interceptor matches a warm pair's Pods through the pair id the Sandbox object names
  (`openshell.ai/warm-pair-id`), since their boundary pair label is not the sandbox id; and v0.1.5's boundary open
  check (`isolation_protocol::validate_open`, from the sandbox backend protocol) expects the sandbox the boundary's
  authenticator bound when the boundary was provisioned without one, which the pull request does for every
  Kubernetes boundary, cold or warm.

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
