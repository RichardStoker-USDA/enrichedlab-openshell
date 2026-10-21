# Run receipts

`enrichedlab-receipts` writes one receipt for every OpenShell sandbox run. It learns how each sandbox started from
an observe-only gateway interceptor binding, watches the sandbox's Kubernetes objects while it runs, and writes the
receipt once it sees the sandbox deleted.

It is an extension, not a gateway change. It uses the
[gateway interceptor](../../docs/extensibility/gateway-interceptors.mdx) contract with one `post_commit` binding
that never changes or refuses an operation, holds no gateway credential, calls no gateway API, and reads Kubernetes
only. Every record is keyed by the gateway's sandbox id, which the gateway assigns when it commits a sandbox and the
Kubernetes driver writes on every object of that sandbox (`openshell.ai/sandbox-id`); nothing is matched by name.
Sandbox objects are watched and listed with the driver's own selector, including this gateway's id
(`openshell.ai/gateway-id`), so another gateway's sandboxes in the same namespace are never receipted as this one's.
Pods are watched by the driver's boundary labels (`openshell.ai/boundary-pair`, the lowercased sandbox id, and
`openshell.ai/boundary-role`), which both the supervisor and the workload Pod carry. The supervisor names its sandbox
by label and the workload Pod, made by the Agent Sandbox controller, by the driver's annotation; either must agree
with the pair label. A Pod's facts are kept only for a sandbox the scoped watch saw or whose committed start this
gateway sent.

## What a receipt holds

| Field | Source |
|---|---|
| `start` | the sandbox as the gateway committed it (the `CreateSandbox` response): workspace, name, labels, annotations, template image and runtime class, the policy's `deterministic_policy_hash` (the hash the supervisor reports when it loads a policy), provider names, the program and the argument count, environment variable names, and the gateway's caller summary |
| `sandbox` | the `Sandbox` object's last state: namespace, object name, UID, generation, creation and deletion times, labels |
| `pods` | the last view of each Pod with the sandbox id: component (sandbox or supervisor), UID, node, runtime class, phase, and per container (init containers first, among them the one that stages the sandbox runtime) the image, the runtime's resolved image digest, restarts and state |
| `images_seen` | every resolved image digest the sandbox's containers, init containers included, reported while it ran |
| `ending` | when and how the end was observed (below) |
| `not_recorded` | what the receipt could not observe, with the reason |

Environment values and command arguments are never kept, and no digest of them is kept either, because either may
carry a credential and a digest of a guessable secret can be tested offline. Labels, annotations and the caller
summary are kept because the gateway's API treats them as non-secret; each map keeps at most 64 entries of at most
256 characters, and a receipt keeps at most 16 Pods, 16 containers per Pod and 64 image digests; what it leaves out
is counted (`pods_omitted`, `containers_omitted`, and `images_omitted`, which counts reports of digests past the 64
kept, so a digest reported again is counted again).

Every receipt lists these under `not_recorded`: the main process's exit status and the caller of the delete, which
the gateway keeps in its own store and audit log; the prover's verdicts on policy proposals, also kept by the
gateway; the supervisor's OCSF events, which are counted elsewhere (join
them by the supervisor Pod's name and UID); output checksums, because workspace contents are not read; and policy
changes after the start, because a policy change's committed response does not name its sandbox. A sandbox created
without a policy of its own also lists `policy`: the gateway's default applied, which the committed sandbox does
not carry. A receipt
without `start` says the gateway's commit was not seen.

## How the end is observed

| `ending.observation` | Meaning |
|---|---|
| `deleted` | the watch delivered the `Sandbox` object's deletion |
| `missing-from-listing` | a fresh listing (after a watch restart, and every ten minutes) no longer had it: it was deleted while the watch was down, or its delete-time write failed |
| `not-observed` | the gateway committed it, no Kubernetes object was seen within an hour, and a fresh listing does not have it: it was never provisioned, or it was created and deleted while the service was down |

A listing closes only sandboxes the service tracked before the listing began, so a sandbox created during a listing
is never taken for a deleted one. A delete whose receipt cannot be written is retried at the next ten-minute sweep.
A Pod report that arrives before its sandbox is known to be this gateway's is held in memory (up to 256 sandboxes
of 16 Pods, for an hour) and kept once the sandbox is known, even if the Pod is gone by then; a report the bounds
could not hold is counted (`enrichedlab_receipts_pods_unheld_total`), and since its sandbox is unknown, the receipt
of every sandbox established as this gateway's within the hour after it lists `pods_unheld` (measured on the
service's own monotonic clock). Held reports are released only after they are written. When a sandbox is first established as this gateway's, its Pods are also listed and recorded at once; each sweep (the first runs at start) also lists this gateway's sandboxes and
then the namespace's sandbox Pods afresh, a page at a time. A receipt with no Pod at all says so under
`not_recorded`.
Pod states are the last ones seen before the `Sandbox` object was deleted. A sandbox created and deleted entirely
while the service was down, with its create unseen, gets no receipt; alert on the service's availability.

## Files

```text
<state>/starts/<sandbox id>.json            the committed start; the first one is kept
<state>/observed/<sandbox id>.json          what Kubernetes showed, replaced atomically
<state>/receipts/<sandbox id>.json          the receipt, written once
<state>/receipts/<sandbox id>.json.sha256   its SHA-256
```

A sandbox id names a file only when it is 1 to 128 letters, digits, `-`, `_` or `.` and does not start with a dot.
Files are written mode 0600 and directories 0700, and every write is flushed and its directory synced. When the
volume is mounted again, Kubernetes' `fsGroup` handling may give the Pod's own group access; the service takes its
directories back to 0700 at start and refuses to start if other users have access. Set `fsGroupChangePolicy:
OnRootMismatch` so a restart does not rewrite every receipt's ownership. A start or receipt is
written to a temporary file, flushed, and hard-linked to its name, so the name never holds a partial record and an
existing one is never replaced. An existing receipt is checked against its digest file before its sandbox's working
records are removed; a digest file lost to a crash between the two writes is written again. At most 4,096 start and 4,096 observed
records are kept at once. Receipts are kept until removed by whatever retention applies to the volume.

## Metrics

`/metrics` on `--metrics-listen` (plain HTTP) carries counts with fixed label values only:

| Series | Labels |
|---|---|
| `enrichedlab_receipts_written_total` | `observation`: new receipts by how the end was observed |
| `enrichedlab_receipts_failures_total` | `operation`: `start`, `observe`, `receipt`, `reconcile`, `watch` |
| `enrichedlab_receipts_starts_total` | `outcome`: the committed start's result (`recorded`, `kept`, `not recorded` and so on) |
| `enrichedlab_receipts_listings_total` | `resource`: complete listings of `sandboxes` or `pods` |
| `enrichedlab_receipts_tracked` | `record`: start and observed records held, at each sweep |
| `enrichedlab_receipts_pods_unheld_total` | none: early Pod reports past the hold bounds |

## Running it

The service serves gRPC over TLS (1 MiB messages, 16 concurrent calls per connection) and verifies the gateway's
extension token on every call: `typ` `openshell-ext+jwt`, `EdDSA`, the exact audience, issuer
`openshell-gateway:<gateway id>`, subject equal to the issuer, and a gateway caller with no sandbox id. It needs:

- a server certificate the gateway trusts (`--tls-cert`, `--tls-key`);
- the gateway's public signing key and, optionally, its key id (`--gateway-public-key`, `--gateway-key-id-file`);
  mount only `public.pem` and `kid` from the gateway's signing key Secret, never `signing.pem`;
- a persistent volume for `--state-dir`;
- a ServiceAccount allowed to `get`, `list` and `watch` `sandboxes` (`agents.x-k8s.io`) and `pods` in
  `--sandbox-namespace`, and nothing else.

Register it with the gateway:

```toml
[[openshell.gateway.interceptors]]
name             = "run-receipts"
grpc_endpoint    = "https://run-receipts.sandboxes.svc.cluster.local:8443"
tls_ca_cert_path = "/etc/openshell/receipts-ca/ca.crt"
audience         = "urn:openshell:extension:interceptor:run-receipts"
failure_policy   = "fail_open"
binding_policy   = "exact"
timeout          = "2s"
bindings         = [{ rpc = "openshell.v1.OpenShell/CreateSandbox", phases = ["post_commit"] }]
```

Run exactly one instance per store (one replica, `Recreate`): the store holds an exclusive lock on `<state>/.lock`, and
a second instance refuses to start while the first holds it.

Registration is static: restart the gateway after adding it. The gateway calls `Describe` at startup and does not
start while the service is unreachable or declares another audience, so start the service first and keep it running
across gateway restarts. Once the gateway runs, an unavailable service only loses starts: the binding is
`fail_open`.
