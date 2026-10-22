// SPDX-FileCopyrightText: Copyright (c) 2026 Richard Stoker
// SPDX-License-Identifier: Apache-2.0

//! The read-only Kubernetes side: watches of the sandbox namespace's `Sandbox` objects and Pods.
//!
//! The service needs `get`, `list` and `watch` on `sandboxes` (the agent-sandbox API group) and `pods`
//! in the sandbox namespace, and nothing else. Objects are selected by the `OpenShell` driver's own
//! labels: `openshell.ai/managed-by=openshell` and `openshell.ai/sandbox-id`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;

use futures::StreamExt;
use k8s_openapi::api::core::v1::{ContainerStatus, Pod};
use kube::api::{Api, DynamicObject, ListParams};
use kube::core::{ApiResource, GroupVersionKind};
use kube::runtime::WatchStreamExt;
use kube::runtime::watcher::{self, Event};
use kube::{Client, ResourceExt};
use tracing::{debug, info, warn};

use crate::receipt::{BoundedMap, ContainerFacts, Observation, PodFacts, SandboxObject};
use crate::store::valid_sandbox_id;
use crate::telemetry;
use crate::tracker::{Tracker, stamp};

/// Sandbox objects carry the driver's labels; with this gateway's id they select its sandboxes.
const SANDBOX_BASE: &str = "openshell.ai/managed-by=openshell,openshell.ai/sandbox-id";
/// Both Pods of a sandbox carry the driver's boundary labels: the pair and the role (workload or
/// supervisor). The pair is the lowercased sandbox id for a sandbox the driver creates directly, or the
/// warm pair id for one a warm pool prepared, which the Sandbox object names after the gateway assigns it. The supervisor also has the sandbox id as a label; the workload Pod,
/// made by the Agent Sandbox controller from the Sandbox's template, has it as an annotation. Pods may not
/// carry the gateway id, so a Pod's facts are kept only for a sandbox this gateway's scoped watch or
/// committed start established (`Tracker::pod_seen`).
const POD_SELECTOR: &str = "openshell.ai/boundary-pair,openshell.ai/boundary-role";
const BOUNDARY_PAIR: &str = "openshell.ai/boundary-pair";
const WARM_PAIR: &str = "openshell.ai/warm-pair-id";
const GATEWAY_ID: &str = "openshell.ai/gateway-id";
const SANDBOX_ID: &str = "openshell.ai/sandbox-id";
const SANDBOX_NAME: &str = "openshell.ai/sandbox-name";
const SANDBOX_WORKSPACE: &str = "openshell.ai/sandbox-workspace";
const COMPONENT: &str = "openshell.ai/component";
/// How often committed starts are checked for a sandbox Kubernetes never showed.
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_mins(10);

fn now() -> String {
    stamp(chrono::Utc::now())
}

fn annotation_or_label(object: &DynamicObject, key: &str) -> Option<String> {
    object
        .annotations()
        .get(key)
        .or_else(|| object.labels().get(key))
        .cloned()
}

/// Sandbox objects: the driver's labels and this gateway's id, as the driver's own lookups select them.
pub fn sandbox_selector(gateway_id: &str) -> String {
    format!("{SANDBOX_BASE},{GATEWAY_ID}={gateway_id}")
}

/// Whether `id` can be a Kubernetes label value, so it can be put in a selector.
pub fn valid_label_value(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 63
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id.as_bytes()[id.len() - 1].is_ascii_alphanumeric()
}

/// The facts the receipt keeps about a `Sandbox` object of this gateway; `None` without a usable
/// sandbox id or for another gateway's object.
pub fn sandbox_object(
    namespace: &str,
    gateway_id: &str,
    object: &DynamicObject,
) -> Option<SandboxObject> {
    if object.labels().get(GATEWAY_ID).map(String::as_str) != Some(gateway_id) {
        return None;
    }
    let sandbox_id = object
        .labels()
        .get(SANDBOX_ID)
        .cloned()
        .filter(|id| valid_sandbox_id(id))?;
    Some(SandboxObject {
        namespace: namespace.to_string(),
        object_name: object.name_any(),
        uid: object.uid(),
        sandbox_id,
        workspace: annotation_or_label(object, SANDBOX_WORKSPACE),
        name: annotation_or_label(object, SANDBOX_NAME),
        generation: object.metadata.generation,
        created_at: object
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| t.0.to_rfc3339()),
        deletion_timestamp: object
            .metadata
            .deletion_timestamp
            .as_ref()
            .map(|t| t.0.to_rfc3339()),
        labels: BoundedMap::from_pairs(object.labels()),
        pair: annotation_or_label(object, WARM_PAIR).filter(|pair| valid_label_value(pair)),
    })
}

/// A container's state name, exit code and reason.
fn container_state(
    state: Option<&k8s_openapi::api::core::v1::ContainerState>,
) -> (&'static str, Option<i32>, Option<String>) {
    let Some(state) = state else {
        return ("unknown", None, None);
    };
    if let Some(terminated) = &state.terminated {
        return (
            "terminated",
            Some(terminated.exit_code),
            terminated.reason.clone(),
        );
    }
    if state.running.is_some() {
        return ("running", None, None);
    }
    state
        .waiting
        .as_ref()
        .map_or(("unknown", None, None), |waiting| {
            ("waiting", None, waiting.reason.clone())
        })
}

/// The facts the receipt keeps about one container status.
fn container_facts(
    status: &ContainerStatus,
    images: &HashMap<&str, Option<&str>>,
    init: bool,
) -> ContainerFacts {
    let (state_name, exit_code, reason) = container_state(status.state.as_ref());
    ContainerFacts {
        name: status.name.clone(),
        init,
        image: images
            .get(status.name.as_str())
            .copied()
            .flatten()
            .map(str::to_string)
            .or_else(|| Some(status.image.clone())),
        image_id: Some(status.image_id.clone()).filter(|id| !id.is_empty()),
        restart_count: status.restart_count,
        state: state_name.to_string(),
        exit_code,
        reason,
    }
}

/// The facts the receipt keeps about one Pod: init containers (a sandbox Pod's runtime image) first,
/// then the others.
pub fn pod_facts(pod: &Pod) -> PodFacts {
    let spec = pod.spec.as_ref();
    let status = pod.status.as_ref();
    let images: HashMap<&str, Option<&str>> = spec
        .map(|spec| {
            spec.init_containers
                .iter()
                .flatten()
                .chain(spec.containers.iter())
                .map(|c| (c.name.as_str(), c.image.as_deref()))
                .collect()
        })
        .unwrap_or_default();
    let collect = |statuses: Option<&Vec<ContainerStatus>>, init: bool| {
        let mut facts: Vec<ContainerFacts> = statuses
            .into_iter()
            .flatten()
            .map(|status| container_facts(status, &images, init))
            .collect();
        facts.sort_by(|a, b| a.name.cmp(&b.name));
        facts
    };
    let mut containers = collect(
        status.and_then(|status| status.init_container_statuses.as_ref()),
        true,
    );
    containers.extend(collect(
        status.and_then(|status| status.container_statuses.as_ref()),
        false,
    ));
    PodFacts {
        name: pod.name_any(),
        uid: pod.uid(),
        component: pod.labels().get(COMPONENT).cloned(),
        node: spec.and_then(|spec| spec.node_name.clone()),
        runtime_class_name: spec.and_then(|spec| spec.runtime_class_name.clone()),
        phase: status.and_then(|status| status.phase.clone()),
        created_at: pod
            .metadata
            .creation_timestamp
            .as_ref()
            .map(|t| t.0.to_rfc3339()),
        containers,
        containers_omitted: 0,
    }
}

/// Lists objects by label in pages of 200 and hands each to `each` as its page arrives, so at most one
/// page is held at a time.
async fn each_listed<K>(
    api: &Api<K>,
    labels: &str,
    mut each: impl FnMut(&K),
) -> Result<(), kube::Error>
where
    K: Clone + serde::de::DeserializeOwned + std::fmt::Debug,
{
    let mut params = ListParams::default().labels(labels).limit(200);
    loop {
        let page = api.list(&params).await?;
        for item in &page.items {
            each(item);
        }
        match page.metadata.continue_.filter(|token| !token.is_empty()) {
            Some(token) => params = params.continue_token(&token),
            None => return Ok(()),
        }
    }
}

/// Lists one sandbox's Pods and records them: run when the sandbox is first established as this
/// gateway's, so Pods the Pod watch reported before then are not lost. A failure is retried by the
/// next sweep's Pod listing.
async fn catch_up_pods(tracker: &Tracker, pods: &Api<Pod>, sandbox_id: &str, pair: &str) {
    if !valid_label_value(pair) {
        return;
    }
    let selector = format!("{BOUNDARY_PAIR}={pair}");
    if let Err(error) = each_listed(pods, &selector, |pod| record_pod(tracker, pod)).await {
        telemetry::failure("watch");
        warn!(sandbox_id = %sandbox_id, error = %error, "could not list a sandbox's Pods; the next sweep retries");
    }
}

/// Records a sandbox object from a watch event, catching up on its Pods the first time.
async fn sandbox_event(tracker: &Tracker, pods: &Api<Pod>, object: SandboxObject) {
    let id = object.sandbox_id.clone();
    let pair = object.pod_pair();
    match blocking(|| tracker.sandbox_seen(object, &now())) {
        Ok(true) => catch_up_pods(tracker, pods, &id, &pair).await,
        Ok(false) => {}
        Err(error) => {
            telemetry::failure("observe");
            warn!(error = %error, "could not record a sandbox");
        }
    }
}

/// The sandbox id and boundary pair of one of a sandbox's Pods.
///
/// The id comes from its label (supervisor) or the driver's annotation (workload); `Tracker::pod_seen`
/// checks the pair label against the pair the sandbox's object names.
pub fn pod_sandbox_id(pod: &Pod) -> Option<(String, String)> {
    let id = pod
        .labels()
        .get(SANDBOX_ID)
        .or_else(|| pod.annotations().get(SANDBOX_ID))?;
    let pair = pod.labels().get(BOUNDARY_PAIR)?;
    (valid_sandbox_id(id) && valid_label_value(pair)).then(|| (id.clone(), pair.clone()))
}

/// Records a Pod's facts when its sandbox is tracked; one of another gateway, or not yet tracked, is
/// held for later (`Tracker::pod_seen`).
fn record_pod(tracker: &Tracker, pod: &Pod) {
    if let Some((id, pair)) = pod_sandbox_id(pod) {
        match blocking(|| tracker.pod_seen(&id, &pair, pod_facts(pod), &now())) {
            Ok(true) => {}
            Ok(false) => debug!(sandbox_id = %id, "Pod of an untracked sandbox left for now"),
            Err(error) => {
                telemetry::failure("observe");
                warn!(error = %error, "could not record a Pod");
            }
        }
    }
}

/// Writes the receipt of a deleted sandbox; on failure keeps the deletion for the next sweep.
fn end_deleted(
    tracker: &Tracker,
    object: SandboxObject,
    retry: &mut HashMap<String, SandboxObject>,
) {
    let id = object.sandbox_id.clone();
    match blocking(|| {
        tracker.sandbox_ended(&id, Some(object.clone()), Observation::Deleted, &now())
    }) {
        Ok(written) => {
            retry.remove(&id);
            telemetry::receipt_written(Observation::Deleted, usize::from(written.new));
            info!(sandbox_id = %id, sha256 = %written.sha256, new = written.new, "run receipt");
        }
        Err(error) => {
            telemetry::failure("receipt");
            warn!(sandbox_id = %id, error = %error, "could not write a run receipt; retrying at the next sweep");
            if retry.len() < crate::store::MAX_TRACKED {
                retry.insert(id, object);
            }
        }
    }
}

/// Closes every sandbox in `before` that `present` lacks.
fn reconcile(tracker: &Tracker, before: &HashSet<String>, present: &HashSet<String>, what: &str) {
    match blocking(|| tracker.close_missing(before, present, &now())) {
        Ok(written) => {
            telemetry::receipt_written(Observation::MissingFromListing, new_receipts(&written));
            info!(
                present = present.len(),
                receipts = written.len(),
                "{what} reconciled"
            );
        }
        Err(error) => {
            telemetry::failure("reconcile");
            warn!(error = %error, "could not reconcile the {what}");
        }
    }
}

/// Every ten minutes: retry deletions whose receipt failed, list the namespace afresh and close what
/// is gone, close starts Kubernetes never showed, and report the working records held.
async fn sweep(
    tracker: &Tracker,
    sandboxes: &Api<DynamicObject>,
    pods: &Api<Pod>,
    namespace: &str,
    gateway_id: &str,
    retry: &mut HashMap<String, SandboxObject>,
) {
    let pending: Vec<SandboxObject> = retry.values().cloned().collect();
    for object in pending {
        end_deleted(tracker, object, retry);
    }
    // Terminal decisions from absence need a complete listing made now; without one, wait for the next sweep.
    let before = match blocking(|| tracker.observed_ids()) {
        Ok(before) => before,
        Err(error) => {
            telemetry::failure("reconcile");
            warn!(error = %error, "could not read the tracked sandboxes");
            return;
        }
    };
    // Sandboxes first, then their Pods, a page at a time: whatever order the two watches delivered at
    // startup, every running sandbox and each of its Pods is recorded by the end of a sweep.
    let mut present = HashSet::new();
    let listed = each_listed(sandboxes, &sandbox_selector(gateway_id), |object| {
        if let Some(object) = sandbox_object(namespace, gateway_id, object) {
            present.insert(object.sandbox_id.clone());
            // The sweep lists every Pod next, so the first-seen catch-up is not needed here.
            report(
                blocking(|| tracker.sandbox_seen(object, &now()).map(|_| ())),
                "record a sandbox",
            );
        }
    })
    .await;
    if let Err(error) = listed {
        telemetry::failure("reconcile");
        warn!(error = %error, "could not list sandboxes");
        return;
    }
    telemetry::listing("sandboxes");
    reconcile(tracker, &before, &present, "periodic listing");
    match blocking(|| tracker.close_unobserved(&present, &now(), SystemTime::now())) {
        Ok(written) => {
            telemetry::receipt_written(Observation::NotObserved, new_receipts(&written));
            if !written.is_empty() {
                info!(
                    receipts = written.len(),
                    "closed starts never seen in Kubernetes"
                );
            }
        }
        Err(error) => {
            telemetry::failure("reconcile");
            warn!(error = %error, "could not close unobserved starts");
        }
    }
    match each_listed(pods, POD_SELECTOR, |pod| record_pod(tracker, pod)).await {
        Ok(()) => telemetry::listing("pods"),
        Err(error) => {
            telemetry::failure("watch");
            warn!(error = %error, "could not list sandbox Pods");
        }
    }
    match blocking(|| tracker.tracked()) {
        Ok((starts, observed)) => telemetry::tracked(starts, observed),
        Err(error) => warn!(error = %error, "could not count working records"),
    }
}

/// Watches one namespace and feeds the tracker until a watch stream ends.
pub async fn watch(
    tracker: Arc<Tracker>,
    namespace: String,
    sandbox_api_version: String,
    gateway_id: String,
) -> Result<(), String> {
    if !valid_label_value(&gateway_id) {
        return Err("the gateway id cannot select Kubernetes objects".to_string());
    }
    let client = Client::try_default()
        .await
        .map_err(|error| format!("Kubernetes client: {error}"))?;
    let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
        "agents.x-k8s.io",
        &sandbox_api_version,
        "Sandbox",
    ));
    let sandboxes: Api<DynamicObject> = Api::namespaced_with(client.clone(), &namespace, &resource);
    let pods: Api<Pod> = Api::namespaced(client, &namespace);
    let selector = sandbox_selector(&gateway_id);
    let config = |labels: &str| watcher::Config::default().labels(labels).page_size(200);
    let mut sandbox_events = watcher::watcher(sandboxes.clone(), config(&selector))
        .default_backoff()
        .boxed();
    let mut pod_events = watcher::watcher(pods.clone(), config(POD_SELECTOR))
        .default_backoff()
        .boxed();
    // Between a watch restart and its complete listing: what was tracked before it began, and what it listed.
    let mut listing: Option<(HashSet<String>, HashSet<String>)> = None;
    let mut retry: HashMap<String, SandboxObject> = HashMap::new();
    let mut ticks = tokio::time::interval(SWEEP_INTERVAL);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    info!(namespace = %namespace, "watching sandboxes and their Pods");
    loop {
        tokio::select! {
            event = sandbox_events.next() => match event {
                Some(Ok(Event::Init)) => {
                    listing = match blocking(|| tracker.observed_ids()) {
                        Ok(before) => Some((before, HashSet::new())),
                        Err(error) => {
                            telemetry::failure("reconcile");
                            warn!(error = %error, "could not read the tracked sandboxes; this listing will not reconcile");
                            None
                        }
                    };
                }
                Some(Ok(Event::InitApply(object))) => {
                    if let Some(object) = sandbox_object(&namespace, &gateway_id, &object) {
                        if let Some((_, present)) = listing.as_mut() {
                            present.insert(object.sandbox_id.clone());
                        }
                        sandbox_event(&tracker, &pods, object).await;
                    }
                }
                Some(Ok(Event::InitDone)) => {
                    telemetry::listing("sandboxes");
                    if let Some((before, present)) = listing.take() {
                        reconcile(&tracker, &before, &present, "listing");
                    }
                }
                Some(Ok(Event::Apply(object))) => {
                    if let Some(object) = sandbox_object(&namespace, &gateway_id, &object) {
                        sandbox_event(&tracker, &pods, object).await;
                    }
                }
                Some(Ok(Event::Delete(object))) => {
                    if let Some(object) = sandbox_object(&namespace, &gateway_id, &object) {
                        end_deleted(&tracker, object, &mut retry);
                    }
                }
                Some(Err(error)) => {
                    telemetry::failure("watch");
                    warn!(error = %error, "sandbox watch error; retrying");
                }
                None => return Err("the sandbox watch ended".to_string()),
            },
            event = pod_events.next() => match event {
                Some(Ok(Event::InitApply(pod) | Event::Apply(pod))) => record_pod(&tracker, &pod),
                Some(Ok(Event::InitDone)) => telemetry::listing("pods"),
                Some(Ok(Event::Init | Event::Delete(_))) => {}
                Some(Err(error)) => {
                    telemetry::failure("watch");
                    warn!(error = %error, "Pod watch error; retrying");
                }
                None => return Err("the Pod watch ended".to_string()),
            },
            _ = ticks.tick() => sweep(&tracker, &sandboxes, &pods, &namespace, &gateway_id, &mut retry).await,
        }
    }
}

/// Store writes are blocking file I/O with fsync; run them without holding up the runtime's other tasks.
fn blocking<T>(work: impl FnOnce() -> T) -> T {
    tokio::task::block_in_place(work)
}

fn new_receipts(written: &[crate::store::WrittenReceipt]) -> usize {
    written.iter().filter(|receipt| receipt.new).count()
}

fn report(result: Result<(), crate::store::StoreError>, what: &str) {
    if let Err(error) = result {
        telemetry::failure("observe");
        warn!(error = %error, "could not {what}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pod_facts_keep_digests_states_and_placement() {
        let pod: Pod = serde_json::from_value(serde_json::json!({
            "metadata": {"name": "default--run-1", "uid": "u-1", "labels": {COMPONENT: "sandbox"},
                         "creationTimestamp": "2026-10-21T10:00:00Z"},
            "spec": {"nodeName": "node-a", "runtimeClassName": "kata",
                     "initContainers": [{"name": "runtime", "image": "registry.example.com/runtime:1"}],
                     "containers": [{"name": "agent", "image": "registry.example.com/agent:1"}]},
            "status": {"phase": "Running",
                "initContainerStatuses": [{
                "name": "runtime", "image": "registry.example.com/runtime:1",
                "imageID": "registry.example.com/runtime@sha256:4567", "ready": true, "restartCount": 0,
                "state": {"terminated": {"exitCode": 0, "reason": "Completed"}}}],
                "containerStatuses": [{
                "name": "agent", "image": "registry.example.com/agent:1",
                "imageID": "registry.example.com/agent@sha256:0123", "ready": true, "restartCount": 2,
                "state": {"terminated": {"exitCode": 3, "reason": "Error"}}}]}
        }))
        .unwrap();
        let facts = pod_facts(&pod);
        assert_eq!(facts.component.as_deref(), Some("sandbox"));
        assert_eq!(facts.node.as_deref(), Some("node-a"));
        assert_eq!(facts.runtime_class_name.as_deref(), Some("kata"));
        assert_eq!(facts.containers.len(), 2);
        let runtime = &facts.containers[0];
        assert!(runtime.init, "init containers come first");
        assert_eq!(
            runtime.image_id.as_deref(),
            Some("registry.example.com/runtime@sha256:4567")
        );
        let container = &facts.containers[1];
        assert!(!container.init);
        assert_eq!(
            container.image_id.as_deref(),
            Some("registry.example.com/agent@sha256:0123")
        );
        assert_eq!(container.state, "terminated");
        assert_eq!(container.exit_code, Some(3));
        assert_eq!(container.restart_count, 2);
    }

    #[test]
    fn both_pods_of_a_sandbox_name_it_through_the_driver_labels() {
        let pod = |labels: serde_json::Value, annotations: serde_json::Value| -> Pod {
            serde_json::from_value(serde_json::json!({"metadata": {"name": "p", "labels": labels, "annotations": annotations}}))
                .unwrap()
        };
        let id = "0D3C5D0E-6a0f-4c2e-9a51-000000000001";
        let pair = id.to_ascii_lowercase();
        let supervisor = pod(
            serde_json::json!({SANDBOX_ID: id, BOUNDARY_PAIR: pair, "openshell.ai/boundary-role": "supervisor"}),
            serde_json::json!({}),
        );
        let workload = pod(
            serde_json::json!({BOUNDARY_PAIR: pair, "openshell.ai/boundary-role": "workload"}),
            serde_json::json!({SANDBOX_ID: id}),
        );
        let named = (id.to_string(), pair);
        assert_eq!(pod_sandbox_id(&supervisor).as_ref(), Some(&named));
        assert_eq!(
            pod_sandbox_id(&workload),
            Some(named),
            "the workload Pod names its sandbox by annotation"
        );
        let warm = pod(
            serde_json::json!({BOUNDARY_PAIR: "9f2c4e6a8b0d1f3e5a7c9e1b", "openshell.ai/boundary-role": "workload"}),
            serde_json::json!({SANDBOX_ID: id}),
        );
        assert_eq!(
            pod_sandbox_id(&warm),
            Some((id.to_string(), "9f2c4e6a8b0d1f3e5a7c9e1b".to_string())),
            "a warm pair's Pod reports its pair; the tracker checks it against the object"
        );
        let unpaired = pod(serde_json::json!({SANDBOX_ID: id}), serde_json::json!({}));
        assert!(pod_sandbox_id(&unpaired).is_none());
    }

    #[test]
    fn a_sandbox_object_needs_a_usable_sandbox_id_and_this_gateway() {
        let object = |labels: serde_json::Value| -> DynamicObject {
            serde_json::from_value(serde_json::json!({
                "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
                "metadata": {"name": "default--run-1", "uid": "uid-1", "generation": 3, "labels": labels,
                             "annotations": {SANDBOX_NAME: "run-1"},
                             "creationTimestamp": "2026-10-21T10:00:00Z", "deletionTimestamp": "2026-10-21T11:00:00Z"}
            }))
            .unwrap()
        };
        let mine = serde_json::json!({SANDBOX_ID: "id-1", SANDBOX_WORKSPACE: "default", GATEWAY_ID: "gw-a"});
        let facts = sandbox_object("sandboxes", "gw-a", &object(mine)).unwrap();
        assert_eq!(facts.sandbox_id, "id-1");
        assert_eq!(facts.name.as_deref(), Some("run-1"));
        assert_eq!(facts.workspace.as_deref(), Some("default"));
        assert_eq!(facts.generation, Some(3));
        assert!(facts.deletion_timestamp.is_some());
        let other = serde_json::json!({SANDBOX_ID: "id-2", GATEWAY_ID: "gw-b"});
        assert!(
            sandbox_object("sandboxes", "gw-a", &object(other)).is_none(),
            "another gateway's sandbox"
        );
        assert!(
            sandbox_object(
                "sandboxes",
                "gw-a",
                &object(serde_json::json!({SANDBOX_ID: "id-3"}))
            )
            .is_none()
        );
        assert!(
            sandbox_object(
                "sandboxes",
                "gw-a",
                &object(serde_json::json!({GATEWAY_ID: "gw-a"}))
            )
            .is_none()
        );
        let escaping = serde_json::json!({SANDBOX_ID: "../x", GATEWAY_ID: "gw-a"});
        assert!(sandbox_object("sandboxes", "gw-a", &object(escaping)).is_none());
        assert_eq!(
            sandbox_selector("gw-a"),
            "openshell.ai/managed-by=openshell,openshell.ai/sandbox-id,openshell.ai/gateway-id=gw-a"
        );
        assert!(valid_label_value("openshell"));
        for bad in ["", "a,b", "a=b", "-a", "a b", &"x".repeat(64)] {
            assert!(!valid_label_value(bad), "{bad}");
        }
    }
}
