// SPDX-FileCopyrightText: Copyright (c) 2026 Richard Stoker
// SPDX-License-Identifier: Apache-2.0

//! The records the service keeps, all keyed by the gateway's immutable sandbox id.
//!
//! They are the start the gateway committed, what Kubernetes showed while the sandbox ran, and the
//! receipt written once its deletion is observed.
//!
//! Labels, annotations and the gateway's caller summary are kept because the gateway's API treats
//! them as non-secret metadata (bounded in count and length). Environment values and command
//! arguments may carry credentials, so only environment names, the program and the argument count are
//! kept; no digest of them is kept either, since a digest of a guessable secret can be tested offline.

use std::collections::{BTreeMap, BTreeSet};

use openshell_core::proto::Sandbox;
use serde::{Deserialize, Serialize};

pub const START_SCHEMA: &str = "enrichedlab.openshell.sandbox-start.v1";
pub const OPEN_SCHEMA: &str = "enrichedlab.openshell.sandbox-observed.v1";
pub const RECEIPT_SCHEMA: &str = "enrichedlab.openshell.run-receipt.v1";

const MAX_ENTRIES: usize = 64;
const MAX_TEXT: usize = 256;
/// At most this many Pods, containers per Pod and distinct image digests are kept per sandbox.
pub const MAX_PODS: usize = 16;
pub const MAX_CONTAINERS: usize = 16;
pub const MAX_IMAGES: usize = 64;

pub fn bounded(text: &str) -> String {
    if text.len() <= MAX_TEXT {
        return text.to_string();
    }
    let mut end = MAX_TEXT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// A map kept with at most 64 entries of at most 256 characters each, and how many were left out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedMap {
    pub entries: BTreeMap<String, String>,
    pub omitted: usize,
}

impl BoundedMap {
    pub fn from_pairs<'a>(pairs: impl IntoIterator<Item = (&'a String, &'a String)>) -> Self {
        let mut sorted: Vec<_> = pairs.into_iter().collect();
        sorted.sort();
        let omitted = sorted.len().saturating_sub(MAX_ENTRIES);
        let entries = sorted
            .into_iter()
            .take(MAX_ENTRIES)
            .map(|(key, value)| (bounded(key), bounded(value)))
            .collect();
        Self { entries, omitted }
    }
}

fn non_empty(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| bounded(text))
}

fn names<'a>(keys: impl IntoIterator<Item = &'a String>) -> Vec<String> {
    let mut names: Vec<String> = keys.into_iter().map(|key| bounded(key)).collect();
    names.sort();
    names.dedup();
    names.truncate(MAX_ENTRIES);
    names
}

/// The workload template a sandbox was created with.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateFacts {
    pub image: Option<String>,
    pub runtime_class_name: Option<String>,
    pub labels: BoundedMap,
    pub annotations: BoundedMap,
    pub environment_names: Vec<String>,
    pub user_namespaces: Option<bool>,
}

/// The sandbox as the gateway committed it, from the `CreateSandbox` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartRecord {
    pub schema: String,
    pub recorded_at: String,
    pub sandbox_id: String,
    pub workspace: String,
    pub name: String,
    pub created_time: Option<String>,
    /// The gateway's non-secret summary of the caller that created the sandbox.
    pub principal: BoundedMap,
    pub labels: BoundedMap,
    pub annotations: BoundedMap,
    pub template: TemplateFacts,
    /// `deterministic_policy_hash` of the committed policy, the hash the supervisor reports when it
    /// loads a policy.
    pub policy_hash: Option<String>,
    pub providers: Vec<String>,
    pub program: Option<String>,
    pub command_arguments: usize,
    pub environment_names: Vec<String>,
    pub log_level: Option<String>,
    /// A Pod report was dropped by the hold's bounds shortly before this start was recorded.
    #[serde(default)]
    pub pods_unheld: bool,
}

impl StartRecord {
    /// The start record of a committed sandbox; `None` when the response names no sandbox id.
    pub fn from_committed(
        sandbox: &Sandbox,
        principal: &std::collections::HashMap<String, String>,
        recorded_at: String,
    ) -> Option<Self> {
        let metadata = sandbox.metadata.clone().unwrap_or_default();
        let id = metadata.id.trim().to_string();
        if id.is_empty() {
            return None;
        }
        let spec = sandbox.spec.clone().unwrap_or_default();
        let template = spec.template.clone().unwrap_or_default();
        Some(Self {
            schema: START_SCHEMA.to_string(),
            recorded_at,
            sandbox_id: id,
            workspace: bounded(&metadata.workspace),
            name: bounded(&metadata.name),
            created_time: metadata.created_time.as_ref().and_then(|time| {
                chrono::DateTime::from_timestamp(
                    time.seconds,
                    u32::try_from(time.nanos).unwrap_or(0),
                )
                .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
            }),
            principal: BoundedMap::from_pairs(principal),
            labels: BoundedMap::from_pairs(&metadata.labels),
            annotations: BoundedMap::from_pairs(&metadata.annotations),
            template: TemplateFacts {
                image: non_empty(&template.image),
                runtime_class_name: non_empty(&template.runtime_class_name),
                labels: BoundedMap::from_pairs(&template.labels),
                annotations: BoundedMap::from_pairs(&template.annotations),
                environment_names: names(template.environment.keys()),
                user_namespaces: template.user_namespaces,
            },
            policy_hash: spec
                .policy
                .as_ref()
                .map(openshell_core::policy_identity::deterministic_policy_hash),
            providers: names(spec.providers.iter()),
            program: spec.command.first().map(|program| bounded(program)),
            command_arguments: spec.command.len(),
            environment_names: names(spec.environment.keys()),
            log_level: non_empty(&spec.log_level),
            pods_unheld: false,
        })
    }
}

/// A container of one of the sandbox's Pods, as Kubernetes reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerFacts {
    pub name: String,
    /// An init container: for a sandbox Pod, the one that stages the sandbox runtime.
    #[serde(default)]
    pub init: bool,
    pub image: Option<String>,
    /// The runtime's resolved image reference, normally `<repository>@sha256:<digest>`.
    pub image_id: Option<String>,
    pub restart_count: i32,
    pub state: String,
    pub exit_code: Option<i32>,
    pub reason: Option<String>,
}

/// One Pod of the sandbox (the workload or its supervisor).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PodFacts {
    pub name: String,
    pub uid: Option<String>,
    pub component: Option<String>,
    pub node: Option<String>,
    pub runtime_class_name: Option<String>,
    pub phase: Option<String>,
    pub created_at: Option<String>,
    /// Init containers first, then the others.
    pub containers: Vec<ContainerFacts>,
    /// Containers past the first 16 that were left out.
    #[serde(default)]
    pub containers_omitted: usize,
}

/// The sandbox's Kubernetes object.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxObject {
    pub namespace: String,
    pub object_name: String,
    pub uid: Option<String>,
    pub sandbox_id: String,
    pub workspace: Option<String>,
    pub name: Option<String>,
    pub generation: Option<i64>,
    pub created_at: Option<String>,
    pub deletion_timestamp: Option<String>,
    pub labels: BoundedMap,
}

/// What Kubernetes showed about a sandbox while it ran: the last view of its object and of each Pod,
/// and every image digest its containers reported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observed {
    pub schema: String,
    pub sandbox_id: String,
    pub sandbox: Option<SandboxObject>,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub pods: Vec<PodFacts>,
    pub images_seen: BTreeSet<String>,
    pub pods_omitted: usize,
    /// Image digest reports left out once 64 distinct digests are kept; a digest reported again is
    /// counted again, so this counts reports, not digests.
    #[serde(default)]
    pub images_omitted: usize,
    /// A Pod report was dropped by the hold's bounds shortly before this sandbox was known.
    #[serde(default)]
    pub pods_unheld: bool,
}

impl Observed {
    pub fn new(sandbox_id: &str, now: &str) -> Self {
        Self {
            schema: OPEN_SCHEMA.to_string(),
            sandbox_id: sandbox_id.to_string(),
            sandbox: None,
            first_seen_at: now.to_string(),
            last_seen_at: now.to_string(),
            pods: Vec::new(),
            images_seen: BTreeSet::new(),
            pods_omitted: 0,
            images_omitted: 0,
            pods_unheld: false,
        }
    }

    /// Takes in another record of the same sandbox: its Pods (each replacing an older view of the
    /// same Pod), every image digest it saw, and what it left out.
    pub fn absorb(&mut self, other: &Self) {
        for pod in &other.pods {
            let now = self.last_seen_at.clone();
            self.record_pod(pod.clone(), &now);
        }
        for id in &other.images_seen {
            if self.images_seen.contains(id) {
                continue;
            }
            if self.images_seen.len() < MAX_IMAGES {
                self.images_seen.insert(id.clone());
            } else {
                self.images_omitted += 1;
            }
        }
        self.pods_omitted += other.pods_omitted;
        self.images_omitted += other.images_omitted;
        self.pods_unheld |= other.pods_unheld;
        if other.first_seen_at < self.first_seen_at {
            self.first_seen_at.clone_from(&other.first_seen_at);
        }
    }

    /// Replaces the view of one Pod (by name), keeping at most 16 Pods and 64 image digests.
    pub fn record_pod(&mut self, mut pod: PodFacts, now: &str) {
        if pod.containers.len() > MAX_CONTAINERS {
            pod.containers_omitted += pod.containers.len() - MAX_CONTAINERS;
            pod.containers.truncate(MAX_CONTAINERS);
        }
        for container in &pod.containers {
            if let Some(id) = &container.image_id {
                let id = bounded(id);
                if self.images_seen.contains(&id) {
                    continue;
                }
                if self.images_seen.len() < MAX_IMAGES {
                    self.images_seen.insert(id);
                } else {
                    self.images_omitted += 1;
                }
            }
        }
        if let Some(existing) = self.pods.iter_mut().find(|known| known.name == pod.name) {
            *existing = pod;
        } else if self.pods.len() < MAX_PODS {
            self.pods.push(pod);
            self.pods.sort_by(|a, b| a.name.cmp(&b.name));
        } else {
            self.pods_omitted += 1;
        }
        self.last_seen_at = now.to_string();
    }
}

/// How the service learned that the sandbox was gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Observation {
    /// The deletion arrived on the watch, with the object's last state.
    Deleted,
    /// The object was missing from a fresh listing: it was deleted while the watch was down.
    MissingFromListing,
    /// The gateway committed the sandbox but no Kubernetes object was seen within the grace period:
    /// it was never provisioned, or it was created and deleted while the service was down.
    NotObserved,
}

/// When and how the end of the run was observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ending {
    pub observed_at: String,
    pub observation: Observation,
    pub deletion_timestamp: Option<String>,
}

/// The run receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub schema: String,
    pub written_at: String,
    pub gateway: String,
    pub sandbox_id: String,
    /// The object's last state on the watch.
    pub sandbox: Option<SandboxObject>,
    pub ending: Ending,
    /// Absent when the service did not see the gateway commit this sandbox.
    pub start: Option<StartRecord>,
    pub first_seen_at: Option<String>,
    pub last_seen_at: Option<String>,
    pub pods: Vec<PodFacts>,
    pub pods_omitted: usize,
    pub images_seen: BTreeSet<String>,
    pub images_omitted: usize,
    /// What a receipt is meant to carry that this one could not observe, and why.
    pub not_recorded: BTreeMap<String, String>,
}

/// The fields every receipt lists as not observed, with the reason.
pub fn standing_gaps() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "main_process_exit".to_string(),
            "the gateway keeps the main process's exit status in its own store, which this service does not read"
                .to_string(),
        ),
        (
            "ocsf_events".to_string(),
            "the supervisor's OCSF events are counted elsewhere, not kept; join those counts by the supervisor Pod's name and UID"
                .to_string(),
        ),
        (
            "output_checksums".to_string(),
            "workspace contents are not read; outputs are recorded where they are collected".to_string(),
        ),
        (
            "deleted_by".to_string(),
            "the caller of the delete is in the gateway's audit log; Kubernetes shows only the gateway".to_string(),
        ),
        (
            "prover_result".to_string(),
            "the gateway's prover checks policy proposals and keeps its verdicts in its own store".to_string(),
        ),
        (
            "policy_revisions".to_string(),
            "a policy change's committed response does not name its sandbox, so changes after the start are not recorded"
                .to_string(),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{SandboxPolicy, SandboxSpec, SandboxTemplate};
    use std::collections::HashMap;

    fn sandbox() -> Sandbox {
        Sandbox {
            metadata: Some(ObjectMeta {
                id: "0d3c5d0e-6a0f-4c2e-9a51-000000000001".to_string(),
                name: "run-1".to_string(),
                workspace: "default".to_string(),
                labels: HashMap::from([("task".to_string(), "t-1".to_string())]),
                created_time: Some(prost_types::Timestamp {
                    seconds: 1_792_000_000,
                    nanos: 0,
                }),
                ..Default::default()
            }),
            spec: Some(SandboxSpec {
                command: vec![
                    "python3".to_string(),
                    "train.py".to_string(),
                    "--token=secret".to_string(),
                ],
                environment: HashMap::from([("API_TOKEN".to_string(), "secret-value".to_string())]),
                providers: vec!["models".to_string()],
                policy: Some(SandboxPolicy {
                    version: 1,
                    ..Default::default()
                }),
                template: Some(SandboxTemplate {
                    image: "registry.example.com/agents/worker@sha256:abc".to_string(),
                    runtime_class_name: "kata".to_string(),
                    environment: HashMap::from([("SECOND".to_string(), "hidden".to_string())]),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn a_start_record_keeps_names_and_the_policy_hash_but_no_secret_or_digest_of_one() {
        let principal = HashMap::from([("subject".to_string(), "user-1".to_string())]);
        let record =
            StartRecord::from_committed(&sandbox(), &principal, "2026-10-21T00:00:00Z".to_string())
                .unwrap();
        let text = serde_json::to_string(&record).unwrap();
        assert!(
            !text.contains("secret"),
            "no environment value or argument is kept: {text}"
        );
        assert!(!text.contains("hidden"));
        assert!(
            !text.contains("train.py"),
            "only the program and the argument count"
        );
        assert_eq!(record.sandbox_id, "0d3c5d0e-6a0f-4c2e-9a51-000000000001");
        assert_eq!(record.environment_names, vec!["API_TOKEN"]);
        assert_eq!(record.template.environment_names, vec!["SECOND"]);
        assert_eq!(record.program.as_deref(), Some("python3"));
        assert_eq!(record.command_arguments, 3);
        assert_eq!(record.labels.entries["task"], "t-1");
        assert_eq!(
            record.created_time.as_deref(),
            Some("2026-10-14T17:46:40.000Z")
        );
        assert_eq!(
            record.policy_hash.as_deref(),
            Some(
                openshell_core::policy_identity::deterministic_policy_hash(&SandboxPolicy {
                    version: 1,
                    ..Default::default()
                })
                .as_str()
            )
        );
    }

    #[test]
    fn a_response_without_a_sandbox_id_makes_no_start_record() {
        let mut nameless = sandbox();
        nameless.metadata.as_mut().unwrap().id = " ".to_string();
        assert!(StartRecord::from_committed(&nameless, &HashMap::new(), String::new()).is_none());
    }

    #[test]
    fn bounded_maps_cap_count_and_length() {
        let long = "x".repeat(400);
        let pairs: Vec<(String, String)> = (0..70)
            .map(|i| (format!("k{i:02}"), long.clone()))
            .collect();
        let map = BoundedMap::from_pairs(pairs.iter().map(|(k, v)| (k, v)));
        assert_eq!(map.entries.len(), 64);
        assert_eq!(map.omitted, 6);
        assert!(map.entries.values().all(|v| v.chars().count() <= 257));
    }

    #[test]
    fn observed_pods_are_replaced_by_name_and_bounded() {
        let mut observed = Observed::new("id", "t0");
        let pod = |name: &str, image: &str| PodFacts {
            name: name.to_string(),
            containers: vec![ContainerFacts {
                name: "c".to_string(),
                image_id: Some(image.to_string()),
                ..Default::default()
            }],
            ..Default::default()
        };
        observed.record_pod(pod("a", "img@sha256:1"), "t1");
        observed.record_pod(pod("a", "img@sha256:2"), "t2");
        assert_eq!(observed.pods.len(), 1);
        assert_eq!(
            observed.images_seen.len(),
            2,
            "both digests the Pod ran are kept"
        );
        for i in 0..20 {
            observed.record_pod(pod(&format!("p{i:02}"), "img@sha256:1"), "t3");
        }
        assert_eq!(observed.pods.len(), MAX_PODS);
        assert_eq!(observed.pods_omitted, 5);
        let mut many = Observed::new("id", "t0");
        let wide = PodFacts {
            name: "wide".to_string(),
            containers: (0..80)
                .map(|i| ContainerFacts {
                    name: format!("c{i}"),
                    image_id: Some(format!("img@sha256:{i}")),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        many.record_pod(wide, "t1");
        assert_eq!(many.pods[0].containers.len(), MAX_CONTAINERS);
        assert_eq!(many.pods[0].containers_omitted, 64);
        for i in 0..70 {
            many.record_pod(pod(&format!("p{i:02}"), &format!("other@sha256:{i}")), "t2");
        }
        assert_eq!(many.images_seen.len(), MAX_IMAGES);
        assert!(
            many.images_omitted > 0,
            "digests past the bound are counted"
        );
        assert_eq!(observed.last_seen_at, "t3");
    }
}
