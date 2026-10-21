// SPDX-FileCopyrightText: Copyright (c) 2026 Richard Stoker
// SPDX-License-Identifier: Apache-2.0

//! What the service does with each observation, independent of where the observation came from.
//!
//! Every record is keyed by the gateway's sandbox id, which the gateway assigns when it commits a
//! sandbox and the driver writes on every Kubernetes object of that sandbox; nothing is matched by
//! name. A receipt is written once per sandbox id when its end is observed: from the watch's delete
//! event, from a fresh listing that no longer contains it (deleted while the watch was down, or its
//! delete-time write failed), or, for a committed sandbox that never appeared in Kubernetes, after a
//! grace period. One lock orders every transition, so a start being written and a receipt being
//! finalized for the same sandbox cannot interleave.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use crate::receipt::{
    Ending, Observation, Observed, PodFacts, RECEIPT_SCHEMA, Receipt, SandboxObject, StartRecord,
    standing_gaps,
};
use crate::store::{Store, StoreError, WrittenReceipt};

/// How long a committed sandbox may go without a Kubernetes object before its receipt says it was
/// never provisioned.
pub const PROVISION_GRACE: Duration = Duration::from_hours(1);

/// Sandboxes whose early Pod reports are held, and how long a report is held.
pub const MAX_PENDING_SANDBOXES: usize = 256;
pub const PENDING_TTL: Duration = Duration::from_hours(1);

/// Pod reports that arrived before their sandbox was known to be this gateway's, held in memory until
/// it is (or the report expires), so the order Pod, then Sandbox, then deletion keeps the Pod.
#[derive(Default)]
pub struct Pending {
    /// Per sandbox: when its first report was held, and the reports accumulated as an observed record
    /// would (each Pod's latest view, every image digest reported).
    held: HashMap<String, (Instant, Observed)>,
    /// When (on this process's monotonic clock) the bounds last dropped a report. The dropped report's
    /// sandbox is unknown, so every sandbox established as this gateway's within the hold window after
    /// a drop is flagged, in its own records, as possibly missing a report. One instant cannot fill up,
    /// and one clock cannot skew against another.
    last_unheld: Option<Instant>,
}

impl Pending {
    /// Drops reports held longer than the TTL: by then they belong to another gateway's sandbox.
    pub fn purge(&mut self, now: Instant) {
        self.held
            .retain(|_, (since, _)| now.duration_since(*since) < PENDING_TTL);
    }

    fn hold(&mut self, sandbox_id: &str, pod: PodFacts, at: &str, now: Instant) {
        self.purge(now);
        if !self.held.contains_key(sandbox_id) && self.held.len() >= MAX_PENDING_SANDBOXES {
            self.unheld(now);
            return;
        }
        let (_, held) = self
            .held
            .entry(sandbox_id.to_string())
            .or_insert_with(|| (now, Observed::new(sandbox_id, at)));
        let known = held.pods.iter().any(|known| known.name == pod.name);
        if !known && held.pods.len() >= crate::receipt::MAX_PODS {
            self.unheld(now);
            return;
        }
        held.record_pod(pod, at);
    }

    fn unheld(&mut self, now: Instant) {
        crate::telemetry::pods_unheld(1);
        self.last_unheld = Some(now);
    }

    /// Whether a report was dropped within the hold window before `now`.
    fn recent_drop(&self, now: Instant) -> bool {
        self.last_unheld
            .is_some_and(|dropped| now.saturating_duration_since(dropped) <= PENDING_TTL)
    }

    /// The reports held for a sandbox, left in place until `release` after they are written.
    fn held_for(&self, sandbox_id: &str) -> Option<Observed> {
        self.held.get(sandbox_id).map(|(_, held)| held.clone())
    }

    fn release(&mut self, sandbox_id: &str) {
        self.held.remove(sandbox_id);
    }
}

/// The service's state machine over the store.
pub struct Tracker {
    store: Store,
    gateway: String,
    state: Mutex<Pending>,
}

pub fn stamp(time: chrono::DateTime<chrono::Utc>) -> String {
    time.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

impl Tracker {
    pub fn new(store: Store, gateway_id: &str) -> Self {
        Self {
            store,
            gateway: format!("openshell-gateway:{gateway_id}"),
            state: Mutex::new(Pending::default()),
        }
    }

    fn guard(&self) -> MutexGuard<'_, Pending> {
        // The durable state is on disk and the held reports are bounded best effort, so a panic while
        // holding the lock leaves nothing that needs repair.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Moves held Pod reports of a sandbox now known to be this gateway's into its observed record.
    fn promote(
        &self,
        pending: &mut Pending,
        sandbox_id: &str,
        now: &str,
        unheld: bool,
    ) -> Result<(), StoreError> {
        let Some(held) = pending.held_for(sandbox_id) else {
            return Ok(());
        };
        let mut observed = self.load_observed(sandbox_id, now)?;
        observed.absorb(&held);
        observed.pods_unheld |= unheld;
        self.store.write_observed(sandbox_id, &observed)?;
        pending.release(sandbox_id);
        Ok(())
    }

    /// The sandbox ids with an observed record: the snapshot a listing is compared against.
    pub fn observed_ids(&self) -> Result<HashSet<String>, StoreError> {
        let _guard = self.guard();
        Ok(self.store.observed()?.into_iter().collect())
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// How many start and observed records are held.
    pub fn tracked(&self) -> Result<(usize, usize), StoreError> {
        Ok((self.store.starts()?.len(), self.store.observed()?.len()))
    }

    /// Keeps the gateway's committed start, unless one is kept already or the sandbox has ended.
    pub fn record_start(&self, start: &StartRecord) -> Result<bool, StoreError> {
        let mut pending = self.guard();
        if self.store.has_receipt(&start.sandbox_id)? {
            return Ok(false);
        }
        let mut start = start.clone();
        start.pods_unheld = pending.recent_drop(Instant::now());
        let written = self.store.write_start(&start.sandbox_id, &start)?;
        // The start is durable; held Pod reports that cannot be moved now stay held for the next write.
        if let Err(error) = self.promote(
            &mut pending,
            &start.sandbox_id,
            &start.recorded_at,
            start.pods_unheld,
        ) {
            crate::telemetry::failure("observe");
            tracing::warn!(sandbox_id = %start.sandbox_id, error = %error, "could not move held Pod reports yet");
        }
        Ok(written)
    }

    fn load_observed(&self, id: &str, now: &str) -> Result<Observed, StoreError> {
        match self.store.read_observed::<Observed>(id) {
            Ok(Some(observed)) if observed.sandbox_id == id => Ok(observed),
            Ok(_) | Err(StoreError::Unreadable(_)) => Ok(Observed::new(id, now)),
            Err(error) => Err(error),
        }
    }

    /// Records the latest view of a sandbox's object.
    /// True when this call first establishes the sandbox as this gateway's, so the caller can catch up
    /// on Pods reported before then.
    pub fn sandbox_seen(&self, object: SandboxObject, now: &str) -> Result<bool, StoreError> {
        let mut pending = self.guard();
        if self.store.has_receipt(&object.sandbox_id)? {
            return Ok(false);
        }
        let mut observed = self.load_observed(&object.sandbox_id, now)?;
        let first = observed.sandbox.is_none();
        if first && pending.recent_drop(Instant::now()) {
            observed.pods_unheld = true;
        }
        observed.last_seen_at = now.to_string();
        observed.sandbox = Some(object.clone());
        if let Some(held) = pending.held_for(&object.sandbox_id) {
            observed.absorb(&held);
        }
        self.store.write_observed(&object.sandbox_id, &observed)?;
        pending.release(&object.sandbox_id);
        Ok(first)
    }

    /// Records the latest view of one of a sandbox's Pods.
    /// Pods are watched across the namespace and may not name their gateway, so their facts are kept
    /// only for a sandbox this service already tracks: one its gateway-scoped watch saw, or one whose
    /// committed start its gateway sent. Others are ignored; false when ignored.
    pub fn pod_seen(&self, sandbox_id: &str, pod: PodFacts, now: &str) -> Result<bool, StoreError> {
        let mut pending = self.guard();
        if self.store.has_receipt(sandbox_id)? {
            return Ok(false);
        }
        let watched = matches!(
            self.store.read_observed::<Observed>(sandbox_id),
            Ok(Some(observed)) if observed.sandbox_id == sandbox_id && observed.sandbox.is_some()
        );
        let started = matches!(
            self.store.read_start::<StartRecord>(sandbox_id),
            Ok(Some(start)) if start.sandbox_id == sandbox_id
        );
        if !watched && !started {
            pending.hold(sandbox_id, pod, now, Instant::now());
            return Ok(false);
        }
        // Held reports are older than this one: merge them first and apply this one on top, in one
        // write, so a stale held view never replaces a newer recorded one.
        let mut observed = self.load_observed(sandbox_id, now)?;
        let held = pending.held_for(sandbox_id);
        if let Some(held) = &held {
            observed.absorb(held);
        }
        observed.record_pod(pod, now);
        self.store.write_observed(sandbox_id, &observed)?;
        if held.is_some() {
            pending.release(sandbox_id);
        }
        Ok(true)
    }

    /// Writes the receipt of a sandbox whose end was observed, then retires its working records.
    pub fn sandbox_ended(
        &self,
        sandbox_id: &str,
        last_object: Option<SandboxObject>,
        observation: Observation,
        now: &str,
    ) -> Result<WrittenReceipt, StoreError> {
        let mut pending = self.guard();
        self.end(&mut pending, sandbox_id, last_object, observation, now)
    }

    fn end(
        &self,
        pending: &mut Pending,
        sandbox_id: &str,
        last_object: Option<SandboxObject>,
        observation: Observation,
        now: &str,
    ) -> Result<WrittenReceipt, StoreError> {
        let mut gaps = standing_gaps();
        // Whether this end is the first time the sandbox is established as this gateway's, decided before
        // held reports are moved: then a recent drop may have been one of its reports, and the flag is
        // written with the moved reports so a retry keeps it.
        let scoped_before = matches!(
            self.store.read_observed::<Observed>(sandbox_id),
            Ok(Some(observed)) if observed.sandbox_id == sandbox_id && observed.sandbox.is_some()
        ) || matches!(
            self.store.read_start::<StartRecord>(sandbox_id),
            Ok(Some(start)) if start.sandbox_id == sandbox_id
        );
        let unheld_now = !scoped_before && pending.recent_drop(Instant::now());
        self.promote(pending, sandbox_id, now, unheld_now)?;
        let observed = match self.store.read_observed::<Observed>(sandbox_id) {
            Ok(observed) => observed.filter(|observed| observed.sandbox_id == sandbox_id),
            Err(StoreError::Unreadable(_)) => {
                gaps.insert(
                    "observed".to_string(),
                    "the observed record could not be read".to_string(),
                );
                None
            }
            Err(error) => return Err(error),
        };
        let start = match self.store.read_start::<StartRecord>(sandbox_id) {
            Ok(Some(start)) if start.sandbox_id == sandbox_id => Some(start),
            Ok(_) => {
                gaps.insert(
                    "start".to_string(),
                    "the gateway's commit of this sandbox was not seen".to_string(),
                );
                None
            }
            Err(StoreError::Unreadable(_)) => {
                gaps.insert(
                    "start".to_string(),
                    "the start record could not be read".to_string(),
                );
                None
            }
            Err(error) => return Err(error),
        };
        if observed
            .as_ref()
            .is_none_or(|observed| observed.pods.is_empty())
        {
            gaps.insert(
                "pods".to_string(),
                "no Pod of this sandbox was recorded before its end".to_string(),
            );
        }
        let sandbox = last_object.or_else(|| {
            observed
                .as_ref()
                .and_then(|observed| observed.sandbox.clone())
        });
        let flagged = observed
            .as_ref()
            .is_some_and(|observed| observed.pods_unheld)
            || start.as_ref().is_some_and(|start| start.pods_unheld)
            || unheld_now;
        if flagged {
            gaps.insert(
                "pods_unheld".to_string(),
                "Pod reports were dropped by the hold's bounds shortly before this sandbox was known; some may have been this sandbox's"
                    .to_string(),
            );
        }
        let receipt = Receipt {
            schema: RECEIPT_SCHEMA.to_string(),
            written_at: now.to_string(),
            gateway: self.gateway.clone(),
            sandbox_id: sandbox_id.to_string(),
            ending: Ending {
                observed_at: now.to_string(),
                observation,
                deletion_timestamp: sandbox
                    .as_ref()
                    .and_then(|object| object.deletion_timestamp.clone()),
            },
            sandbox,
            start,
            first_seen_at: observed
                .as_ref()
                .map(|observed| observed.first_seen_at.clone()),
            last_seen_at: observed
                .as_ref()
                .map(|observed| observed.last_seen_at.clone()),
            pods: observed
                .as_ref()
                .map(|observed| observed.pods.clone())
                .unwrap_or_default(),
            pods_omitted: observed
                .as_ref()
                .map_or(0, |observed| observed.pods_omitted),
            images_omitted: observed
                .as_ref()
                .map_or(0, |observed| observed.images_omitted),
            images_seen: observed
                .map(|observed| observed.images_seen)
                .unwrap_or_default(),
            not_recorded: gaps,
        };
        let bytes = serde_json::to_vec_pretty(&receipt).map_err(StoreError::Encode)?;
        let written = self.store.write_receipt(sandbox_id, &bytes)?;
        self.store.retire(sandbox_id)?;
        Ok(written)
    }

    /// After a complete listing: a sandbox tracked before the listing began (`before`, from
    /// [`Self::observed_ids`]) and missing from it ended while it was not watched. A sandbox first seen
    /// after the listing began is not in `before`, so it is never closed by that listing.
    pub fn close_missing(
        &self,
        before: &HashSet<String>,
        present: &HashSet<String>,
        now: &str,
    ) -> Result<Vec<WrittenReceipt>, StoreError> {
        let mut pending = self.guard();
        let mut written = Vec::new();
        let tracked: HashSet<String> = self.store.observed()?.into_iter().collect();
        let mut missing: Vec<&String> = before
            .iter()
            .filter(|id| !present.contains(*id) && tracked.contains(*id))
            .collect();
        missing.sort();
        for id in missing {
            written.push(self.end(&mut pending, id, None, Observation::MissingFromListing, now)?);
        }
        Ok(written)
    }

    /// After a complete listing (`present`): a committed start older than the grace period, whose
    /// sandbox the listing does not have and the service never saw, is closed. The sandbox was never
    /// provisioned, or it was created and deleted while the service was down. A start whose sandbox is
    /// listed waits for its deletion however old it is.
    pub fn close_unobserved(
        &self,
        present: &HashSet<String>,
        now: &str,
        clock: SystemTime,
    ) -> Result<Vec<WrittenReceipt>, StoreError> {
        let mut pending = self.guard();
        let mut written = Vec::new();
        for (id, recorded) in self.store.starts()? {
            if present.contains(&id)
                || self
                    .store
                    .read_observed::<Observed>(&id)
                    .ok()
                    .flatten()
                    .is_some()
            {
                continue;
            }
            if clock.duration_since(recorded).unwrap_or_default() >= PROVISION_GRACE {
                written.push(self.end(&mut pending, &id, None, Observation::NotObserved, now)?);
            }
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{BoundedMap, ContainerFacts, START_SCHEMA, TemplateFacts};
    use crate::store::tests::temp_root;
    use std::fs;

    const ID: &str = "0d3c5d0e-6a0f-4c2e-9a51-000000000001";

    struct Fixture {
        tracker: Tracker,
        root: std::path::PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn fixture() -> Fixture {
        let root = temp_root();
        Fixture {
            tracker: Tracker::new(Store::open(&root).unwrap(), "openshell"),
            root,
        }
    }

    fn object(id: &str) -> SandboxObject {
        SandboxObject {
            namespace: "sandboxes".to_string(),
            object_name: "default--run-1".to_string(),
            uid: Some("uid-1".to_string()),
            sandbox_id: id.to_string(),
            workspace: Some("default".to_string()),
            name: Some("run-1".to_string()),
            generation: Some(1),
            created_at: Some("2026-10-21T10:00:00Z".to_string()),
            deletion_timestamp: None,
            labels: BoundedMap::default(),
        }
    }

    fn start(id: &str) -> StartRecord {
        StartRecord {
            schema: START_SCHEMA.to_string(),
            recorded_at: "2026-10-21T09:59:59Z".to_string(),
            sandbox_id: id.to_string(),
            workspace: "default".to_string(),
            name: "run-1".to_string(),
            created_time: None,
            principal: BoundedMap::default(),
            labels: BoundedMap::default(),
            annotations: BoundedMap::default(),
            template: TemplateFacts::default(),
            policy_hash: Some("abc".to_string()),
            providers: Vec::new(),
            program: None,
            command_arguments: 0,
            environment_names: Vec::new(),
            log_level: None,
            pods_unheld: false,
        }
    }

    fn pod(name: &str, component: &str, image: &str) -> PodFacts {
        PodFacts {
            name: name.to_string(),
            component: Some(component.to_string()),
            containers: vec![ContainerFacts {
                name: "c".to_string(),
                image_id: Some(image.to_string()),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn receipt(f: &Fixture, id: &str) -> Receipt {
        serde_json::from_slice(&fs::read(f.root.join(format!("receipts/{id}.json"))).unwrap())
            .unwrap()
    }

    #[test]
    fn a_deleted_sandbox_gets_one_receipt_with_its_start_pods_and_images() {
        let f = fixture();
        assert!(f.tracker.record_start(&start(ID)).unwrap());
        f.tracker.sandbox_seen(object(ID), "t1").unwrap();
        f.tracker
            .pod_seen(ID, pod("default--run-1", "sandbox", "img@sha256:1"), "t2")
            .unwrap();
        f.tracker
            .pod_seen(
                ID,
                pod("os-supervisor-1", "supervisor", "sup@sha256:9"),
                "t3",
            )
            .unwrap();
        let mut last = object(ID);
        last.deletion_timestamp = Some("2026-10-21T11:00:00Z".to_string());
        let written = f
            .tracker
            .sandbox_ended(ID, Some(last), Observation::Deleted, "t4")
            .unwrap();
        assert!(written.new);
        let r = receipt(&f, ID);
        assert_eq!(
            r.start.as_ref().unwrap().policy_hash.as_deref(),
            Some("abc")
        );
        assert_eq!(r.pods.len(), 2);
        assert_eq!(r.images_seen.len(), 2);
        assert_eq!(r.ending.observation, Observation::Deleted);
        assert_eq!(
            r.ending.deletion_timestamp.as_deref(),
            Some("2026-10-21T11:00:00Z")
        );
        assert_eq!(r.first_seen_at.as_deref(), Some("t1"));
        assert!(r.not_recorded.contains_key("main_process_exit"));
        assert!(!r.not_recorded.contains_key("start"));

        let again = f
            .tracker
            .sandbox_ended(ID, None, Observation::Deleted, "t5")
            .unwrap();
        assert!(!again.new, "one receipt per sandbox");
        assert_eq!(again.sha256, written.sha256);
        assert!(
            !f.tracker.record_start(&start(ID)).unwrap(),
            "no start after the end"
        );
        f.tracker.sandbox_seen(object(ID), "t6").unwrap();
        assert!(
            f.tracker.store().observed().unwrap().is_empty(),
            "an ended sandbox is not tracked again"
        );
    }

    #[test]
    fn a_sandbox_missing_from_a_fresh_listing_ended_while_it_was_not_watched() {
        let f = fixture();
        f.tracker.sandbox_seen(object(ID), "t0").unwrap();
        let other = "0d3c5d0e-6a0f-4c2e-9a51-000000000002";
        f.tracker.sandbox_seen(object(other), "t0").unwrap();
        let before = f.tracker.observed_ids().unwrap();
        // First seen after the listing began, so absent from it: never closed by it.
        let newer = "0d3c5d0e-6a0f-4c2e-9a51-000000000003";
        f.tracker.record_start(&start(newer)).unwrap();
        assert!(
            f.tracker
                .pod_seen(newer, pod("p", "sandbox", "img@sha256:1"), "t1")
                .unwrap()
        );
        let present = HashSet::from([other.to_string()]);
        let written = f.tracker.close_missing(&before, &present, "t2").unwrap();
        assert_eq!(
            written.len(),
            1,
            "only the sandbox tracked before the listing and missing from it"
        );
        let r = receipt(&f, ID);
        assert_eq!(r.ending.observation, Observation::MissingFromListing);
        assert_eq!(
            r.not_recorded["start"],
            "the gateway's commit of this sandbox was not seen"
        );
        assert_eq!(
            f.tracker.store().observed().unwrap(),
            vec![other.to_string(), newer.to_string()]
        );
        assert!(
            f.tracker
                .close_missing(&before, &present, "t3")
                .unwrap()
                .is_empty(),
            "a closed sandbox is not closed again"
        );
    }

    #[test]
    fn a_committed_sandbox_absent_from_a_listing_is_closed_after_the_grace_period() {
        let f = fixture();
        f.tracker.record_start(&start(ID)).unwrap();
        let seen = "0d3c5d0e-6a0f-4c2e-9a51-000000000002";
        f.tracker.record_start(&start(seen)).unwrap();
        f.tracker.sandbox_seen(object(seen), "t0").unwrap();
        let listed = "0d3c5d0e-6a0f-4c2e-9a51-000000000003";
        f.tracker.record_start(&start(listed)).unwrap();
        let present = HashSet::from([listed.to_string()]);
        assert!(
            f.tracker
                .close_unobserved(&present, "t1", SystemTime::now())
                .unwrap()
                .is_empty(),
            "within the grace period"
        );
        let later = SystemTime::now() + PROVISION_GRACE + Duration::from_secs(1);
        let written = f.tracker.close_unobserved(&present, "t2", later).unwrap();
        assert_eq!(
            written.len(),
            1,
            "a sandbox seen or listed waits for its deletion"
        );
        assert_eq!(receipt(&f, ID).ending.observation, Observation::NotObserved);
        assert!(receipt(&f, ID).start.is_some());
        assert!(
            f.tracker
                .store()
                .read_start::<StartRecord>(listed)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn pods_of_an_untracked_sandbox_are_ignored() {
        let f = fixture();
        assert!(
            !f.tracker
                .pod_seen(ID, pod("p", "sandbox", "img@sha256:1"), "t1")
                .unwrap()
        );
        assert!(
            f.tracker.store().observed().unwrap().is_empty(),
            "another gateway's Pod leaves no record"
        );
        assert!(
            f.tracker.sandbox_seen(object(ID), "t2").unwrap(),
            "first scoped: the caller catches up on Pods"
        );
        assert!(
            !f.tracker.sandbox_seen(object(ID), "t3").unwrap(),
            "only once"
        );
        assert!(
            f.tracker
                .pod_seen(ID, pod("p", "sandbox", "img@sha256:1"), "t4")
                .unwrap()
        );
    }

    #[test]
    fn a_pod_reported_before_its_sandbox_is_kept_once_the_sandbox_is_known() {
        let f = fixture();
        assert!(
            !f.tracker
                .pod_seen(ID, pod("w", "sandbox", "runtime@sha256:1"), "t1")
                .unwrap(),
            "held, not yet kept"
        );
        assert!(f.tracker.store().observed().unwrap().is_empty());
        assert!(f.tracker.sandbox_seen(object(ID), "t2").unwrap());
        f.tracker
            .sandbox_ended(ID, None, Observation::Deleted, "t3")
            .unwrap();
        let r = receipt(&f, ID);
        assert_eq!(
            r.pods.len(),
            1,
            "the early report survives although the Pod was never reported again"
        );
        assert!(r.images_seen.contains("runtime@sha256:1"));
        assert!(!r.not_recorded.contains_key("pods"));
    }

    #[test]
    fn a_pod_held_when_its_sandbox_is_deleted_goes_into_the_receipt() {
        let f = fixture();
        f.tracker
            .pod_seen(ID, pod("w", "sandbox", "runtime@sha256:1"), "t1")
            .unwrap();
        f.tracker
            .sandbox_ended(ID, Some(object(ID)), Observation::Deleted, "t2")
            .unwrap();
        assert_eq!(receipt(&f, ID).pods.len(), 1);
    }

    #[test]
    fn reports_past_the_hold_bound_are_named_in_the_receipt() {
        let f = fixture();
        for i in 0..MAX_PENDING_SANDBOXES {
            f.tracker
                .pod_seen(
                    &format!("other-{i}"),
                    pod("p", "sandbox", "x@sha256:1"),
                    "t0",
                )
                .unwrap();
        }
        f.tracker
            .pod_seen(ID, pod("w", "sandbox", "runtime@sha256:1"), "t1")
            .unwrap();
        f.tracker.sandbox_seen(object(ID), "t2").unwrap();
        f.tracker
            .sandbox_ended(ID, None, Observation::Deleted, "t3")
            .unwrap();
        let r = receipt(&f, ID);
        assert!(r.pods.is_empty());
        assert!(r.not_recorded.contains_key("pods_unheld"));
        assert!(r.not_recorded.contains_key("pods"));
    }

    #[test]
    fn a_sandbox_established_long_after_the_last_drop_has_no_unheld_gap() {
        let f = fixture();
        let Some(long_ago) = Instant::now().checked_sub(PENDING_TTL + Duration::from_secs(1))
        else {
            return;
        };
        f.tracker.guard().last_unheld = Some(long_ago);
        f.tracker.sandbox_seen(object(ID), "t1").unwrap();
        f.tracker
            .sandbox_ended(ID, None, Observation::Deleted, "t2")
            .unwrap();
        assert!(!receipt(&f, ID).not_recorded.contains_key("pods_unheld"));
        f.tracker.guard().last_unheld = Some(Instant::now());
        let other = "0d3c5d0e-6a0f-4c2e-9a51-000000000002";
        f.tracker.record_start(&start(other)).unwrap();
        f.tracker
            .sandbox_ended(other, None, Observation::Deleted, "t3")
            .unwrap();
        assert!(
            receipt(&f, other).not_recorded.contains_key("pods_unheld"),
            "flagged through the start record"
        );
    }

    #[test]
    fn a_failed_write_keeps_the_held_reports() {
        let f = fixture();
        f.tracker
            .pod_seen(ID, pod("w", "sandbox", "runtime@sha256:1"), "t1")
            .unwrap();
        let observed = f.root.join("observed");
        fs::set_permissions(
            &observed,
            std::os::unix::fs::PermissionsExt::from_mode(0o500),
        )
        .unwrap();
        assert!(f.tracker.sandbox_seen(object(ID), "t2").is_err());
        fs::set_permissions(
            &observed,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        assert!(f.tracker.sandbox_seen(object(ID), "t3").unwrap());
        f.tracker
            .sandbox_ended(ID, None, Observation::Deleted, "t4")
            .unwrap();
        assert_eq!(
            receipt(&f, ID).pods.len(),
            1,
            "the report held through the failed write is kept"
        );
    }

    #[test]
    fn two_early_reports_of_one_pod_keep_both_digests() {
        let f = fixture();
        f.tracker
            .pod_seen(ID, pod("w", "sandbox", "runtime@sha256:1"), "t1")
            .unwrap();
        f.tracker
            .pod_seen(ID, pod("w", "sandbox", "runtime@sha256:2"), "t2")
            .unwrap();
        f.tracker.sandbox_seen(object(ID), "t3").unwrap();
        f.tracker
            .sandbox_ended(ID, None, Observation::Deleted, "t4")
            .unwrap();
        let r = receipt(&f, ID);
        assert_eq!(r.pods.len(), 1);
        assert!(
            r.images_seen.contains("runtime@sha256:1")
                && r.images_seen.contains("runtime@sha256:2")
        );
    }

    #[test]
    fn a_newer_report_is_never_replaced_by_a_held_older_one() {
        let f = fixture();
        let mut early = pod("w", "sandbox", "runtime@sha256:1");
        early.phase = Some("Pending".to_string());
        f.tracker.pod_seen(ID, early, "t1").unwrap();
        let observed = f.root.join("observed");
        fs::set_permissions(
            &observed,
            std::os::unix::fs::PermissionsExt::from_mode(0o500),
        )
        .unwrap();
        assert!(
            f.tracker.record_start(&start(ID)).unwrap(),
            "the start is kept although moving the held report fails"
        );
        fs::set_permissions(
            &observed,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let mut late = pod("w", "sandbox", "runtime@sha256:2");
        late.phase = Some("Failed".to_string());
        assert!(f.tracker.pod_seen(ID, late, "t2").unwrap());
        f.tracker
            .sandbox_ended(ID, None, Observation::Deleted, "t3")
            .unwrap();
        let r = receipt(&f, ID);
        assert_eq!(
            r.pods[0].phase.as_deref(),
            Some("Failed"),
            "the newer view stands"
        );
        assert!(
            r.images_seen.contains("runtime@sha256:1"),
            "the held report's digest is kept"
        );
    }

    #[test]
    fn a_delete_that_first_establishes_a_sandbox_after_a_drop_says_so() {
        let f = fixture();
        f.tracker.guard().last_unheld = Some(Instant::now());
        f.tracker
            .pod_seen(ID, pod("s", "supervisor", "sup@sha256:1"), "t1")
            .unwrap();
        f.tracker
            .sandbox_ended(ID, Some(object(ID)), Observation::Deleted, "t2")
            .unwrap();
        let r = receipt(&f, ID);
        assert_eq!(r.pods.len(), 1, "the held supervisor report is kept");
        assert!(
            r.not_recorded.contains_key("pods_unheld"),
            "and the recent drop is named"
        );
    }

    #[test]
    fn held_reports_expire() {
        let mut pending = Pending::default();
        let then = Instant::now();
        pending.hold(ID, pod("w", "sandbox", "x@sha256:1"), "t0", then);
        pending.purge(then + PENDING_TTL.checked_sub(Duration::from_secs(1)).unwrap());
        assert_eq!(pending.held.len(), 1);
        pending.purge(then + PENDING_TTL);
        assert!(pending.held.is_empty());
    }

    #[test]
    fn a_receipt_without_any_pod_says_so() {
        let f = fixture();
        f.tracker.sandbox_seen(object(ID), "t1").unwrap();
        f.tracker
            .sandbox_ended(ID, None, Observation::Deleted, "t2")
            .unwrap();
        assert_eq!(
            receipt(&f, ID).not_recorded["pods"],
            "no Pod of this sandbox was recorded before its end"
        );
        let other = "0d3c5d0e-6a0f-4c2e-9a51-000000000002";
        f.tracker.sandbox_seen(object(other), "t1").unwrap();
        f.tracker
            .pod_seen(other, pod("p", "sandbox", "img@sha256:1"), "t2")
            .unwrap();
        f.tracker
            .sandbox_ended(other, None, Observation::Deleted, "t3")
            .unwrap();
        assert!(!receipt(&f, other).not_recorded.contains_key("pods"));
    }

    #[test]
    fn a_delete_for_an_unseen_sandbox_still_gets_a_receipt_from_its_last_object() {
        let f = fixture();
        f.tracker
            .sandbox_ended(ID, Some(object(ID)), Observation::Deleted, "t1")
            .unwrap();
        let r = receipt(&f, ID);
        assert_eq!(r.sandbox.unwrap().uid.as_deref(), Some("uid-1"));
        assert!(r.first_seen_at.is_none());
    }

    #[test]
    fn records_of_another_sandbox_are_never_attributed() {
        let f = fixture();
        let mut wrong = start(ID);
        wrong.sandbox_id = "someone-else".to_string();
        f.tracker.store().write_start(ID, &wrong).unwrap();
        f.tracker
            .sandbox_ended(ID, Some(object(ID)), Observation::Deleted, "t1")
            .unwrap();
        assert!(receipt(&f, ID).start.is_none());
    }

    #[test]
    fn an_unreadable_observed_record_is_named_in_the_receipt() {
        let f = fixture();
        fs::write(f.root.join(format!("observed/{ID}.json")), b"broken").unwrap();
        f.tracker
            .sandbox_ended(ID, Some(object(ID)), Observation::Deleted, "t1")
            .unwrap();
        assert_eq!(
            receipt(&f, ID).not_recorded["observed"],
            "the observed record could not be read"
        );
    }
}
