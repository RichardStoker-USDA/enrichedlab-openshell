// SPDX-FileCopyrightText: Copyright (c) 2026 Richard Stoker
// SPDX-License-Identifier: Apache-2.0

//! The service's Prometheus metrics. They carry counts and fixed label values only: no sandbox id,
//! name, path or error text.

use std::net::SocketAddr;

use metrics::{counter, gauge};
use metrics_exporter_prometheus::PrometheusBuilder;

use crate::receipt::Observation;

/// Serves `/metrics` on `listen`. Call inside the Tokio runtime.
pub fn install(listen: SocketAddr) -> Result<(), String> {
    PrometheusBuilder::new()
        .with_http_listener(listen)
        .install()
        .map_err(|error| format!("metrics listener: {error}"))?;
    for observation in [
        Observation::Deleted,
        Observation::MissingFromListing,
        Observation::NotObserved,
    ] {
        counter!("enrichedlab_receipts_written_total", "observation" => observation_label(observation)).absolute(0);
    }
    for operation in OPERATIONS {
        counter!("enrichedlab_receipts_failures_total", "operation" => operation).absolute(0);
    }
    counter!("enrichedlab_receipts_pods_unheld_total").absolute(0);
    for outcome in FORWARD_OUTCOMES {
        counter!("enrichedlab_receipts_forwarded_total", "outcome" => outcome).absolute(0);
    }
    Ok(())
}

/// The operations whose failures are counted.
pub const OPERATIONS: [&str; 6] = [
    "start",
    "observe",
    "receipt",
    "reconcile",
    "watch",
    "forward",
];

/// The outcomes of sending a receipt to the research record.
pub const FORWARD_OUTCOMES: [&str; 4] = ["forwarded", "replayed", "refused", "retry"];

const fn observation_label(observation: Observation) -> &'static str {
    match observation {
        Observation::Deleted => "deleted",
        Observation::MissingFromListing => "missing-from-listing",
        Observation::NotObserved => "not-observed",
    }
}

/// A receipt was written (only new receipts are counted).
pub fn receipt_written(observation: Observation, count: usize) {
    if count > 0 {
        counter!("enrichedlab_receipts_written_total", "observation" => observation_label(observation))
            .increment(u64::try_from(count).unwrap_or(u64::MAX));
    }
}

/// An operation failed; `operation` is one of [`OPERATIONS`].
pub fn failure(operation: &'static str) {
    counter!("enrichedlab_receipts_failures_total", "operation" => operation).increment(1);
}

/// The outcome of one committed start, by its log annotation value.
pub fn start(outcome: &'static str) {
    counter!("enrichedlab_receipts_starts_total", "outcome" => outcome).increment(1);
}

/// A watch completed a full listing of `resource` (`sandboxes` or `pods`).
pub fn listing(resource: &'static str) {
    counter!("enrichedlab_receipts_listings_total", "resource" => resource).increment(1);
}

/// The working records held now.
pub fn tracked(starts: usize, observed: usize) {
    #[allow(clippy::cast_precision_loss)]
    {
        gauge!("enrichedlab_receipts_tracked", "record" => "start").set(starts as f64);
        gauge!("enrichedlab_receipts_tracked", "record" => "observed").set(observed as f64);
    }
}

/// A receipt's forwarding outcome; `outcome` is one of [`FORWARD_OUTCOMES`].
pub fn forwarded(outcome: &'static str) {
    counter!("enrichedlab_receipts_forwarded_total", "outcome" => outcome).increment(1);
}

/// Receipts with no forwarding outcome yet.
pub fn unforwarded(count: usize) {
    #[allow(clippy::cast_precision_loss)]
    gauge!("enrichedlab_receipts_unforwarded").set(count as f64);
}

/// Receipts in the store and the operator's limit; at the limit new sandbox starts are refused.
pub fn stored(count: usize, limit: usize) {
    #[allow(clippy::cast_precision_loss)]
    {
        gauge!("enrichedlab_receipts_stored").set(count as f64);
        gauge!("enrichedlab_receipts_store_limit").set(limit as f64);
    }
}

/// Early Pod reports the service could not hold (its bounds were full); the receipt of an affected
/// sandbox says so.
pub fn pods_unheld(count: u64) {
    counter!("enrichedlab_receipts_pods_unheld_total").increment(count);
}
