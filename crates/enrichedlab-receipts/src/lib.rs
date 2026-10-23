// SPDX-FileCopyrightText: Copyright (c) 2026 Richard Stoker
// SPDX-License-Identifier: Apache-2.0

//! Run receipts for `OpenShell` sandboxes.
//!
//! The service writes one receipt per sandbox when the sandbox ends: the `Sandbox` object's identity
//! and generation, each Pod with its image digests, runtime class, placement and container states,
//! the start the gateway committed (template, policy hash, providers, the caller summary), how the end
//! was observed, and an explicit list of what it could not observe. It learns the start from an
//! observe-only gateway interceptor binding and everything else from read-only Kubernetes watches, and
//! binds every record to the gateway's immutable sandbox id. When configured, it also forwards each
//! receipt to the `EnrichedLab` research record over gRPC. See the crate README for deployment.

pub mod cluster;
pub mod forward;
pub mod receipt;
pub mod service;
pub mod store;
pub mod telemetry;
pub mod token;
pub mod tracker;

#[cfg(test)]
mod forward_tests;
#[cfg(test)]
mod service_tests;
