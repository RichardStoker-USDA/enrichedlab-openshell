// SPDX-FileCopyrightText: Copyright (c) 2026 EnrichedLab contributors
// SPDX-License-Identifier: Apache-2.0

//! Operator-controlled sandbox admission at the authenticated gateway boundary.

use std::sync::Arc;

use metrics::{Gauge, gauge};
use openshell_core::config::{GatewayInterceptorBindingPolicy, GatewayInterceptorConfig};
use openshell_gateway_interceptors::GatewayInterceptorRuntime;
use tokio::io::AsyncReadExt as _;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tonic::Status;

use crate::config_file::SandboxAdmissionConfig;

const CREATE_SANDBOX: &str = "/openshell.v1.OpenShell/CreateSandbox";
const START_SANDBOX: &str = "/openshell.v1.OpenShell/StartSandbox";
const IN_FLIGHT: &str = "openshell_sandbox_admission_in_flight";
const MAX_IN_FLIGHT: usize = 64;

pub(crate) fn guards(path: &str) -> bool {
    matches!(path, CREATE_SANDBOX | START_SANDBOX)
}

#[derive(Debug)]
pub(crate) struct SandboxAdmission {
    config: SandboxAdmissionConfig,
    in_flight: Gauge,
    capacity: Arc<Semaphore>,
}

impl SandboxAdmission {
    pub(crate) fn new(
        config: SandboxAdmissionConfig,
        interceptors: &[GatewayInterceptorConfig],
        signed_extensions: bool,
    ) -> Result<Self, openshell_core::error::Error> {
        use openshell_core::error::Error;
        if !config.pause_file.is_absolute()
            || config.receipt_binding.trim().is_empty()
            || !signed_extensions
            || !interceptors.iter().any(|interceptor| {
                interceptor.name == config.receipt_interceptor
                    && interceptor.binding_policy == GatewayInterceptorBindingPolicy::Exact
                    && !interceptor.allow_insecure_transport
                    && interceptor.grpc_endpoint.starts_with("https://")
            })
        {
            return Err(Error::config(
                "sandbox admission requires an absolute pause file and an exact authenticated TLS interceptor",
            ));
        }
        let in_flight = gauge!(IN_FLIGHT);
        in_flight.set(0.0);
        Ok(Self {
            config,
            in_flight,
            capacity: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
        })
    }

    async fn check_open(&self) -> Result<(), Status> {
        let unavailable = || Status::unavailable("sandbox admission setting is unavailable");
        let file = tokio::fs::File::open(&self.config.pause_file)
            .await
            .map_err(|_| unavailable())?;
        let mut bytes = Vec::with_capacity(8);
        file.take(8)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| unavailable())?;
        match bytes.as_slice() {
            b"open" | b"open\n" => Ok(()),
            b"paused" | b"paused\n" => Err(Status::unavailable("sandbox admissions are paused")),
            _ => Err(unavailable()),
        }
    }

    pub(crate) async fn enter(
        &self,
        interceptors: Option<&GatewayInterceptorRuntime>,
    ) -> Result<StartPermit, Status> {
        // Count the request before sampling the file. Once the operator sees a
        // published pause and a zero count, no request that saw "open" remains.
        let capacity =
            self.capacity.clone().try_acquire_owned().map_err(|_| {
                Status::resource_exhausted("too many sandbox admissions in progress")
            })?;
        self.in_flight.increment(1.0);
        let permit = StartPermit {
            in_flight: self.in_flight.clone(),
            _capacity: capacity,
        };
        self.check_open().await?;
        let not_ready =
            || Status::unavailable("sandbox admissions require a ready receipt service");
        interceptors
            .ok_or_else(not_ready)?
            .check_post_commit_ready(
                CREATE_SANDBOX,
                &self.config.receipt_interceptor,
                &self.config.receipt_binding,
            )
            .await
            .map_err(|_| not_ready())?;
        // A pause could have arrived during the dependency probe.
        self.check_open().await?;
        Ok(permit)
    }
}

/// Held through the RPC response and its post-commit receipt hook.
pub(crate) struct StartPermit {
    in_flight: Gauge,
    _capacity: OwnedSemaphorePermit,
}

impl Drop for StartPermit {
    fn drop(&mut self) {
        self.in_flight.decrement(1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_sandbox_creation_and_restart_use_the_gate() {
        assert!(guards(CREATE_SANDBOX));
        assert!(guards(START_SANDBOX));
        assert!(!guards("/openshell.v1.OpenShell/GetSandbox"));
        assert!(!guards("/openshell.v1.OpenShell/StopSandbox"));
        assert!(!guards("/openshell.v1.OpenShell/IssueSandboxToken"));
        assert!(!guards("/openshell.v1.OpenShell/CreateSandboxTemplate"));
    }

    #[tokio::test]
    async fn maintenance_file_is_fail_closed_and_survives_gateway_reconstruction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sandbox_admission");
        let gateway = || SandboxAdmission {
            config: SandboxAdmissionConfig {
                pause_file: path.clone(),
                receipt_interceptor: "receipts".into(),
                receipt_binding: "record-start".into(),
            },
            in_flight: Gauge::noop(),
            capacity: Arc::new(Semaphore::new(1)),
        };
        let error = |r: Result<StartPermit, Status>| r.err().unwrap();

        assert_eq!(
            error(gateway().enter(None).await).message(),
            "sandbox admission setting is unavailable"
        );
        tokio::fs::write(&path, b"open\n").await.unwrap();
        assert!(gateway().check_open().await.is_ok());
        assert_eq!(
            error(gateway().enter(None).await).message(),
            "sandbox admissions require a ready receipt service"
        );
        tokio::fs::write(&path, b"paused\n").await.unwrap();
        let first = gateway();
        assert_eq!(
            error(first.enter(None).await).message(),
            "sandbox admissions are paused"
        );
        drop(first);
        assert_eq!(
            error(gateway().enter(None).await).message(),
            "sandbox admissions are paused"
        );
        tokio::fs::write(&path, b"open\nunexpected").await.unwrap();
        assert_eq!(
            error(gateway().enter(None).await).message(),
            "sandbox admission setting is unavailable"
        );
    }
}
