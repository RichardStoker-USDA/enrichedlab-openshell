// SPDX-FileCopyrightText: Copyright (c) 2026 EnrichedLab contributors
// SPDX-License-Identifier: Apache-2.0

//! Operator-controlled sandbox admission at the authenticated gateway boundary.

use std::{path::PathBuf, sync::Arc, time::Duration};

use crate::persistence::{ObjectCursor, ObjectType, Store};
use metrics::{Gauge, counter, gauge};
use openshell_core::config::{GatewayInterceptorBindingPolicy, GatewayInterceptorConfig};
use openshell_core::proto::{Sandbox, SandboxPhase};
use openshell_gateway_interceptors::GatewayInterceptorRuntime;
use prost::Message as _;
use tokio::io::AsyncReadExt as _;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tonic::Status;

const CREATE_SANDBOX: &str = "/openshell.v1.OpenShell/CreateSandbox";
const START_SANDBOX: &str = "/openshell.v1.OpenShell/StartSandbox";
pub const PROVISIONING_WORKERS: &str = "openshell_sandbox_provisioning_workers";
const IN_FLIGHT: &str = "openshell_sandbox_admission_in_flight";
const MAX_IN_FLIGHT: usize = 64;

pub fn guards(path: &str) -> bool {
    matches!(path, CREATE_SANDBOX | START_SANDBOX)
}

#[derive(Debug)]
pub struct SandboxAdmission {
    config: SandboxAdmissionConfig,
    capacity: Arc<Semaphore>,
}

#[derive(Debug)]
struct SandboxAdmissionConfig {
    pause_file: PathBuf,
    receipt_interceptor: String,
    receipt_binding: String,
}

impl SandboxAdmission {
    pub fn from_environment(
        interceptors: &[GatewayInterceptorConfig],
        signed_extensions: bool,
        metrics_enabled: bool,
    ) -> Result<Option<Self>, openshell_core::Error> {
        let pause_file = std::env::var_os("OPENSHELL_SANDBOX_ADMISSION_FILE");
        let receipt_interceptor = std::env::var("OPENSHELL_SANDBOX_RECEIPT_INTERCEPTOR");
        let receipt_binding = std::env::var("OPENSHELL_SANDBOX_RECEIPT_BINDING");

        match (pause_file, receipt_interceptor, receipt_binding) {
            (None, Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => {
                Ok(None)
            }
            (Some(path), Ok(interceptor), Ok(binding)) => Self::new(
                SandboxAdmissionConfig {
                    pause_file: path.into(),
                    receipt_interceptor: interceptor,
                    receipt_binding: binding,
                },
                interceptors,
                signed_extensions,
                metrics_enabled,
            )
            .map(Some),
            _ => Err(openshell_core::Error::config(
                "sandbox admission requires all three environment settings",
            )),
        }
    }

    fn new(
        config: SandboxAdmissionConfig,
        interceptors: &[GatewayInterceptorConfig],
        signed_extensions: bool,
        metrics_enabled: bool,
    ) -> Result<Self, openshell_core::error::Error> {
        use openshell_core::error::Error;
        if !metrics_enabled {
            return Err(Error::config(
                "sandbox admission requires the gateway metrics listener",
            ));
        }
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
        gauge!(IN_FLIGHT).increment(0.0);
        gauge!(PROVISIONING_WORKERS).increment(0.0);
        counter!("openshell_gateway_interceptor_fail_open_total").increment(0);
        for stage in ["response_body", "evaluation"] {
            counter!("openshell_gateway_interceptor_post_commit_observation_failures_total",
                "stage" => stage)
            .increment(0);
        }
        Ok(Self {
            config,
            capacity: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
        })
    }

    async fn read_pause(&self) -> Result<bool, Status> {
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
            b"open" | b"open\n" => Ok(false),
            b"paused" | b"paused\n" => Ok(true),
            _ => Err(unavailable()),
        }
    }

    pub async fn check_open(&self) -> Result<(), Status> {
        if self.read_pause().await? {
            return Err(Status::unavailable("sandbox admissions are paused"));
        }
        Ok(())
    }

    pub async fn is_paused(&self) -> bool {
        matches!(self.read_pause().await, Ok(true))
    }

    /// A failed compensation can leave an active or transitional sandbox even
    /// after driver and request futures have finished. Read the persisted
    /// lifecycle, independently of the process gauges and RPC result.
    pub async fn durable_drain_clear(&self, store: &Store) -> bool {
        tokio::time::timeout(Duration::from_secs(2), async {
            if !self.is_paused().await {
                return false;
            }
            let page_size = 128;
            let mut after = None;
            loop {
                let Ok(records) = store
                    .list_by_type_after(Sandbox::object_type(), after.as_ref(), page_size)
                    .await
                else {
                    return false;
                };
                if !records.iter().all(|record| {
                    Sandbox::decode(record.payload.as_slice()).is_ok_and(|sandbox| {
                        matches!(
                            SandboxPhase::try_from(sandbox.phase()),
                            Ok(SandboxPhase::Stopped | SandboxPhase::Completed)
                        ) && !sandbox
                            .status
                            .and_then(|status| status.provisioning)
                            .is_some_and(|operation| operation.driver_operation_pending)
                    })
                }) {
                    return false;
                }
                if records.len() < page_size as usize {
                    return self.is_paused().await;
                }
                after = records.last().map(ObjectCursor::from);
            }
        })
        .await
        .unwrap_or(false)
    }

    pub async fn enter(&self) -> Result<StartPermit, Status> {
        // Count the request before sampling the file. Once the operator sees a
        // published pause and a zero count, no request that saw "open" remains.
        let capacity =
            self.capacity.clone().try_acquire_owned().map_err(|_| {
                Status::resource_exhausted("too many sandbox admissions in progress")
            })?;
        let permit = StartPermit {
            _activity: ActiveWork::start(IN_FLIGHT),
            _capacity: capacity,
        };
        self.check_open().await?;
        Ok(permit)
    }

    pub async fn require_receipt_service(
        &self,
        interceptors: Option<&GatewayInterceptorRuntime>,
    ) -> Result<(), Status> {
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
            .map_err(|_| not_ready())
    }
}

#[cfg(test)]
impl SandboxAdmission {
    pub fn for_test(pause_file: PathBuf, receipt_interceptor: &str, receipt_binding: &str) -> Self {
        Self {
            config: SandboxAdmissionConfig {
                pause_file,
                receipt_interceptor: receipt_interceptor.into(),
                receipt_binding: receipt_binding.into(),
            },
            capacity: Arc::new(Semaphore::new(1)),
        }
    }
}

/// Held through the RPC response and its post-commit receipt hook.
pub struct StartPermit {
    _activity: ActiveWork,
    _capacity: OwnedSemaphorePermit,
}

pub struct ActiveWork(Gauge);

impl ActiveWork {
    pub fn start(metric: &'static str) -> Self {
        let gauge = gauge!(metric);
        gauge.increment(1.0);
        Self(gauge)
    }
}

impl Drop for ActiveWork {
    fn drop(&mut self) {
        self.0.decrement(1.0);
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

    #[test]
    fn configured_admission_without_metrics_is_refused() {
        let settings = SandboxAdmissionConfig {
            pause_file: "/example/admission".into(),
            receipt_interceptor: "receipts".into(),
            receipt_binding: "record-start".into(),
        };
        let error = SandboxAdmission::new(settings, &[], true, false).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires the gateway metrics listener")
        );
    }

    #[tokio::test]
    async fn maintenance_file_is_fail_closed_and_survives_gateway_reconstruction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sandbox_admission");
        let gateway = || SandboxAdmission::for_test(path.clone(), "receipts", "record-start");
        let error = |r: Result<StartPermit, Status>| r.err().unwrap();

        assert_eq!(
            error(gateway().enter().await).message(),
            "sandbox admission setting is unavailable"
        );
        tokio::fs::write(&path, b"open\n").await.unwrap();
        assert!(gateway().check_open().await.is_ok());
        assert_eq!(
            gateway()
                .require_receipt_service(None)
                .await
                .err()
                .unwrap()
                .message(),
            "sandbox admissions require a ready receipt service"
        );
        tokio::fs::write(&path, b"paused\n").await.unwrap();
        let first = gateway();
        assert_eq!(
            error(first.enter().await).message(),
            "sandbox admissions are paused"
        );
        drop(first);
        assert_eq!(
            error(gateway().enter().await).message(),
            "sandbox admissions are paused"
        );
        tokio::fs::write(&path, b"open\nunexpected").await.unwrap();
        assert_eq!(
            error(gateway().enter().await).message(),
            "sandbox admission setting is unavailable"
        );
    }
}
