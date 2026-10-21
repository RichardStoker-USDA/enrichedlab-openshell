// SPDX-FileCopyrightText: Copyright (c) 2026 Richard Stoker
// SPDX-License-Identifier: Apache-2.0

//! The gateway interceptor: one observe-only binding.
//!
//! `CreateSandbox` `post_commit`, `fail_open`: after the gateway has authorized and committed a
//! sandbox, the service keeps the committed sandbox (by its id) as the run's start. It never changes or
//! refuses an operation, so the gateway works whether the service runs or not; a start it did not see
//! is named as missing in that run's receipt. Every call must carry the gateway's extension token.

use std::collections::HashMap;
use std::sync::Arc;

use openshell_core::extension_protocol::{
    ExtensionFamily, extension_metadata, validate_gateway_metadata,
};
use openshell_core::proto::SandboxResponse;
use openshell_core::proto::gateway_interceptor::v1::{
    DescribeRequest, GatewayInterceptorPhase, InterceptorBinding, InterceptorEvaluation,
    InterceptorManifest, InterceptorResult, InterceptorSelector, ProviderProfileSnapshot,
    ProviderProfileSnapshotRequest, gateway_interceptor_server::GatewayInterceptor,
    interceptor_evaluation,
};
use openshell_gateway_interceptors::ProtoJsonCodec;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::receipt::StartRecord;
use crate::token::TokenVerifier;
use crate::tracker::{Tracker, stamp};

const SERVICE: &str = "openshell.v1.OpenShell";
const NAME: &str = "enrichedlab/run-receipts";

/// The interceptor's state.
pub struct StartRecorder {
    tracker: Arc<Tracker>,
    verifier: TokenVerifier,
    codec: ProtoJsonCodec,
}

fn allow(annotations: HashMap<String, String>) -> InterceptorResult {
    InterceptorResult {
        allowed: true,
        reason: String::new(),
        status_code: String::new(),
        patches: Vec::new(),
        log_annotations: annotations,
    }
}

/// Counts the outcome and returns it as the gateway log annotation.
fn annotation(value: &'static str) -> HashMap<String, String> {
    crate::telemetry::start(value);
    if value == "not recorded" || value == "unreadable" {
        crate::telemetry::failure("start");
    }
    HashMap::from([("enrichedlab.receipt.start".to_string(), value.to_string())])
}

impl StartRecorder {
    pub fn new(tracker: Arc<Tracker>, verifier: TokenVerifier) -> Result<Self, String> {
        let codec = ProtoJsonCodec::openshell()
            .map_err(|error| format!("OpenShell descriptors: {error}"))?;
        Ok(Self {
            tracker,
            verifier,
            codec,
        })
    }

    pub fn manifest(&self) -> InterceptorManifest {
        InterceptorManifest {
            name: NAME.to_string(),
            bindings: vec![InterceptorBinding {
                id: "record-sandbox-start".to_string(),
                selector: Some(InterceptorSelector {
                    rpc: format!("{SERVICE}/CreateSandbox"),
                    service: String::new(),
                    method: String::new(),
                }),
                phases: vec![GatewayInterceptorPhase::PostCommit as i32],
                failure_policy: "fail_open".to_string(),
            }],
            failure_policy: "fail_open".to_string(),
            provider_profiles: false,
            expected_audience: self.verifier.audience().to_string(),
            extension: Some(extension_metadata(
                ExtensionFamily::GatewayInterceptor,
                NAME,
                env!("CARGO_PKG_VERSION"),
                [],
            )),
        }
    }

    /// Handles one verified evaluation. Always allows: the binding is observe-only.
    pub fn evaluate_verified(&self, evaluation: &InterceptorEvaluation) -> InterceptorResult {
        if evaluation.method != "CreateSandbox" {
            return allow(HashMap::new());
        }
        let Some(interceptor_evaluation::Phase::PostCommit(post)) = evaluation.phase.as_ref()
        else {
            return allow(HashMap::new());
        };
        let Some(payload) = post.committed_response.as_ref() else {
            return allow(annotation("no response"));
        };
        let value = openshell_core::proto_struct::struct_to_json_value(payload);
        let response = match self
            .codec
            .encode_json_to_message("openshell.v1.SandboxResponse", &value)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                <SandboxResponse as prost::Message>::decode(bytes.as_slice())
                    .map_err(|error| error.to_string())
            }) {
            Ok(response) => response,
            Err(error) => {
                warn!(error = %error, "the committed sandbox cannot be read");
                return allow(annotation("unreadable"));
            }
        };
        let Some(start) = response.sandbox.as_ref().and_then(|sandbox| {
            StartRecord::from_committed(sandbox, &evaluation.principal, stamp(chrono::Utc::now()))
        }) else {
            return allow(annotation("no sandbox id"));
        };
        match self.tracker.record_start(&start) {
            Ok(true) => {
                info!(sandbox_id = %start.sandbox_id, "recorded sandbox start");
                allow(annotation("recorded"))
            }
            Ok(false) => allow(annotation("kept")),
            Err(error) => {
                warn!(sandbox_id = %start.sandbox_id, error = %error, "could not record a sandbox start");
                allow(annotation("not recorded"))
            }
        }
    }
}

/// The gRPC face: every call is checked against the gateway's extension token first.
pub struct ReceiptInterceptor(pub Arc<StartRecorder>);

fn authorization<T>(request: &Request<T>) -> Option<&str> {
    request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
}

#[tonic::async_trait]
impl GatewayInterceptor for ReceiptInterceptor {
    async fn describe(
        &self,
        request: Request<DescribeRequest>,
    ) -> Result<Response<InterceptorManifest>, Status> {
        self.0
            .verifier
            .verify(authorization(&request))
            .map_err(|error| Status::unauthenticated(error.to_string()))?;
        let manifest = self.0.manifest();
        validate_gateway_metadata(
            ExtensionFamily::GatewayInterceptor,
            NAME,
            manifest.extension.as_ref(),
            request.into_inner().gateway,
        )
        .map_err(|error| Status::failed_precondition(error.to_string()))?;
        Ok(Response::new(manifest))
    }

    async fn evaluate(
        &self,
        request: Request<InterceptorEvaluation>,
    ) -> Result<Response<InterceptorResult>, Status> {
        self.0
            .verifier
            .verify(authorization(&request))
            .map_err(|error| Status::unauthenticated(error.to_string()))?;
        let recorder = self.0.clone();
        let evaluation = request.into_inner();
        // File writes are blocking; keep them off the async workers.
        tokio::task::spawn_blocking(move || recorder.evaluate_verified(&evaluation))
            .await
            .map(Response::new)
            .map_err(|_| Status::internal("the start could not be recorded"))
    }

    async fn snapshot_provider_profiles(
        &self,
        _request: Request<ProviderProfileSnapshotRequest>,
    ) -> Result<Response<ProviderProfileSnapshot>, Status> {
        Err(Status::unimplemented(
            "this interceptor vends no provider profiles",
        ))
    }
}
