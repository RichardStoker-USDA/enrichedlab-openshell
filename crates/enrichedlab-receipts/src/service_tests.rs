// SPDX-FileCopyrightText: Copyright (c) 2026 Richard Stoker
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use openshell_core::proto::datamodel::v1::ObjectMeta;
use openshell_core::proto::gateway_interceptor::v1::{
    InterceptorEvaluation, PostCommitEvaluation, ValidateEvaluation,
    gateway_interceptor_server::GatewayInterceptor, interceptor_evaluation,
};
use openshell_core::proto::{Sandbox, SandboxPolicy, SandboxResponse, SandboxSpec};
use openshell_extension_core::{EXTENSION_JWT_TYP, ExtensionCallerKind, ExtensionJwtClaims};
use openshell_gateway_interceptors::ProtoJsonCodec;

use crate::receipt::StartRecord;
use crate::service::{ReceiptInterceptor, StartRecorder};
use crate::store::Store;
use crate::store::tests::temp_root;
use crate::token::TokenVerifier;
use crate::tracker::Tracker;

const AUDIENCE: &str = "urn:openshell:extension:interceptor:run-receipts";
const ID: &str = "0d3c5d0e-6a0f-4c2e-9a51-000000000001";

struct Harness {
    recorder: Arc<StartRecorder>,
    tracker: Arc<Tracker>,
    root: std::path::PathBuf,
    signing: EncodingKey,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn harness() -> Harness {
    let pair = openshell_crypto::pki::generate_jwt_keypair().unwrap();
    let signing = EncodingKey::from_ed_pem(pair.serialize_pem().unwrap().as_bytes()).unwrap();
    let verifier = TokenVerifier::new(
        pair.public_key_pem().as_bytes(),
        None,
        "openshell",
        AUDIENCE,
    )
    .unwrap();
    let root = temp_root();
    let tracker = Arc::new(Tracker::new(Store::open(&root).unwrap(), "openshell"));
    let recorder = Arc::new(StartRecorder::new(tracker.clone(), verifier).unwrap());
    Harness {
        recorder,
        tracker,
        root,
        signing,
    }
}

fn committed(id: &str) -> SandboxResponse {
    SandboxResponse {
        sandbox: Some(Sandbox {
            metadata: Some(ObjectMeta {
                id: id.to_string(),
                name: "run-1".to_string(),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            spec: Some(SandboxSpec {
                command: vec!["python3".to_string(), "--key=never-kept".to_string()],
                environment: HashMap::from([("TOKEN".to_string(), "never-kept".to_string())]),
                policy: Some(SandboxPolicy {
                    version: 1,
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn post_commit(method: &str, response: &SandboxResponse) -> InterceptorEvaluation {
    let value = ProtoJsonCodec::openshell()
        .unwrap()
        .decode_message_to_json("openshell.v1.SandboxResponse", response)
        .unwrap();
    let serde_json::Value::Object(object) = value else {
        panic!("not an object")
    };
    InterceptorEvaluation {
        interceptor_name: "run-receipts".to_string(),
        binding_id: "record-sandbox-start".to_string(),
        service: "openshell.v1.OpenShell".to_string(),
        method: method.to_string(),
        principal: HashMap::from([("subject".to_string(), "operator-1".to_string())]),
        phase: Some(interceptor_evaluation::Phase::PostCommit(
            PostCommitEvaluation {
                committed_response: Some(
                    openshell_core::proto_struct::json_object_to_struct(object).unwrap(),
                ),
            },
        )),
    }
}

#[test]
fn a_committed_create_records_the_start_by_sandbox_id_without_secrets() {
    let h = harness();
    let result = h
        .recorder
        .evaluate_verified(&post_commit("CreateSandbox", &committed(ID)));
    assert!(result.allowed);
    assert_eq!(
        result.log_annotations["enrichedlab.receipt.start"],
        "recorded"
    );
    let start: StartRecord = h.tracker.store().read_start(ID).unwrap().unwrap();
    assert_eq!(start.principal.entries["subject"], "operator-1");
    assert_eq!(start.environment_names, vec!["TOKEN"]);
    let text = fs::read_to_string(h.root.join(format!("starts/{ID}.json"))).unwrap();
    assert!(!text.contains("never-kept"));

    let again = h
        .recorder
        .evaluate_verified(&post_commit("CreateSandbox", &committed(ID)));
    assert_eq!(
        again.log_annotations["enrichedlab.receipt.start"], "kept",
        "the first commit is kept"
    );
}

#[test]
fn every_evaluation_is_allowed_and_only_committed_creates_are_recorded() {
    let h = harness();
    let other = h
        .recorder
        .evaluate_verified(&post_commit("DeleteSandbox", &committed(ID)));
    assert!(other.allowed);
    let validate = InterceptorEvaluation {
        method: "CreateSandbox".to_string(),
        phase: Some(interceptor_evaluation::Phase::Validate(
            ValidateEvaluation::default(),
        )),
        ..Default::default()
    };
    assert!(h.recorder.evaluate_verified(&validate).allowed);
    let unnamed = h
        .recorder
        .evaluate_verified(&post_commit("CreateSandbox", &committed(" ")));
    assert!(unnamed.allowed);
    assert_eq!(
        unnamed.log_annotations["enrichedlab.receipt.start"],
        "no sandbox id"
    );
    let escaping = h
        .recorder
        .evaluate_verified(&post_commit("CreateSandbox", &committed("../x")));
    assert!(escaping.allowed);
    assert_eq!(
        escaping.log_annotations["enrichedlab.receipt.start"],
        "not recorded"
    );
    assert!(h.tracker.store().starts().unwrap().is_empty());
}

#[test]
fn the_manifest_binds_one_observe_only_phase_with_the_audience() {
    let h = harness();
    let manifest = h.recorder.manifest();
    assert_eq!(manifest.expected_audience, AUDIENCE);
    assert_eq!(manifest.bindings.len(), 1);
    let binding = &manifest.bindings[0];
    assert_eq!(
        binding.selector.as_ref().unwrap().rpc,
        "openshell.v1.OpenShell/CreateSandbox"
    );
    assert_eq!(binding.failure_policy, "fail_open");
    assert_eq!(
        binding.phases,
        vec![
            openshell_core::proto::gateway_interceptor::v1::GatewayInterceptorPhase::PostCommit
                as i32
        ]
    );
}

#[tokio::test]
async fn calls_without_the_gateway_token_are_unauthenticated() {
    let h = harness();
    let interceptor = ReceiptInterceptor(h.recorder.clone());
    let refused = interceptor
        .evaluate(tonic::Request::new(post_commit(
            "CreateSandbox",
            &committed(ID),
        )))
        .await
        .unwrap_err();
    assert_eq!(refused.code(), tonic::Code::Unauthenticated);
    assert!(
        h.tracker.store().starts().unwrap().is_empty(),
        "nothing is recorded for an unauthenticated call"
    );

    let now = chrono::Utc::now().timestamp();
    let claims = ExtensionJwtClaims {
        iss: "openshell-gateway:openshell".to_string(),
        aud: AUDIENCE.to_string(),
        sub: "openshell-gateway:openshell".to_string(),
        iat: now,
        exp: now + 600,
        jti: "t".to_string(),
        caller_kind: ExtensionCallerKind::Gateway,
        sandbox_id: None,
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.typ = Some(EXTENSION_JWT_TYP.to_string());
    let token = openshell_crypto::jwt::encode(&header, &claims, &h.signing).unwrap();
    let mut request = tonic::Request::new(post_commit("CreateSandbox", &committed(ID)));
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    let answered = interceptor.evaluate(request).await.unwrap().into_inner();
    assert!(answered.allowed);
    assert_eq!(
        answered.log_annotations["enrichedlab.receipt.start"],
        "recorded"
    );
}
