// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Negotiated control contract and boundary routing for the Sandbox Protocol.

use openshell_core::extension_protocol::negotiate_metadata;
use openshell_core::proto::extension::v1::{PeerMetadata, ProtocolVersion};

use crate::backend_proto::OpenBoundaryRequest;
use crate::boundary_protocol::{BoundaryConfig, SandboxRuntimeDescriptor};
use crate::proto::{ExchangeFrame, exchange_frame::Payload};

pub const SANDBOX_PROTOCOL_CAPABILITY: &str = "openshell.sandbox.protocol";
const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };

/// The built-in runtime supports fresh launches; suspend/resume is optional.
#[must_use]
pub fn metadata(implementation: &str) -> PeerMetadata {
    let capabilities = vec![SANDBOX_PROTOCOL_CAPABILITY.to_string()];
    PeerMetadata {
        protocol_version: Some(PROTOCOL_VERSION),
        implementation_name: implementation.to_string(),
        implementation_version: openshell_core::VERSION.to_string(),
        supported_capabilities: capabilities.clone(),
        required_capabilities: capabilities,
    }
}

/// Use the shared extension rules: equal majors and both peers' requirements.
pub fn negotiate(local: &PeerMetadata, remote: Option<PeerMetadata>) -> Result<(), tonic::Status> {
    negotiate_metadata("isolation", "sandbox-protocol", local, remote)
        .map(drop)
        .map_err(|error| tonic::Status::failed_precondition(error.to_string()))
}

/// Check native driver coordinates against the protected runtime bootstrap.
///
/// The caller must first authenticate the bearer against the provisioned
/// sandbox and generation using `SandboxProtocolAuthenticator`, and pass the
/// sandbox it authenticated. A boundary provisioned for one sandbox names it
/// in `config.boundary_id`. A prepared, unassigned boundary names none: its
/// authenticator binds the sandbox of the first gateway-signed credential for
/// its physical runtime, so the descriptor must name that sandbox.
/// This only opens a route; attach, confirm, and start retain their authority.
pub fn validate_open(
    request: &OpenBoundaryRequest,
    config: &BoundaryConfig,
    authenticated_sandbox: &str,
) -> Result<(), tonic::Status> {
    if request.backend_name != crate::BACKEND_NAME
        || request.session_id != config.session_id.to_string()
    {
        return Err(tonic::Status::permission_denied(
            "boundary launch identity does not match runtime",
        ));
    }
    let descriptor: SandboxRuntimeDescriptor =
        serde_json::from_slice(&request.driver_descriptor)
            .map_err(|_| tonic::Status::invalid_argument("invalid OpenShell runtime descriptor"))?;
    let expected_boundary = if config.boundary_id.is_empty() {
        authenticated_sandbox
    } else {
        config.boundary_id.as_str()
    };
    if expected_boundary.is_empty()
        || descriptor.boundary_id != expected_boundary
        || descriptor.generation != config.generation
        || descriptor.session_id != config.session_id
        || descriptor.workload_identity != config.workload_identity
        || descriptor.resource_claims != config.resource_claims
        || descriptor.provisioning_evidence != config.provisioning_evidence
    {
        return Err(tonic::Status::permission_denied(
            "driver descriptor does not match provisioned boundary",
        ));
    }
    Ok(())
}

#[must_use]
pub fn data_chunk(data: Vec<u8>) -> ExchangeFrame {
    ExchangeFrame {
        payload: Some(Payload::RelayData(data)),
    }
}

#[must_use]
pub fn exchange_frame(boundary_id: &str) -> ExchangeFrame {
    ExchangeFrame {
        payload: Some(Payload::BoundaryId(boundary_id.to_string())),
    }
}

/// Adapt a single typed frame for callers inspecting a local response.
pub fn chunk_data(chunk: ExchangeFrame) -> Result<Vec<u8>, tonic::Status> {
    let mut mode = match chunk.payload.as_ref() {
        Some(Payload::Request(_)) => crate::stream_adapter::Mode::Request,
        Some(Payload::Response(_)) => crate::stream_adapter::Mode::Response,
        Some(Payload::Stdin(_) | Payload::StdinClosed(_)) => crate::stream_adapter::Mode::Input,
        Some(Payload::Stdout(_) | Payload::Stderr(_) | Payload::Exit(_)) => {
            crate::stream_adapter::Mode::Output
        }
        Some(Payload::TcpOpenDecision(_)) => crate::stream_adapter::Mode::Decision,
        _ => crate::stream_adapter::Mode::Relay,
    };
    crate::stream_adapter::receive(&mut mode, chunk)
        .map_err(|error| tonic::Status::invalid_argument(error.to_string()))
}

/// A typed control request after the stream's boundary-binding frame.
pub fn request_chunk(
    request: &crate::boundary_protocol::RequestEnvelope,
) -> Result<ExchangeFrame, crate::boundary_protocol::FrameError> {
    use crate::protobuf::WireMessage;
    Ok(ExchangeFrame {
        payload: Some(Payload::Request(request.to_proto()?)),
    })
}

/// A typed control response, preserving the request's correlation ID.
pub fn response_chunk(
    response: &crate::boundary_protocol::ResponseEnvelope,
) -> Result<ExchangeFrame, crate::boundary_protocol::FrameError> {
    use crate::protobuf::WireMessage;
    Ok(ExchangeFrame {
        payload: Some(Payload::Response(response.to_proto()?)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary_protocol::{
        BoundaryListener, GatewayVerificationKey, SandboxTlsClientConfig, SandboxTlsServerConfig,
        SandboxTransport,
    };
    use std::path::PathBuf;

    const PREPARED_BINDING: [(&str, &str); 2] = [
        (
            "kubernetes.sandbox_resource_uid",
            "11111111-1111-4111-8111-111111111111",
        ),
        (
            "kubernetes.workload_pod_uid",
            "22222222-2222-4222-8222-222222222222",
        ),
    ];

    fn config(boundary_id: &str) -> BoundaryConfig {
        BoundaryConfig {
            boundary_id: boundary_id.to_string(),
            generation: "generation-1".to_string(),
            session_id: "550e8400-e29b-41d4-a716-446655440000".parse().unwrap(),
            session_rotation: openshell_core::jwt::SessionRotation::new(1).unwrap(),
            auth_epoch: openshell_core::jwt::CredentialEpoch::new(1).unwrap(),
            gateway_id: "test-gateway".to_string(),
            verification_keys: vec![GatewayVerificationKey {
                key_id: "test-key".to_string(),
                public_key_pem: "unused".to_string(),
            }],
            listener: BoundaryListener::Unix {
                socket_path: PathBuf::from("/test/boundary.sock"),
                tls: SandboxTlsServerConfig {
                    certificate_chain_path: PathBuf::from("/test/boundary.crt"),
                    private_key_path: PathBuf::from("/test/boundary.key"),
                },
            },
            resource_claims: PREPARED_BINDING
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
            resource_claim_files: std::collections::BTreeMap::new(),
            workload_identity:
                openshell_isolation_interface::contract::ResolvedWorkloadIdentity::new(
                    1500,
                    1500,
                    vec![1500],
                    "sandbox".to_string(),
                    "a".repeat(64),
                )
                .unwrap(),
            provisioning_evidence:
                openshell_isolation_interface::contract::ProvisioningEvidence::from_enforcement_evidence(
                    "generation-1",
                    b"test-fence",
                )
                .unwrap(),
            child_env: std::collections::HashMap::new(),
        }
    }

    fn open_request(config: &BoundaryConfig, boundary_id: &str) -> OpenBoundaryRequest {
        let descriptor = SandboxRuntimeDescriptor {
            boundary_id: boundary_id.to_string(),
            generation: config.generation.clone(),
            session_id: config.session_id,
            workload_identity: config.workload_identity.clone(),
            transport: SandboxTransport::Unix {
                socket_path: PathBuf::from("/test/boundary.sock"),
            },
            tls: SandboxTlsClientConfig {
                server_name: "test-boundary".to_string(),
                trust_anchor_pem: "unused".to_string(),
            },
            host_gateway_ip: None,
            resource_claims: config.resource_claims.clone(),
            provisioning_evidence: config.provisioning_evidence.clone(),
        };
        OpenBoundaryRequest {
            session_id: config.session_id.to_string(),
            backend_name: crate::BACKEND_NAME.to_string(),
            driver_descriptor: serde_json::to_vec(&descriptor).unwrap(),
        }
    }

    #[test]
    fn a_provisioned_boundary_opens_only_for_its_own_sandbox() {
        let config = config("sandbox-a");
        validate_open(&open_request(&config, "sandbox-a"), &config, "sandbox-a").unwrap();
        let refused =
            validate_open(&open_request(&config, "sandbox-b"), &config, "sandbox-a").unwrap_err();
        assert_eq!(refused.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn a_prepared_boundary_opens_for_the_sandbox_its_assignment_bound() {
        let config = config("");
        validate_open(&open_request(&config, "sandbox-a"), &config, "sandbox-a").unwrap();
        for (named, authenticated) in [("sandbox-b", "sandbox-a"), ("", "sandbox-a"), ("", "")] {
            let refused =
                validate_open(&open_request(&config, named), &config, authenticated).unwrap_err();
            assert_eq!(refused.code(), tonic::Code::PermissionDenied, "{named:?}");
        }
    }

    #[test]
    fn a_prepared_boundary_still_checks_every_other_coordinate() {
        let config = config("");
        let mut request = open_request(&config, "sandbox-a");
        let mut descriptor: SandboxRuntimeDescriptor =
            serde_json::from_slice(&request.driver_descriptor).unwrap();
        descriptor.generation = "generation-2".to_string();
        request.driver_descriptor = serde_json::to_vec(&descriptor).unwrap();
        assert!(validate_open(&request, &config, "sandbox-a").is_err());
    }
}
