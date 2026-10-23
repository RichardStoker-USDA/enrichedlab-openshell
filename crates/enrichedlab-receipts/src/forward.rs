// SPDX-FileCopyrightText: Copyright (c) 2026 Richard Stoker
// SPDX-License-Identifier: Apache-2.0

//! Forwards written receipts to the `EnrichedLab` research record (`enrichedlab.evidence.v1.EvidenceAppendService`).
//!
//! The receipts directory is the outbox. Each pass takes the oldest receipts with no outcome in `forwarded/`, sends
//! each one's exact bytes and SHA-256 as a `sandbox.receipt` record, and keeps the record's answer (or the refusal)
//! as the outcome. The idempotency key is derived from the gateway and sandbox ids, so a receipt sent again after a
//! lost answer returns the original record. A refusal that says the service or its authority is unavailable stops
//! the pass and backs off; a refusal of the receipt itself is kept and the receipt is not sent again.
//!
//! Every receipt goes to one configured place: a lab's standalone scope. Sandbox labels are set by whoever creates
//! the sandbox, so they never choose where a record goes.

use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::{Code, Request, Status};
use tonic_types::StatusExt;
use tracing::{info, warn};

use crate::store::{Store, StoreError, hex};
use crate::telemetry;

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    unreachable_pub,
    dead_code,
    unused_imports,
    unused_qualifications,
    rust_2018_idioms
)]
pub mod pb {
    tonic::include_proto!("enrichedlab.evidence.v1");
}

use pb::evidence_append_service_client::EvidenceAppendServiceClient;
use pb::{AppendRequest, ScopeKind};

/// The research record's largest payload.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
/// The largest projected token read.
const MAX_TOKEN_BYTES: u64 = 16 * 1024;
/// Receipts sent in one pass.
const BATCH: usize = 64;
/// The event type of a forwarded receipt.
pub const EVENT_TYPE: &str = "sandbox.receipt";
const OUTCOME_SCHEMA: &str = "enrichedlab.receipts.forwarded/v1";

/// Where receipts go and how the service proves who it is.
#[derive(Debug, Clone)]
pub struct Destination {
    pub tenant: String,
    /// The lab whose standalone scope holds the receipts.
    pub group: String,
    /// A projected `ServiceAccount` token for the record's audience, read again for every call
    /// because the kubelet rotates it.
    pub token_file: PathBuf,
}

/// The TLS channel to the append service; it connects on first use.
pub fn channel(
    endpoint: &str,
    ca_pem: &[u8],
    server_name: &str,
) -> Result<Channel, tonic::transport::Error> {
    Ok(Endpoint::from_shared(endpoint.to_string())?
        .tls_config(
            ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(ca_pem))
                .domain_name(server_name.to_string()),
        )?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .connect_lazy())
}

/// What happened to one receipt, kept in `forwarded/<sandbox id>.json`.
#[derive(Debug, Serialize)]
struct Outcome {
    schema: &'static str,
    at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    record: Option<Recorded>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refused: Option<Refused>,
}

#[derive(Debug, Serialize)]
struct Recorded {
    record_id: String,
    stream_id: String,
    sequence: u64,
    record_hash: String,
    replayed: bool,
}

#[derive(Debug, Serialize)]
struct Refused {
    code: String,
    reason: String,
}

/// How a pass ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Pass {
    /// Every pending receipt in the batch has an outcome now.
    Done { forwarded: usize, refused: usize },
    /// The service or its authority was unavailable; try again later.
    Later { forwarded: usize, refused: usize },
}

/// The idempotency key of a sandbox's receipt: stable for the gateway and sandbox, within the
/// record's syntax whatever the id's length.
pub fn idempotency_key(gateway: &str, sandbox_id: &str) -> String {
    let digest = Sha256::digest(format!("{gateway}\n{sandbox_id}").as_bytes());
    format!("receipt:{}", hex(&digest))
}

/// The receipt's source time: when its end was observed, at the record's microsecond precision.
fn source_time(receipt: &[u8]) -> Option<prost_types::Timestamp> {
    #[derive(serde::Deserialize)]
    struct Ending {
        observed_at: String,
    }
    #[derive(serde::Deserialize)]
    struct Head {
        ending: Ending,
    }
    let head: Head = serde_json::from_slice(receipt).ok()?;
    let at = DateTime::parse_from_rfc3339(&head.ending.observed_at).ok()?;
    let nanos = i32::try_from(at.timestamp_subsec_micros()).ok()? * 1_000;
    Some(prost_types::Timestamp {
        seconds: at.timestamp(),
        nanos,
    })
}

fn read_token(path: &PathBuf) -> Option<String> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_TOKEN_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    let token = text.trim();
    (!token.is_empty()
        && text.len() as u64 <= MAX_TOKEN_BYTES
        && !token.contains(char::is_whitespace))
    .then(|| token.to_string())
}

/// True when the refusal is about the receipt itself, so sending it again would be refused again.
fn refuses_the_receipt(status: &Status) -> bool {
    matches!(
        status.code(),
        Code::InvalidArgument | Code::AlreadyExists | Code::OutOfRange
    )
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn refused(store: &Store, id: &str, code: &str, reason: &str) -> Result<(), StoreError> {
    store
        .write_forwarded(
            id,
            &Outcome {
                schema: OUTCOME_SCHEMA,
                at: now(),
                record: None,
                refused: Some(Refused {
                    code: code.to_string(),
                    reason: reason.to_string(),
                }),
            },
        )
        .map(|_| ())
}

/// Sends the oldest pending receipts once.
pub async fn pass(
    store: &Store,
    client: &mut EvidenceAppendServiceClient<Channel>,
    destination: &Destination,
    gateway: &str,
) -> Result<Pass, StoreError> {
    let (mut forwarded, mut refused_count) = (0, 0);
    for id in store.unforwarded(BATCH)? {
        let (bytes, sha256) = match store.read_receipt(&id) {
            Ok(read) => read,
            Err(StoreError::Digest(_)) => {
                // A receipt that no longer matches its digest never enters the record.
                refused(store, &id, "LOCAL", "RECEIPT_DIGEST_MISMATCH")?;
                telemetry::forwarded("refused");
                refused_count += 1;
                continue;
            }
            Err(error) => return Err(error),
        };
        if bytes.len() > MAX_PAYLOAD_BYTES {
            refused(store, &id, "LOCAL", "PAYLOAD_SIZE")?;
            telemetry::forwarded("refused");
            refused_count += 1;
            continue;
        }
        let Some(source_time) = source_time(&bytes) else {
            refused(store, &id, "LOCAL", "SOURCE_TIME_INVALID")?;
            telemetry::forwarded("refused");
            refused_count += 1;
            continue;
        };
        let Some(token) = read_token(&destination.token_file) else {
            warn!("the projected token for the research record cannot be read");
            telemetry::forwarded("retry");
            return Ok(Pass::Later {
                forwarded,
                refused: refused_count,
            });
        };
        let mut request = Request::new(AppendRequest {
            tenant_id: destination.tenant.clone(),
            group_key: destination.group.clone(),
            scope_kind: ScopeKind::Standalone as i32,
            project_id: String::new(),
            run_id: String::new(),
            event_type: EVENT_TYPE.to_string(),
            idempotency_key: idempotency_key(gateway, &id),
            source_time: Some(source_time),
            payload: bytes,
            payload_sha256: sha256,
        });
        let Ok(value) = format!("Bearer {token}").parse() else {
            telemetry::forwarded("retry");
            return Ok(Pass::Later {
                forwarded,
                refused: refused_count,
            });
        };
        request.metadata_mut().insert("authorization", value);
        match client.append(request).await {
            Ok(response) => {
                let answer = response.into_inner();
                store.write_forwarded(
                    &id,
                    &Outcome {
                        schema: OUTCOME_SCHEMA,
                        at: now(),
                        record: Some(Recorded {
                            record_id: answer.record_id,
                            stream_id: answer.stream_id,
                            sequence: answer.sequence,
                            record_hash: answer.record_hash,
                            replayed: answer.replayed,
                        }),
                        refused: None,
                    },
                )?;
                telemetry::forwarded(if answer.replayed {
                    "replayed"
                } else {
                    "forwarded"
                });
                forwarded += 1;
            }
            Err(status) if refuses_the_receipt(&status) => {
                let reason = status
                    .get_details_error_info()
                    .map(|info| info.reason)
                    .unwrap_or_default();
                warn!(code = ?status.code(), reason = %reason, "the research record refused a receipt");
                refused(store, &id, &format!("{:?}", status.code()), &reason)?;
                telemetry::forwarded("refused");
                refused_count += 1;
            }
            Err(status) => {
                let reason = status
                    .get_details_error_info()
                    .map(|info| info.reason)
                    .unwrap_or_default();
                warn!(code = ?status.code(), reason = %reason, "the research record is unavailable; retrying later");
                telemetry::forwarded("retry");
                return Ok(Pass::Later {
                    forwarded,
                    refused: refused_count,
                });
            }
        }
    }
    Ok(Pass::Done {
        forwarded,
        refused: refused_count,
    })
}

/// Forwards receipts for the life of the service: a pass every `interval`, backing off to ten
/// minutes while the record is unavailable.
pub async fn run(
    store: Store,
    channel: Channel,
    destination: Destination,
    gateway: String,
    interval: Duration,
) {
    let mut client = EvidenceAppendServiceClient::new(channel);
    let mut delay = interval;
    loop {
        match pass(&store, &mut client, &destination, &gateway).await {
            Ok(Pass::Done { forwarded, refused }) => {
                if forwarded + refused > 0 {
                    info!(
                        forwarded,
                        refused, "receipts forwarded to the research record"
                    );
                }
                delay = interval;
            }
            Ok(Pass::Later { .. }) => delay = (delay * 2).min(Duration::from_mins(10)),
            Err(error) => {
                warn!(error = %error, "the receipt outbox cannot be read");
                telemetry::failure("forward");
                delay = (delay * 2).min(Duration::from_mins(10));
            }
        }
        if let Ok(count) = store.unforwarded_count() {
            telemetry::unforwarded(count);
        }
        tokio::time::sleep(delay).await;
    }
}
