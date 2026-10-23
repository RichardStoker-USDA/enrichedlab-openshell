// SPDX-FileCopyrightText: Copyright (c) 2026 Richard Stoker
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use tonic::transport::{Channel, Server};
use tonic::{Code, Request, Response, Status};
use tonic_types::{ErrorDetails, StatusExt};

use crate::forward::pb::evidence_append_service_client::EvidenceAppendServiceClient;
use crate::forward::pb::evidence_append_service_server::{
    EvidenceAppendService, EvidenceAppendServiceServer,
};
use crate::forward::pb::{AppendRequest, AppendResponse, ScopeKind};
use crate::forward::{Destination, EVENT_TYPE, Pass, idempotency_key, pass};
use crate::store::Store;
use crate::store::tests::temp_root;

const GATEWAY: &str = "openshell";

/// What the stand-in record answers next; once the script is empty it accepts.
#[derive(Clone)]
enum Answer {
    Accept,
    Refuse(Code, &'static str),
}

#[derive(Default)]
struct Seen {
    requests: Vec<(String, AppendRequest)>,
    script: VecDeque<Answer>,
    sequence: u64,
}

#[derive(Clone, Default)]
struct Record(Arc<Mutex<Seen>>);

#[tonic::async_trait]
impl EvidenceAppendService for Record {
    async fn append(
        &self,
        request: Request<AppendRequest>,
    ) -> Result<Response<AppendResponse>, Status> {
        let token = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let request = request.into_inner();
        let mut seen = self.0.lock().unwrap();
        let replayed = seen
            .requests
            .iter()
            .any(|(_, earlier)| earlier.idempotency_key == request.idempotency_key);
        seen.requests.push((token, request));
        match seen.script.pop_front().unwrap_or(Answer::Accept) {
            Answer::Accept => {
                if !replayed {
                    seen.sequence += 1;
                }
                Ok(Response::new(AppendResponse {
                    record_id: format!("record-{}", seen.sequence),
                    stream_id: "stream".into(),
                    sequence: seen.sequence,
                    record_hash: "a".repeat(64),
                    ingested_at: None,
                    replayed,
                }))
            }
            Answer::Refuse(code, reason) => Err(Status::with_error_details(
                code,
                reason.to_ascii_lowercase(),
                ErrorDetails::with_error_info(
                    reason,
                    "evidence.enrichedlab.org",
                    std::collections::HashMap::<String, String>::new(),
                ),
            )),
        }
    }
}

struct Harness {
    store: Store,
    record: Record,
    client: EvidenceAppendServiceClient<Channel>,
    destination: Destination,
    root: PathBuf,
    token_dir: PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
        let _ = fs::remove_dir_all(&self.token_dir);
    }
}

async fn harness() -> Harness {
    let record = Record::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let service = record.clone();
    tokio::spawn(async move {
        Server::builder()
            .add_service(EvidenceAppendServiceServer::new(service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let channel = Channel::from_shared(format!("http://{address}"))
        .unwrap()
        .connect_lazy();
    let root = temp_root();
    let token_dir = temp_root();
    fs::create_dir_all(&token_dir).unwrap();
    fs::write(token_dir.join("token"), "first-token\n").unwrap();
    Harness {
        store: Store::open(&root).unwrap(),
        record,
        client: EvidenceAppendServiceClient::new(channel),
        destination: Destination {
            tenant: "site".into(),
            group: "operations".into(),
            token_file: token_dir.join("token"),
        },
        root,
        token_dir,
    }
}

fn receipt(id: &str, observed_at: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema": "test",
        "sandbox_id": id,
        "ending": {"observed_at": observed_at, "observation": "deleted"},
    }))
    .unwrap()
}

impl Harness {
    fn write(&self, id: &str) -> Vec<u8> {
        let bytes = receipt(id, "2026-10-23T12:00:00.123456789Z");
        self.store.write_receipt(id, &bytes).unwrap();
        bytes
    }

    async fn pass(&mut self) -> Pass {
        pass(&self.store, &mut self.client, &self.destination, GATEWAY)
            .await
            .unwrap()
    }

    fn sent(&self) -> Vec<(String, AppendRequest)> {
        self.record.0.lock().unwrap().requests.clone()
    }

    fn script(&self, answers: &[Answer]) {
        self.record
            .0
            .lock()
            .unwrap()
            .script
            .extend(answers.iter().cloned());
    }

    fn outcome(&self, id: &str) -> serde_json::Value {
        serde_json::from_slice(
            &fs::read(self.root.join("forwarded").join(format!("{id}.json"))).unwrap(),
        )
        .unwrap()
    }
}

#[tokio::test]
async fn forwards_each_receipt_once_as_its_exact_bytes() {
    let mut h = harness().await;
    let first = h.write("sandbox-a");
    h.write("sandbox-b");
    assert_eq!(
        h.pass().await,
        Pass::Done {
            forwarded: 2,
            refused: 0
        }
    );
    let sent = h.sent();
    assert_eq!(sent.len(), 2);
    let (token, request) = sent
        .iter()
        .find(|(_, request)| request.idempotency_key == idempotency_key(GATEWAY, "sandbox-a"))
        .unwrap();
    assert_eq!(token, "Bearer first-token");
    assert_eq!(request.payload, first);
    assert_eq!(
        request.payload_sha256,
        crate::store::hex(&Sha256::digest(&first))
    );
    assert_eq!(request.tenant_id, "site");
    assert_eq!(request.group_key, "operations");
    assert_eq!(request.scope_kind, ScopeKind::Standalone as i32);
    assert!(request.project_id.is_empty() && request.run_id.is_empty());
    assert_eq!(request.event_type, EVENT_TYPE);
    // Microseconds only: the record refuses finer times.
    let time = request.source_time.unwrap();
    assert_eq!(time.nanos, 123_456_000);
    let outcome = h.outcome("sandbox-a");
    assert!(
        outcome["record"]["sequence"].as_u64().is_some(),
        "{outcome}"
    );
    assert!(outcome.get("refused").is_none());
    assert_eq!(h.store.unforwarded_count().unwrap(), 0);

    // Nothing is sent again.
    assert_eq!(
        h.pass().await,
        Pass::Done {
            forwarded: 0,
            refused: 0
        }
    );
    assert_eq!(h.sent().len(), 2);
}

#[tokio::test]
async fn an_unavailable_record_stops_the_pass_and_keeps_receipts_pending() {
    let mut h = harness().await;
    h.write("sandbox-a");
    h.write("sandbox-b");
    for code in [
        Code::Unavailable,
        Code::ResourceExhausted,
        Code::PermissionDenied,
        Code::Unauthenticated,
    ] {
        h.script(&[Answer::Refuse(code, "RECORD_UNAVAILABLE")]);
        assert_eq!(
            h.pass().await,
            Pass::Later {
                forwarded: 0,
                refused: 0
            },
            "{code:?}"
        );
        assert_eq!(h.store.unforwarded_count().unwrap(), 2, "{code:?}");
    }
    // The token is read again for every call, so a rotated token is used at once.
    fs::write(h.destination.token_file.clone(), "second-token").unwrap();
    assert_eq!(
        h.pass().await,
        Pass::Done {
            forwarded: 2,
            refused: 0
        }
    );
    assert!(
        h.sent()
            .iter()
            .rev()
            .take(2)
            .all(|(token, _)| token == "Bearer second-token")
    );
}

#[tokio::test]
async fn a_retry_after_a_lost_answer_returns_the_original_record() {
    let mut h = harness().await;
    h.write("sandbox-a");
    // The record appended but the answer was lost: the receipt stays pending and the retry uses the
    // same key, which the record answers as a replay.
    h.script(&[Answer::Accept]);
    assert_eq!(
        h.pass().await,
        Pass::Done {
            forwarded: 1,
            refused: 0
        }
    );
    fs::remove_file(h.root.join("forwarded/sandbox-a.json")).unwrap();
    assert_eq!(
        h.pass().await,
        Pass::Done {
            forwarded: 1,
            refused: 0
        }
    );
    let sent = h.sent();
    assert_eq!(sent[0].1.idempotency_key, sent[1].1.idempotency_key);
    assert_eq!(h.outcome("sandbox-a")["record"]["replayed"], true);
}

#[tokio::test]
async fn a_refused_receipt_is_kept_with_its_reason_and_not_sent_again() {
    let mut h = harness().await;
    h.write("sandbox-a");
    h.script(&[Answer::Refuse(Code::InvalidArgument, "PAYLOAD_NOT_JSON")]);
    assert_eq!(
        h.pass().await,
        Pass::Done {
            forwarded: 0,
            refused: 1
        }
    );
    let outcome = h.outcome("sandbox-a");
    assert_eq!(outcome["refused"]["reason"], "PAYLOAD_NOT_JSON");
    assert_eq!(outcome["refused"]["code"], "InvalidArgument");
    assert_eq!(
        h.pass().await,
        Pass::Done {
            forwarded: 0,
            refused: 0
        }
    );
    assert_eq!(h.sent().len(), 1);
}

#[tokio::test]
async fn receipts_the_record_could_not_take_are_refused_without_sending() {
    let mut h = harness().await;
    // Larger than the record's payload limit.
    let mut big = receipt("sandbox-big", "2026-10-23T12:00:00Z");
    big.pop();
    big.extend(format!(",\"padding\":\"{}\"}}", "x".repeat(70 * 1024)).bytes());
    h.store.write_receipt("sandbox-big", &big).unwrap();
    // No readable end time.
    h.store
        .write_receipt("sandbox-time", &receipt("sandbox-time", "not a time"))
        .unwrap();
    // Changed after it was written.
    h.write("sandbox-tampered");
    fs::write(
        h.root.join("receipts/sandbox-tampered.json"),
        receipt("x", "2026-10-23T12:00:00Z"),
    )
    .unwrap();
    assert_eq!(
        h.pass().await,
        Pass::Done {
            forwarded: 0,
            refused: 3
        }
    );
    assert!(h.sent().is_empty());
    assert_eq!(
        h.outcome("sandbox-big")["refused"]["reason"],
        "PAYLOAD_SIZE"
    );
    assert_eq!(
        h.outcome("sandbox-time")["refused"]["reason"],
        "SOURCE_TIME_INVALID"
    );
    assert_eq!(
        h.outcome("sandbox-tampered")["refused"]["reason"],
        "RECEIPT_DIGEST_MISMATCH"
    );
}

#[tokio::test]
async fn an_unreadable_token_sends_nothing() {
    let mut h = harness().await;
    h.write("sandbox-a");
    fs::remove_file(&h.destination.token_file).unwrap();
    assert_eq!(
        h.pass().await,
        Pass::Later {
            forwarded: 0,
            refused: 0
        }
    );
    fs::write(&h.destination.token_file, "two words").unwrap();
    assert_eq!(
        h.pass().await,
        Pass::Later {
            forwarded: 0,
            refused: 0
        }
    );
    assert!(h.sent().is_empty());
    assert_eq!(h.store.unforwarded_count().unwrap(), 1);
}

#[test]
fn idempotency_keys_fit_the_record_syntax_for_any_sandbox_id() {
    for id in ["a", &"x".repeat(128)] {
        let key = idempotency_key(GATEWAY, id);
        assert!((8..=128).contains(&key.len()), "{key}");
        assert!(
            key.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-')),
            "{key}"
        );
    }
    assert_ne!(idempotency_key("one", "a"), idempotency_key("two", "a"));
}
