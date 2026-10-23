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
use crate::forward::{Destination, EVENT_TYPE, Pass, idempotency_key, jittered, pass};
use crate::store::Store;
use crate::store::tests::temp_root;

const GATEWAY: &str = "openshell";

/// What the stand-in record answers next; once the script is empty it accepts.
#[derive(Clone)]
enum Answer {
    Accept,
    /// Appends, then the answer is lost on the way back.
    AcceptLost,
    Refuse(Code, &'static str),
}

#[derive(Default)]
struct Seen {
    requests: Vec<(String, AppendRequest)>,
    script: VecDeque<Answer>,
    sequence: u64,
    /// Committed appends by idempotency key: a retry gets the first answer back.
    committed: std::collections::HashMap<String, AppendResponse>,
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
        let key = request.idempotency_key.clone();
        let mut seen = self.0.lock().unwrap();
        seen.requests.push((token, request));
        let answer = seen.script.pop_front().unwrap_or(Answer::Accept);
        if let Answer::Refuse(code, reason) = answer {
            return Err(Status::with_error_details(
                code,
                reason.to_ascii_lowercase(),
                ErrorDetails::with_error_info(
                    reason,
                    "evidence.enrichedlab.org",
                    std::collections::HashMap::<String, String>::new(),
                ),
            ));
        }
        let existing = seen.committed.get(&key).cloned();
        let response = existing.map_or_else(
            || {
                seen.sequence += 1;
                let first = AppendResponse {
                    record_id: format!("record-{}", seen.sequence),
                    stream_id: "stream".into(),
                    sequence: seen.sequence,
                    record_hash: "a".repeat(64),
                    ingested_at: None,
                    replayed: false,
                };
                seen.committed.insert(key, first.clone());
                first
            },
            |first| AppendResponse {
                replayed: true,
                ..first
            },
        );
        if matches!(answer, Answer::AcceptLost) {
            return Err(Status::unavailable("connection reset"));
        }
        Ok(Response::new(response))
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
        store: Store::open(&root).unwrap().with_outbox(),
        record,
        client: EvidenceAppendServiceClient::new(channel),
        destination: Destination {
            tenant: "site".into(),
            group: "operations".into(),
            token_file: token_dir.join("token"),
            retention: std::time::Duration::from_hours(24 * 30),
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
    assert_eq!(h.store.outbox_len().unwrap(), 0);

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
        assert_eq!(h.store.outbox_len().unwrap(), 2, "{code:?}");
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
    // The record appended but the answer was lost: the receipt stays queued and the retry uses the
    // same key, which the record answers with the first append's identity.
    h.script(&[Answer::AcceptLost]);
    assert_eq!(
        h.pass().await,
        Pass::Later {
            forwarded: 0,
            refused: 0
        }
    );
    assert_eq!(h.store.outbox_len().unwrap(), 1);
    h.write("sandbox-b");
    assert_eq!(
        h.pass().await,
        Pass::Done {
            forwarded: 2,
            refused: 0
        }
    );
    let sent = h.sent();
    let key = idempotency_key(GATEWAY, "sandbox-a");
    assert_eq!(
        sent.iter()
            .filter(|(_, request)| request.idempotency_key == key)
            .count(),
        2
    );
    let outcome = h.outcome("sandbox-a");
    assert_eq!(outcome["record"]["replayed"], true);
    assert_eq!(outcome["record"]["record_id"], "record-1");
    assert_eq!(outcome["record"]["sequence"], 1);
    assert_eq!(h.outcome("sandbox-b")["record"]["sequence"], 2);
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
    assert_eq!(h.store.outbox_len().unwrap(), 1);
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

#[test]
fn retries_are_spread_between_half_and_all_of_the_delay() {
    let delay = std::time::Duration::from_mins(1);
    let waits: Vec<_> = (0..200).map(|_| jittered(delay)).collect();
    assert!(
        waits
            .iter()
            .all(|wait| *wait >= delay / 2 && *wait <= delay)
    );
    assert!(
        waits.iter().any(|wait| *wait != waits[0]),
        "every wait was the same"
    );
}

#[tokio::test]
async fn a_receipt_that_cannot_be_sent_never_holds_back_the_ones_after_it() {
    let mut h = harness().await;
    // A crash between the receipt and its digest file: the digest is written again from the receipt.
    let lost_digest = h.write("sandbox-1-digest-lost");
    fs::remove_file(h.root.join("receipts/sandbox-1-digest-lost.json.sha256")).unwrap();
    // A receipt that is not a record at all, with no digest file either.
    h.write("sandbox-2-garbled");
    fs::write(h.root.join("receipts/sandbox-2-garbled.json"), b"{not json").unwrap();
    fs::remove_file(h.root.join("receipts/sandbox-2-garbled.json.sha256")).unwrap();
    // Larger than the store reads back at all.
    let mut huge = receipt("sandbox-3-huge", "2026-10-23T12:00:00Z");
    huge.pop();
    huge.extend(format!(",\"padding\":\"{}\"}}", "x".repeat(5 * 1024 * 1024)).bytes());
    h.store.write_receipt("sandbox-3-huge", &huge).unwrap();
    // Cannot be opened right now: skipped for this pass, kept queued.
    h.write("sandbox-4-locked");
    let locked = h.root.join("receipts/sandbox-4-locked.json");
    fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
    // Removed while queued: its marker is dropped.
    h.write("sandbox-5-gone");
    fs::remove_file(h.root.join("receipts/sandbox-5-gone.json")).unwrap();
    // And a valid receipt queued after all of them.
    h.write("sandbox-6-valid");

    assert_eq!(
        h.pass().await,
        Pass::Done {
            forwarded: 2,
            refused: 2
        }
    );
    let sent = h.sent();
    let sent_key = |id: &str| {
        sent.iter()
            .any(|(_, request)| request.idempotency_key == idempotency_key(GATEWAY, id))
    };
    assert!(sent_key("sandbox-1-digest-lost") && sent_key("sandbox-6-valid"));
    assert_eq!(
        fs::read_to_string(h.root.join("receipts/sandbox-1-digest-lost.json.sha256"))
            .unwrap()
            .split_whitespace()
            .next(),
        Some(crate::store::hex(&Sha256::digest(&lost_digest)).as_str())
    );
    assert_eq!(
        h.outcome("sandbox-2-garbled")["refused"]["reason"],
        "RECEIPT_UNREADABLE"
    );
    assert_eq!(
        h.outcome("sandbox-3-huge")["refused"]["reason"],
        "PAYLOAD_SIZE"
    );
    assert!(!h.root.join("outbox/sandbox-5-gone").exists());
    assert_eq!(
        h.store.outbox(64).unwrap(),
        vec!["sandbox-4-locked".to_string()]
    );

    fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    assert_eq!(
        h.pass().await,
        Pass::Done {
            forwarded: 1,
            refused: 0
        }
    );
    assert_eq!(h.store.outbox_len().unwrap(), 0);
}

#[tokio::test]
async fn receipts_written_before_forwarding_are_queued_once_at_start() {
    let root = temp_root();
    {
        let plain = Store::open(&root).unwrap();
        for id in ["early-a", "early-b"] {
            plain
                .write_receipt(id, &receipt(id, "2026-10-23T12:00:00Z"))
                .unwrap();
        }
        plain
            .write_forwarded("early-b", &serde_json::json!({"record": {"sequence": 9}}))
            .unwrap();
        assert_eq!(plain.outbox_len().unwrap(), 0);
    }
    let store = Store::open(&root).unwrap().with_outbox();
    assert_eq!(store.enqueue_unforwarded().unwrap(), 1);
    assert_eq!(store.enqueue_unforwarded().unwrap(), 0);
    assert_eq!(store.outbox(64).unwrap(), vec!["early-a".to_string()]);
    drop(store);
    let _ = fs::remove_dir_all(&root);
}

#[tokio::test]
async fn a_listing_holds_only_the_oldest_queued_receipts() {
    let h = harness().await;
    for i in 0..10 {
        h.write(&format!("sandbox-{i:02}"));
        let marker = h.root.join(format!("outbox/sandbox-{i:02}"));
        let at = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000 + i);
        fs::File::options()
            .write(true)
            .open(&marker)
            .unwrap()
            .set_modified(at)
            .unwrap();
    }
    assert_eq!(
        h.store.outbox(3).unwrap(),
        vec!["sandbox-00", "sandbox-01", "sandbox-02"]
    );
    assert_eq!(h.store.outbox_len().unwrap(), 10);
}

#[tokio::test]
async fn forwarded_receipts_leave_the_volume_after_retention_and_refusals_stay() {
    let mut h = harness().await;
    h.write("sandbox-recorded");
    h.write("sandbox-recent");
    h.write("sandbox-refused");
    assert_eq!(
        h.pass().await,
        Pass::Done {
            forwarded: 3,
            refused: 0
        }
    );
    // Stands in for a receipt the record refused.
    fs::write(
        h.root.join("forwarded/sandbox-refused.json"),
        serde_json::to_vec(&serde_json::json!({"refused": {"reason": "PAYLOAD_NOT_JSON"}}))
            .unwrap(),
    )
    .unwrap();
    let old = std::time::SystemTime::now() - std::time::Duration::from_hours(24 * 40);
    for id in ["sandbox-recorded", "sandbox-refused"] {
        fs::File::options()
            .write(true)
            .open(h.root.join(format!("forwarded/{id}.json")))
            .unwrap()
            .set_modified(old)
            .unwrap();
    }
    let before = std::time::SystemTime::now() - h.destination.retention;
    assert_eq!(h.store.prune_forwarded(before, 1_000).unwrap(), 1);
    for gone in [
        "receipts/sandbox-recorded.json",
        "receipts/sandbox-recorded.json.sha256",
        "forwarded/sandbox-recorded.json",
    ] {
        assert!(!h.root.join(gone).exists(), "{gone}");
    }
    for kept in [
        "receipts/sandbox-recent.json",
        "receipts/sandbox-refused.json",
        "forwarded/sandbox-refused.json",
    ] {
        assert!(h.root.join(kept).exists(), "{kept}");
    }
}

#[test]
fn the_channel_refuses_an_endpoint_that_would_send_the_token_in_the_clear() {
    for endpoint in ["http://evidence.example:8443", "http://127.0.0.1:1"] {
        assert!(matches!(
            crate::forward::channel(endpoint, b"", "evidence.example"),
            Err(crate::forward::ChannelError::NotHttps)
        ));
    }
}
