// SPDX-FileCopyrightText: Copyright (c) 2026 Richard Stoker
// SPDX-License-Identifier: Apache-2.0

//! `enrichedlab-receipts`: serves the start recorder over TLS and watches the sandbox namespace.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use enrichedlab_receipts::service::{ReceiptInterceptor, StartRecorder};
use enrichedlab_receipts::store::Store;
use enrichedlab_receipts::token::TokenVerifier;
use enrichedlab_receipts::tracker::Tracker;
use openshell_core::proto::gateway_interceptor::v1::gateway_interceptor_server::GatewayInterceptorServer;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tracing::{error, info};

/// The largest interceptor call accepted: a committed sandbox is far smaller.
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Run receipts for `OpenShell` sandboxes.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Address to serve gRPC over TLS on.
    #[arg(long, env = "RECEIPTS_LISTEN", default_value = "0.0.0.0:8443")]
    listen: SocketAddr,
    /// PEM server certificate chain.
    #[arg(long, env = "RECEIPTS_TLS_CERT")]
    tls_cert: PathBuf,
    /// PEM server private key.
    #[arg(long, env = "RECEIPTS_TLS_KEY")]
    tls_key: PathBuf,
    /// Directory on a persistent volume for records and receipts (created mode 0700).
    #[arg(long, env = "RECEIPTS_STATE_DIR")]
    state_dir: PathBuf,
    /// The gateway id: tokens must be issued by `openshell-gateway:<id>`.
    #[arg(long, env = "RECEIPTS_GATEWAY_ID")]
    gateway_id: String,
    /// The gateway's Ed25519 public signing key (PEM, SPKI).
    #[arg(long, env = "RECEIPTS_GATEWAY_PUBLIC_KEY")]
    gateway_public_key: PathBuf,
    /// A file holding the signing key's id; tokens with another `kid` are refused.
    #[arg(long, env = "RECEIPTS_GATEWAY_KEY_ID_FILE")]
    gateway_key_id_file: Option<PathBuf>,
    /// This service's registered audience.
    #[arg(
        long,
        env = "RECEIPTS_AUDIENCE",
        default_value = "urn:openshell:extension:interceptor:run-receipts"
    )]
    audience: String,
    /// The namespace the gateway creates sandboxes in.
    #[arg(long, env = "RECEIPTS_SANDBOX_NAMESPACE")]
    sandbox_namespace: String,
    /// Address to serve Prometheus metrics (plain HTTP, counts only) on.
    #[arg(long, env = "RECEIPTS_METRICS_LISTEN", default_value = "0.0.0.0:9090")]
    metrics_listen: SocketAddr,
    /// The served version of the agent-sandbox `Sandbox` API.
    #[arg(long, env = "RECEIPTS_SANDBOX_API_VERSION", default_value = "v1beta1")]
    sandbox_api_version: String,
    /// The research record's append service (`https://host:port`); receipts are forwarded only
    /// when this is set, and the other `evidence` settings are then required.
    #[arg(long, env = "RECEIPTS_EVIDENCE_ENDPOINT")]
    evidence_endpoint: Option<String>,
    /// CA bundle (PEM) that signed the append service's certificate.
    #[arg(long, env = "RECEIPTS_EVIDENCE_CA", requires = "evidence_endpoint")]
    evidence_ca: Option<PathBuf>,
    /// The name the append service's certificate carries.
    #[arg(
        long,
        env = "RECEIPTS_EVIDENCE_SERVER_NAME",
        requires = "evidence_endpoint"
    )]
    evidence_server_name: Option<String>,
    /// A projected `ServiceAccount` token for the append service's audience.
    #[arg(
        long,
        env = "RECEIPTS_EVIDENCE_TOKEN_FILE",
        requires = "evidence_endpoint"
    )]
    evidence_token_file: Option<PathBuf>,
    /// The research record's tenant.
    #[arg(long, env = "RECEIPTS_EVIDENCE_TENANT", requires = "evidence_endpoint")]
    evidence_tenant: Option<String>,
    /// The lab whose standalone scope holds the receipts.
    #[arg(long, env = "RECEIPTS_EVIDENCE_GROUP", requires = "evidence_endpoint")]
    evidence_group: Option<String>,
}

async fn shutdown() {
    // Kubernetes stops a Pod with SIGTERM; a terminal sends SIGINT.
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut terminate) => {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().json().with_target(false).init();
    openshell_crypto::tls::ensure_default_provider();
    let args = Args::parse();

    enrichedlab_receipts::telemetry::install(args.metrics_listen)?;
    let store = Store::open(&args.state_dir)?;
    let public_key = std::fs::read(&args.gateway_public_key)?;
    let kid = match &args.gateway_key_id_file {
        Some(path) => Some(std::fs::read_to_string(path)?),
        None => None,
    };
    let verifier = TokenVerifier::new(&public_key, kid, &args.gateway_id, &args.audience)?;
    let forwarder = match &args.evidence_endpoint {
        Some(endpoint) => {
            let missing = || "every --evidence-* setting is required with --evidence-endpoint";
            let ca = std::fs::read(args.evidence_ca.as_ref().ok_or_else(missing)?)?;
            let channel = enrichedlab_receipts::forward::channel(
                endpoint,
                &ca,
                args.evidence_server_name.as_deref().ok_or_else(missing)?,
            )?;
            let destination = enrichedlab_receipts::forward::Destination {
                tenant: args.evidence_tenant.clone().ok_or_else(missing)?,
                group: args.evidence_group.clone().ok_or_else(missing)?,
                token_file: args.evidence_token_file.clone().ok_or_else(missing)?,
            };
            Some(tokio::spawn(enrichedlab_receipts::forward::run(
                store.clone(),
                channel,
                destination,
                args.gateway_id.clone(),
                Duration::from_secs(30),
            )))
        }
        None => None,
    };
    let tracker = Arc::new(Tracker::new(store, &args.gateway_id));
    let recorder = Arc::new(StartRecorder::new(tracker.clone(), verifier)?);
    let identity = Identity::from_pem(
        std::fs::read(&args.tls_cert)?,
        std::fs::read(&args.tls_key)?,
    );

    let server = Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity))?
        .timeout(Duration::from_secs(30))
        .concurrency_limit_per_connection(16)
        .add_service(
            GatewayInterceptorServer::new(ReceiptInterceptor(recorder))
                .max_decoding_message_size(MAX_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_MESSAGE_BYTES),
        )
        .serve_with_shutdown(args.listen, shutdown());
    // The watch runs on a worker thread of its own task, so its blocking store writes never hold up
    // the server's accept loop.
    let watch = tokio::spawn(enrichedlab_receipts::cluster::watch(
        tracker,
        args.sandbox_namespace.clone(),
        args.sandbox_api_version,
        args.gateway_id.clone(),
    ));
    info!(
        listen = %args.listen,
        namespace = %args.sandbox_namespace,
        forwarding = forwarder.is_some(),
        "serving run receipts"
    );
    tokio::select! {
        result = server => result?,
        result = watch => {
            error!(error = ?result, "the Kubernetes watch stopped");
            return Err("the Kubernetes watch stopped".into());
        }
    }
    Ok(())
}
