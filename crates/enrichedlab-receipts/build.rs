// SPDX-FileCopyrightText: Copyright (c) 2026 Richard Stoker
// SPDX-License-Identifier: Apache-2.0

//! Generates the research record's append client from the `EnrichedLab` contracts descriptor set in
//! `proto/`, so the build needs no `protoc`.

use prost::Message;

fn main() {
    println!("cargo:rerun-if-changed=proto/enrichedlab_evidence_v1.binpb");
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir");
    let bytes =
        std::fs::read(std::path::Path::new(&manifest).join("proto/enrichedlab_evidence_v1.binpb"))
            .expect("evidence contract descriptor");
    let descriptor =
        prost_types::FileDescriptorSet::decode(bytes.as_slice()).expect("descriptor set");
    tonic_prost_build::configure()
        // The server side is generated too, for the forwarder's tests.
        .build_server(true)
        .build_client(true)
        .compile_fds(descriptor)
        .expect("generate the evidence append client");
}
