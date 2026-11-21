// SPDX-FileCopyrightText: Copyright (c) 2026 Richard Stoker
// SPDX-License-Identifier: Apache-2.0

//! Offline, single-transaction import between this binary's two gateway stores.

use super::{postgres::POSTGRES_MIGRATOR, sqlite::SQLITE_MIGRATOR};
use futures::TryStreamExt;
use miette::{Result, miette};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::migrate::{Migrate, Migrator};
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{ConnectOptions, Connection, PgConnection, SqliteConnection};
use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;

#[derive(sqlx::FromRow, Serialize)]
struct ObjectRow {
    id: String,
    object_type: String,
    name: Option<String>,
    scope: Option<String>,
    version: Option<i64>,
    status: Option<String>,
    dedup_key: Option<String>,
    hit_count: i64,
    payload: Vec<u8>,
    created_at_ms: i64,
    updated_at_ms: i64,
    labels: Option<String>,
    resource_version: i64,
    workspace: String,
}

impl ObjectRow {
    fn normalize_labels(&mut self) -> Result<()> {
        if let Some(labels) = &mut self.labels {
            let labels_map: BTreeMap<String, String> = serde_json::from_str(labels)
                .map_err(|_| miette!("gateway object labels cannot be migrated"))?;
            *labels = serde_json::to_string(&labels_map)
                .map_err(|_| miette!("gateway object labels cannot be encoded"))?;
        }
        Ok(())
    }
}

#[derive(sqlx::FromRow, Serialize)]
struct ClaimRow {
    target: String,
    sandbox_id: String,
    attempt_id: String,
    runtime_generation: String,
}

#[derive(Default, Eq, PartialEq)]
struct Snapshot {
    objects: u64,
    claims: u64,
    digest: String,
}

fn frame(hasher: &mut Sha256, value: &impl Serialize) -> Result<()> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| miette!("gateway snapshot encoding failed"))?;
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

async fn verify_migrations(connection: &mut impl Migrate, migrator: &Migrator) -> Result<()> {
    const TABLE: &str = "_sqlx_migrations";
    if connection
        .dirty_version(TABLE)
        .await
        .map_err(|_| miette!("cannot check gateway migration status"))?
        .is_some()
    {
        return Err(miette!("gateway database has a failed migration"));
    }
    let applied = connection
        .list_applied_migrations(TABLE)
        .await
        .map_err(|_| miette!("cannot read gateway migration history"))?;
    let mut expected = migrator
        .iter()
        .filter(|item| !item.migration_type.is_down_migration());
    for migration in applied {
        let identical = expected.next().is_some_and(|item| {
            migration.version == item.version && migration.checksum == item.checksum
        });
        if !identical {
            return Err(miette!(
                "gateway database schema does not match this binary"
            ));
        }
    }
    if expected.next().is_some() {
        return Err(miette!(
            "gateway database schema does not match this binary"
        ));
    }
    Ok(())
}

const SQLITE_OBJECTS: &str = "SELECT * FROM objects ORDER BY id COLLATE BINARY";
const PG_OBJECTS: &str =
    "SELECT id, object_type, name, scope, version, status, dedup_key, hit_count, payload,
            created_at_ms, updated_at_ms, labels::text AS labels, resource_version, workspace
     FROM objects ORDER BY id COLLATE \"C\"";
const SQLITE_CLAIMS: &str = "SELECT * FROM allocation_claims ORDER BY target COLLATE BINARY";
const PG_CLAIMS: &str = "SELECT * FROM allocation_claims ORDER BY target COLLATE \"C\"";

async fn import(backup: &Path, options: PgConnectOptions) -> Result<Snapshot> {
    let backup = backup
        .canonicalize()
        .map_err(|_| miette!("cannot resolve SQLite backup"))?;
    if !backup.is_file() {
        return Err(miette!("SQLite backup must be a regular file"));
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = backup.as_os_str().to_owned();
        sidecar.push(suffix);
        if Path::new(&sidecar).symlink_metadata().is_ok() {
            return Err(miette!("SQLite backup must be standalone"));
        }
    }
    let mut source = SqliteConnection::connect_with(
        &SqliteConnectOptions::new()
            .filename(&backup)
            .read_only(true)
            .immutable(true),
    )
    .await
    .map_err(|_| miette!("cannot open SQLite backup read-only"))?;
    let mut source = source
        .begin()
        .await
        .map_err(|_| miette!("cannot open SQLite snapshot"))?;
    verify_migrations(&mut *source, &SQLITE_MIGRATOR).await?;
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_schema WHERE type = 'table'
         AND name NOT GLOB 'sqlite_*' ORDER BY name COLLATE BINARY",
    )
    .fetch_all(&mut *source)
    .await
    .map_err(|_| miette!("cannot inventory the SQLite backup"))?;
    if tables != ["_sqlx_migrations", "allocation_claims", "objects"] {
        return Err(miette!("SQLite backup has unexpected tables"));
    }
    let object_columns: Vec<String> =
        sqlx::query_scalar("SELECT name FROM pragma_table_xinfo('objects') ORDER BY name")
            .fetch_all(&mut *source)
            .await
            .map_err(|_| miette!("cannot inventory gateway object fields"))?;
    let claim_columns: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM pragma_table_xinfo('allocation_claims') ORDER BY name",
    )
    .fetch_all(&mut *source)
    .await
    .map_err(|_| miette!("cannot inventory gateway claim fields"))?;
    if object_columns
        != [
            "created_at_ms",
            "dedup_key",
            "hit_count",
            "id",
            "labels",
            "name",
            "object_type",
            "payload",
            "resource_version",
            "scope",
            "status",
            "updated_at_ms",
            "version",
            "workspace",
        ]
        || claim_columns != ["attempt_id", "runtime_generation", "sandbox_id", "target"]
    {
        return Err(miette!("SQLite backup has unexpected gateway fields"));
    }
    let healthy: Vec<String> = sqlx::query_scalar("PRAGMA quick_check")
        .fetch_all(&mut *source)
        .await
        .map_err(|_| miette!("SQLite integrity check failed"))?;
    if healthy != ["ok"] {
        return Err(miette!("SQLite backup failed integrity check"));
    }
    let duplicate_labels: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM objects, json_each(objects.labels)
         GROUP BY objects.id, json_each.key HAVING count(*) > 1)",
    )
    .fetch_one(&mut *source)
    .await
    .map_err(|_| miette!("cannot validate SQLite labels"))?;
    if duplicate_labels {
        return Err(miette!("SQLite labels contain duplicate keys"));
    }

    let mut connection = PgConnection::connect_with(&options.disable_statement_logging())
        .await
        .map_err(|_| miette!("cannot connect to the PostgreSQL target"))?;
    let mut target = connection
        .begin()
        .await
        .map_err(|_| miette!("cannot open target transaction"))?;
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut *target)
        .await
        .map_err(|_| miette!("cannot set target lock deadline"))?;
    let locked: bool = sqlx::query_scalar(
        "SELECT pg_try_advisory_xact_lock(hashtext(current_schema()), 1397048140)",
    )
    .fetch_one(&mut *target)
    .await
    .map_err(|_| miette!("cannot fence gateway imports"))?;
    if !locked {
        return Err(miette!("another gateway import already owns the target"));
    }
    // Restrict unqualified migration SQL to the dedicated target schema. A
    // connection URI may intentionally set a search path with a fallback.
    let schema: Option<String> = sqlx::query_scalar("SELECT current_schema()::text")
        .fetch_one(&mut *target)
        .await
        .map_err(|_| miette!("cannot identify the target schema"))?;
    let schema = schema
        .filter(|name| !name.starts_with("pg_") && name != "information_schema")
        .ok_or_else(|| miette!("a dedicated writable PostgreSQL schema is required"))?;
    sqlx::query("SELECT pg_catalog.set_config('search_path', pg_catalog.quote_ident($1), true)")
        .bind(&schema)
        .execute(&mut *target)
        .await
        .map_err(|_| miette!("cannot isolate the target schema"))?;
    let empty: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1)",
    )
    .bind(&schema)
    .fetch_one(&mut *target)
    .await
    .map_err(|_| miette!("cannot inventory the target schema"))?;
    if !empty {
        return Err(miette!("target PostgreSQL schema must be empty"));
    }
    POSTGRES_MIGRATOR
        .run_direct(None, &mut *target, false)
        .await
        .map_err(|_| miette!("cannot initialize the PostgreSQL gateway schema"))?;
    verify_migrations(&mut *target, &POSTGRES_MIGRATOR).await?;

    let mut expected = Snapshot::default();
    let mut digest = Sha256::new();
    digest.update(b"objects");
    {
        let mut rows = sqlx::query_as::<_, ObjectRow>(SQLITE_OBJECTS).fetch(&mut *source);
        while let Some(mut row) = rows
            .try_next()
            .await
            .map_err(|_| miette!("cannot read a SQLite object"))?
        {
            row.normalize_labels()?;
            sqlx::query(
                "INSERT INTO objects
                 (id,object_type,name,scope,version,status,dedup_key,hit_count,payload,created_at_ms,
                  updated_at_ms,labels,resource_version,workspace)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::text::jsonb,$13,$14)",
            )
            .bind(&row.id).bind(&row.object_type).bind(&row.name).bind(&row.scope)
            .bind(row.version).bind(&row.status).bind(&row.dedup_key).bind(row.hit_count)
            .bind(&row.payload).bind(row.created_at_ms).bind(row.updated_at_ms)
            .bind(&row.labels).bind(row.resource_version).bind(&row.workspace)
            .execute(&mut *target)
            .await
            .map_err(|_| miette!("PostgreSQL rejected a gateway object"))?;
            frame(&mut digest, &row)?;
            expected.objects += 1;
        }
    }
    digest.update(b"allocation_claims");
    {
        let mut rows = sqlx::query_as::<_, ClaimRow>(SQLITE_CLAIMS).fetch(&mut *source);
        while let Some(row) = rows
            .try_next()
            .await
            .map_err(|_| miette!("cannot read a SQLite allocation claim"))?
        {
            sqlx::query(
                "INSERT INTO allocation_claims (target,sandbox_id,attempt_id,runtime_generation)
                 VALUES ($1,$2,$3,$4)",
            )
            .bind(&row.target)
            .bind(&row.sandbox_id)
            .bind(&row.attempt_id)
            .bind(&row.runtime_generation)
            .execute(&mut *target)
            .await
            .map_err(|_| miette!("PostgreSQL rejected a gateway allocation claim"))?;
            frame(&mut digest, &row)?;
            expected.claims += 1;
        }
    }
    expected.digest = format!("{:x}", digest.finalize());
    if read_target(&mut target).await? != expected {
        return Err(miette!(
            "PostgreSQL readback differs from the SQLite snapshot"
        ));
    }
    target
        .commit()
        .await
        .map_err(|_| miette!("target commit outcome could not be confirmed"))?;
    Ok(expected)
}

async fn read_target(target: &mut PgConnection) -> Result<Snapshot> {
    let mut actual = Snapshot::default();
    let mut digest = Sha256::new();
    digest.update(b"objects");
    {
        let mut rows = sqlx::query_as::<_, ObjectRow>(PG_OBJECTS).fetch(&mut *target);
        while let Some(mut row) = rows
            .try_next()
            .await
            .map_err(|_| miette!("cannot verify a PostgreSQL object"))?
        {
            row.normalize_labels()?;
            frame(&mut digest, &row)?;
            actual.objects += 1;
        }
    }
    digest.update(b"allocation_claims");
    {
        let mut rows = sqlx::query_as::<_, ClaimRow>(PG_CLAIMS).fetch(&mut *target);
        while let Some(row) = rows
            .try_next()
            .await
            .map_err(|_| miette!("cannot verify a PostgreSQL allocation claim"))?
        {
            frame(&mut digest, &row)?;
            actual.claims += 1;
        }
    }
    actual.digest = format!("{:x}", digest.finalize());
    Ok(actual)
}

pub async fn run(backup: &Path, uri_file: &Path) -> Result<()> {
    let uri =
        std::fs::read_to_string(uri_file).map_err(|_| miette!("cannot read target URI file"))?;
    let options = PgConnectOptions::from_str(uri.trim())
        .map_err(|_| miette!("invalid PostgreSQL URI"))?
        .ssl_mode(PgSslMode::VerifyFull);
    openshell_crypto::tls::ensure_default_provider();
    let snapshot = import(backup, options).await?;
    println!(
        "objects={} allocation_claims={} sha256={}",
        snapshot.objects, snapshot.claims, snapshot.digest
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::test_postgres::TestSchema;

    async fn backup(path: &Path, corrupt_labels: bool) {
        let mut source = SqliteConnection::connect_with(
            &SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true),
        )
        .await
        .unwrap();
        SQLITE_MIGRATOR.run(&mut source).await.unwrap();
        sqlx::query(
            "INSERT INTO objects (id,object_type,name,scope,version,status,dedup_key,hit_count,payload,
                created_at_ms,updated_at_ms,labels,resource_version,workspace)
             VALUES ('a','sandbox','fixture','scope',7,'ready','synthetic',4,x'00ff01',
                21,42,'{\"z\":\"last\",\"a\":\"first\"}',11,'test_workspace')",
        )
        .execute(&mut source)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO objects (id,object_type,payload,created_at_ms,updated_at_ms,labels)
             VALUES ('b','provider_credential',x'123400ff',1,2,?)",
        )
        .bind(if corrupt_labels { Some("[]") } else { None })
        .execute(&mut source)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO allocation_claims VALUES ('target','a','fixture_attempt','fixture_epoch')",
        )
        .execute(&mut source)
        .await
        .unwrap();
        source.close().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires the disposable PostgreSQL fixture"]
    async fn postgres_import_preserves_gateway_state_and_fences_competing_copies() {
        let target = TestSchema::create("gateway_import").await;
        let options = PgConnectOptions::from_str(target.url()).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("fixture.sqlite");
        backup(&file, false).await;
        let original = std::fs::read(&file).unwrap();
        let (first, second) = tokio::join!(
            import(&file, options.clone()),
            import(&file, options.clone())
        );
        let ((Ok(snapshot), Err(_)) | (Err(_), Ok(snapshot))) = (first, second) else {
            panic!("exactly one copy must commit");
        };
        assert_eq!(snapshot.objects, 2);
        assert_eq!(snapshot.claims, 1);
        let mut recovered = PgConnection::connect_with(&options).await.unwrap();
        assert!(read_target(&mut recovered).await.unwrap() == snapshot);
        let payload: Vec<u8> = sqlx::query_scalar("SELECT payload FROM objects WHERE id='b'")
            .fetch_one(&mut recovered)
            .await
            .unwrap();
        assert_eq!(payload, [0x12, 0x34, 0, 0xff]);
        let (version, workspace): (i64, String) =
            sqlx::query_as("SELECT resource_version,workspace FROM objects WHERE id='a'")
                .fetch_one(&mut recovered)
                .await
                .unwrap();
        assert_eq!(version, 11);
        assert_eq!(workspace, "test_workspace");
        assert!(import(&file, options).await.is_err());
        assert!(read_target(&mut recovered).await.unwrap() == snapshot);
        assert_eq!(std::fs::read(&file).unwrap(), original);
        recovered.close().await.unwrap();
        target.drop_schema().await;
    }

    #[tokio::test]
    #[ignore = "requires the disposable PostgreSQL fixture"]
    async fn postgres_import_failure_rolls_back_schema_and_rows() {
        let target = TestSchema::create("gateway_import_fail").await;
        let options = PgConnectOptions::from_str(target.url()).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("fixture.sqlite");
        backup(&file, true).await;
        let error = import(&file, options.clone()).await.err().unwrap();
        // Corrupt labels are on the second object, after the first insert.
        assert_eq!(
            error.to_string(),
            "gateway object labels cannot be migrated"
        );
        let mut connection = PgConnection::connect_with(&options).await.unwrap();
        let rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname = current_schema()",
        )
        .fetch_one(&mut connection)
        .await
        .unwrap();
        assert_eq!(rows, 0);
        connection.close().await.unwrap();
        target.drop_schema().await;
    }
}
