use super::*;
use sqlx::sqlite::SqlitePool;

const ENVELOPE: &str = "AAAAAAAAAAAAAAAAAAAAAA==.AAAAAAAAAAAAAAAA.AA==";

async fn contract(storage: StorageState) {
    let kid = hex::encode(crate::core::crypto::random_bytes(32).unwrap());
    let subject = "b".repeat(64);
    let other = "c".repeat(64);
    let row = SubjectRow {
        kid: kid.clone(),
        subject: subject.clone(),
        seed: ENVELOPE.to_owned(),
    };
    let results = futures_util::future::join_all((0..16).map(|_| storage.save_subject(&row))).await;
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    for error in results.into_iter().filter_map(Result::err) {
        assert!(matches!(
            error.downcast_ref::<crate::error::VectisError>(),
            Some(crate::error::VectisError::Conflict(_))
        ));
    }
    assert_eq!(
        storage.get_subject(&kid, &subject).await.unwrap().seed,
        ENVELOPE
    );
    let first = "d".repeat(64);
    let second = "e".repeat(64);
    storage
        .save_token_for_subject(&kid, &first, ENVELOPE, Some(&subject))
        .await
        .unwrap();
    storage.save_token(&kid, &second, ENVELOPE).await.unwrap();
    let fresh = "f".repeat(64);
    for records in [
        vec![
            TokenRow {
                kid: kid.clone(),
                hashid: fresh.clone(),
                data: ENVELOPE.to_owned(),
                subject: Some(subject.clone()),
            },
            TokenRow {
                kid: kid.clone(),
                hashid: first.clone(),
                data: ENVELOPE.to_owned(),
                subject: Some(subject.clone()),
            },
        ],
        vec![
            TokenRow {
                kid: kid.clone(),
                hashid: fresh.clone(),
                data: ENVELOPE.to_owned(),
                subject: Some(subject.clone()),
            },
            TokenRow {
                kid: kid.clone(),
                hashid: fresh.clone(),
                data: ENVELOPE.to_owned(),
                subject: Some(subject.clone()),
            },
        ],
    ] {
        assert!(storage.save_tokens_batch(&records).await.is_err());
        assert!(storage.get_token(&kid, &fresh).await.is_err());
    }
    assert!(storage.delete_token(&kid, &first).await.is_err());
    assert!(
        storage
            .delete_token_for_subject(&kid, &first, Some(&other))
            .await
            .is_err()
    );
    let rows = storage
        .get_tokens_batch(
            &kid,
            &[second.clone(), first.clone(), first.clone()],
            ENVELOPE.len() * 3,
        )
        .await
        .unwrap();
    assert!(rows[0].as_ref().unwrap().subject.is_none());
    assert_eq!(
        rows[1].as_ref().unwrap().subject.as_deref(),
        Some(subject.as_str())
    );
    assert_eq!(
        rows[2].as_ref().unwrap().subject.as_deref(),
        Some(subject.as_str())
    );
    assert!(
        storage
            .consume_tokens_batch_for_subject(
                &kid,
                &[first.clone(), second.clone()],
                Some(&subject)
            )
            .await
            .is_err()
    );
    // A mismatch rolls the entire consume back, including the matching row.
    assert!(storage.get_token(&kid, &first).await.is_ok());
    storage.delete_subject(&kid, &subject).await.unwrap();
    assert!(crate::error::is_not_found(
        storage
            .get_subject(&kid, &subject)
            .await
            .err()
            .unwrap()
            .as_ref()
    ));
    assert_eq!(
        storage
            .get_token(&kid, &first)
            .await
            .unwrap()
            .subject
            .as_deref(),
        Some(subject.as_str())
    );
    storage.save_subject(&row).await.unwrap();
    storage.delete_subject(&kid, &subject).await.unwrap();
    storage
        .consume_tokens_batch_for_subject(&kid, &[first], Some(&subject))
        .await
        .unwrap();
    storage.consume_token(&kid, &second).await.unwrap();
}

#[tokio::test]
async fn sqlite_subject_contract_and_legacy_migration() {
    struct TestDir(std::path::PathBuf);
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let dir = TestDir(std::env::temp_dir().join(format!(
        "vectis-subjects-{}",
        hex::encode(crate::core::crypto::random_bytes(16).unwrap())
    )));
    std::fs::create_dir(&dir.0).unwrap();
    let path = dir.0.join("subjects.db");
    let pool = SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true),
    )
    .await
    .unwrap();
    let schema = include_str!("../../db/sqlite_schema.sql");
    let legacy = schema
        .split("CREATE TABLE IF NOT EXISTS subjects")
        .next()
        .unwrap()
        .replace("    subject VARCHAR(128),\n", "");
    sqlx::raw_sql(&legacy).execute(&pool).await.unwrap();
    let kid = "a".repeat(64);
    let hashid = "f".repeat(64);
    sqlx::query("INSERT INTO tokens (kid, hashid, data) VALUES (?, ?, ?)")
        .bind(&kid)
        .bind(&hashid)
        .bind(ENVELOPE)
        .execute(&pool)
        .await
        .unwrap();
    assert!(sqlite::SqliteStorage::new(&path).await.is_err());
    sqlx::raw_sql(include_str!("../../db/migrations/sqlite_subject_keys.sql"))
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let db = sqlite::SqliteStorage::new(&path).await.unwrap();
    let legacy = db.get_token(&kid, &hashid).await.unwrap();
    assert_eq!(legacy.data, ENVELOPE);
    assert!(legacy.subject.is_none());
    // Corrupt seeds can still be administratively removed without decoding.
    let subject = "0".repeat(64);
    let row = SubjectRow {
        kid: kid.clone(),
        subject: subject.clone(),
        seed: "corrupt".to_owned(),
    };
    db.save_subject(&row).await.unwrap();
    let storage = StorageState {
        backend: StorageBackend::Sqlite(db),
    };
    assert!(matches!(
        storage
            .get_subject(&kid, &subject)
            .await
            .err()
            .unwrap()
            .downcast_ref(),
        Some(crate::error::VectisError::Internal(_))
    ));
    storage.delete_subject(&kid, &subject).await.unwrap();
    contract(storage).await;
}

#[tokio::test]
#[ignore = "requires VECTIS_TEST_POSTGRES_DSN and migrated Vectis schema in a disposable database"]
async fn postgres_subject_contract() {
    let dsn = std::env::var("VECTIS_TEST_POSTGRES_DSN").unwrap();
    let db = postgres::PostgresStorage::new(&dsn).await.unwrap();
    contract(StorageState {
        backend: StorageBackend::Postgres(db),
    })
    .await;
}
