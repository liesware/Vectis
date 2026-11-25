use super::*;

fn ddl_with_test_generated_identifiers(sql: String) -> sqlx::RawSql {
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
}

async fn fixture() -> (PostgresStorage, String, String) {
    let dsn =
        std::env::var("VECTIS_TEST_POSTGRES_DSN").expect("disposable PostgreSQL DSN required");
    let db = PostgresStorage::new(&dsn).await.unwrap();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let kid = format!("purge_{nonce}");
    db.save_ops_keys(&kid, "keys-v1", "properties-v1")
        .await
        .unwrap();
    sqlx::query("INSERT INTO tokens(kid, hashid, data) VALUES ($1, 'token', 'synthetic')")
        .bind(&kid)
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO subjects VALUES ($1, 'subject', 'synthetic')")
        .bind(&kid)
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO indexes VALUES ($1, 'digest')")
        .bind(&kid)
        .execute(&db.pool)
        .await
        .unwrap();
    (db, kid, dsn)
}

async fn counts(db: &PostgresStorage, kid: &str) -> super::super::KeyPurgeCounts {
    let mut found = Vec::new();
    for sql in [
        "SELECT COUNT(*) FROM opskeys WHERE kid = $1",
        "SELECT COUNT(*) FROM tokens WHERE kid = $1",
        "SELECT COUNT(*) FROM subjects WHERE kid = $1",
        "SELECT COUNT(*) FROM indexes WHERE kid = $1",
    ] {
        found.push(
            sqlx::query_scalar::<_, i64>(sql)
                .bind(kid)
                .fetch_one(&db.pool)
                .await
                .unwrap() as u64,
        );
    }
    super::super::KeyPurgeCounts {
        opskeys: found[0],
        tokens: found[1],
        subjects: found[2],
        indexes: found[3],
    }
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL database with Vectis schema"]
async fn postgres_purge_counts_cas_isolation_and_concurrency() {
    let (db, kid, _) = fixture().await;
    let (_other_db, other, _) = fixture().await;
    let expected = counts(&db, &kid).await;
    for (keys, properties) in [("changed", "properties-v1"), ("keys-v1", "changed")] {
        assert!(
            db.purge_ops_key(&kid, keys, properties)
                .await
                .unwrap_err()
                .to_string()
                .contains("changed since")
        );
        assert_eq!(counts(&db, &kid).await, expected);
    }
    let (first, second) = tokio::join!(
        db.purge_ops_key(&kid, "keys-v1", "properties-v1"),
        db.purge_ops_key(&kid, "keys-v1", "properties-v1")
    );
    assert_ne!(first.is_ok(), second.is_ok());
    assert_eq!(first.or(second).unwrap(), expected);
    assert_eq!(counts(&db, &kid).await, Default::default());
    assert_eq!(db.get_ops_keys(&other).await.unwrap().keys, "keys-v1");
    assert_eq!(counts(&db, &other).await, expected);
    assert!(crate::error::is_not_found(
        db.purge_ops_key(&kid, "keys-v1", "properties-v1")
            .await
            .unwrap_err()
            .as_ref()
    ));
    db.purge_ops_key(&other, "keys-v1", "properties-v1")
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL database with Vectis schema"]
async fn postgres_purge_intermediate_error_rolls_back() {
    let (db, kid, _) = fixture().await;
    let expected = counts(&db, &kid).await;
    let name = format!("fail_{kid}");
    let sql = format!(
        "CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic failure'; END $$; CREATE TRIGGER {name} BEFORE DELETE ON indexes FOR EACH ROW WHEN (OLD.kid = '{kid}') EXECUTE FUNCTION {name}();"
    );
    ddl_with_test_generated_identifiers(sql)
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(
        db.purge_ops_key(&kid, "keys-v1", "properties-v1")
            .await
            .unwrap_err()
            .to_string()
            .contains("before COMMIT")
    );
    assert_eq!(counts(&db, &kid).await, expected);
    ddl_with_test_generated_identifiers(format!(
        "DROP TRIGGER {name} ON indexes; DROP FUNCTION {name}();"
    ))
    .execute(&db.pool)
    .await
    .unwrap();
    db.purge_ops_key(&kid, "keys-v1", "properties-v1")
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL database and CREATEROLE"]
async fn postgres_purge_missing_delete_privilege_rolls_back() {
    use std::str::FromStr;
    let (db, kid, dsn) = fixture().await;
    let expected = counts(&db, &kid).await;
    let role = format!("limited_{kid}");
    ddl_with_test_generated_identifiers(format!("CREATE ROLE {role} LOGIN; GRANT USAGE ON SCHEMA public TO {role}; GRANT SELECT ON opskeys,tokens,subjects,indexes TO {role}; GRANT UPDATE(properties) ON opskeys TO {role}; GRANT DELETE ON opskeys,tokens,subjects TO {role};"))
        .execute(&db.pool).await.unwrap();
    let options = sqlx::postgres::PgConnectOptions::from_str(&dsn)
        .unwrap()
        .username(&role);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let limited = PostgresStorage {
        pool,
        dsn_context: "<test database>".into(),
    };
    assert!(
        limited
            .purge_ops_key(&kid, "keys-v1", "properties-v1")
            .await
            .unwrap_err()
            .to_string()
            .contains("before COMMIT")
    );
    assert_eq!(counts(&db, &kid).await, expected);
    limited.pool.close().await;
    ddl_with_test_generated_identifiers(format!("REVOKE ALL ON opskeys,tokens,subjects,indexes FROM {role}; REVOKE UPDATE(properties) ON opskeys FROM {role}; REVOKE ALL ON SCHEMA public FROM {role}; DROP ROLE {role};"))
        .execute(&db.pool).await.unwrap();
    db.purge_ops_key(&kid, "keys-v1", "properties-v1")
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL database with Vectis schema"]
async fn postgres_purge_held_lock_times_out_without_deleting() {
    let (db, kid, _) = fixture().await;
    let expected = counts(&db, &kid).await;
    let mut holder = db.pool.begin().await.unwrap();
    sqlx::query("SELECT kid FROM opskeys WHERE kid = $1 FOR UPDATE")
        .bind(&kid)
        .fetch_one(&mut *holder)
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let error = db
        .purge_ops_key(&kid, "keys-v1", "properties-v1")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("before COMMIT"));
    assert!(started.elapsed() < std::time::Duration::from_secs(30));
    holder.rollback().await.unwrap();
    assert_eq!(counts(&db, &kid).await, expected);
    db.purge_ops_key(&kid, "keys-v1", "properties-v1")
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires an owned disposable PostgreSQL database with Vectis schema"]
async fn postgres_purge_commit_disconnect_is_explicitly_uncertain() {
    let (db, kid, _) = fixture().await;
    let expected = counts(&db, &kid).await;
    let name = format!("disconnect_{kid}");
    ddl_with_test_generated_identifiers(format!("CREATE FUNCTION {name}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_terminate_backend(pg_backend_pid()); RETURN OLD; END $$; CREATE CONSTRAINT TRIGGER {name} AFTER DELETE ON opskeys DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (OLD.kid = '{kid}') EXECUTE FUNCTION {name}();"))
        .execute(&db.pool).await.unwrap();
    let error = db
        .purge_ops_key(&kid, "keys-v1", "properties-v1")
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("outcome is unknown after COMMIT")
    );
    assert_eq!(counts(&db, &kid).await, expected);
    ddl_with_test_generated_identifiers(format!(
        "DROP TRIGGER {name} ON opskeys; DROP FUNCTION {name}();"
    ))
    .execute(&db.pool)
    .await
    .unwrap();
    db.purge_ops_key(&kid, "keys-v1", "properties-v1")
        .await
        .unwrap();
}
