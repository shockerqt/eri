use std::{fs, process::Command};

#[test]
fn check_config_needs_no_keys_secret_or_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("eri.toml");
    fs::write(
        &path,
        "mode='production'\nissuer='https://auth.example'\nbind='127.0.0.1:18082'\n[database]\nurl_env='ERI_TEST_NONEXISTENT_DATABASE_URL'\n[signing]\nmanifest='missing-keys.json'\n",
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_eri"))
        .arg("--config")
        .arg(&path)
        .arg("--check-config")
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(result.stdout.is_empty());
    assert!(result.stderr.is_empty());
}
