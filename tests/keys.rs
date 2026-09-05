use eri::SigningKeys;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Claims {
    iss: String,
    aud: String,
    sub: String,
    exp: usize,
}

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/keys")
        .join(name)
}
fn copy_key(dir: &TempDir, name: &str) {
    let target = dir.path().join(name);
    fs::copy(fixture(name), &target).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(target, fs::Permissions::from_mode(0o600)).unwrap();
    }
}
fn manifest(active: &str, previous: &[&str], next: &[&str]) -> (TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    for name in [
        "active-private.pem",
        "active-public.pem",
        "previous-private.pem",
        "previous-public.pem",
        "next-private.pem",
        "next-public.pem",
    ] {
        copy_key(&dir, name);
    }
    let private = format!("{active}-private.pem");
    let public = format!("{active}-public.pem");
    let previous: Vec<_> = previous
        .iter()
        .map(|name| serde_json::json!({"kid": *name, "public_key": format!("{name}-public.pem")}))
        .collect();
    let next: Vec<_> = next
        .iter()
        .map(|name| serde_json::json!({"kid": *name, "public_key": format!("{name}-public.pem")}))
        .collect();
    fs::write(dir.path().join("manifest.json"), serde_json::to_vec_pretty(&serde_json::json!({"active":{"kid":active,"private_key":private,"public_key":public},"previous":previous,"next":next})).unwrap()).unwrap();
    let path = dir.path().join("manifest.json");
    (dir, path)
}
fn claims(issuer: &str, audience: &str, offset: i64) -> Claims {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    Claims {
        iss: issuer.into(),
        aud: audience.into(),
        sub: "user-1".into(),
        exp: (now + offset) as usize,
    }
}

fn encode_with(
    dir: &TempDir,
    key_name: &str,
    header: &jsonwebtoken::Header,
    claims: &impl Serialize,
) -> String {
    let encoding = jsonwebtoken::EncodingKey::from_rsa_pem(
        &fs::read(dir.path().join(format!("{key_name}-private.pem"))).unwrap(),
    )
    .unwrap();
    jsonwebtoken::encode(header, claims, &encoding).unwrap()
}

#[test]
fn signs_and_strictly_verifies_claims() {
    let (dir, path) = manifest("active", &[], &[]);
    let keys = SigningKeys::load(&path).unwrap();
    let token = keys
        .sign(&claims("https://issuer.example", "api", 300))
        .unwrap();
    let decoded: Claims = keys
        .verify(&token, "https://issuer.example", "api")
        .unwrap();
    assert_eq!(decoded.sub, "user-1");
    assert!(
        keys.verify::<Claims>(&token, "https://other.example", "api")
            .is_err()
    );
    assert!(
        keys.verify::<Claims>(&token, "https://issuer.example", "other")
            .is_err()
    );
    let expired = keys
        .sign(&claims("https://issuer.example", "api", -120))
        .unwrap();
    assert!(
        keys.verify::<Claims>(&expired, "https://issuer.example", "api")
            .is_err()
    );
    let within_skew = keys
        .sign(&claims("https://issuer.example", "api", -20))
        .unwrap();
    assert!(
        keys.verify::<Claims>(&within_skew, "https://issuer.example", "api")
            .is_ok()
    );
    let beyond_configured_skew = keys
        .sign(&claims("https://issuer.example", "api", -40))
        .unwrap();
    assert!(
        keys.verify::<Claims>(&beyond_configured_skew, "https://issuer.example", "api")
            .is_err()
    );
    let mut wrong_type = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    wrong_type.kid = Some("active".into());
    wrong_type.typ = Some("JWT".into());
    let wrong_type_token = encode_with(
        &dir,
        "active",
        &wrong_type,
        &claims("https://issuer.example", "api", 300),
    );
    assert!(
        keys.verify::<Claims>(&wrong_type_token, "https://issuer.example", "api")
            .is_err()
    );
}

#[test]
fn independently_rejects_invalid_signature_header_and_required_claims() {
    let (dir, path) = manifest("active", &[], &[]);
    let keys = SigningKeys::load(&path).unwrap();
    let valid_claims = serde_json::json!({"iss":"https://issuer.example","aud":"api","sub":"user-1","exp":claims("", "", 300).exp});
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("active".into());
    header.typ = Some("at+jwt".into());

    let wrong_key = encode_with(&dir, "next", &header, &valid_claims);
    assert!(
        keys.verify::<serde_json::Value>(&wrong_key, "https://issuer.example", "api")
            .is_err()
    );

    let valid = encode_with(&dir, "active", &header, &valid_claims);
    let mut parts: Vec<String> = valid.split('.').map(str::to_owned).collect();
    let replacement = if parts[2].starts_with('A') { "B" } else { "A" };
    parts[2].replace_range(..1, replacement);
    let tampered = parts.join(".");
    assert!(
        keys.verify::<serde_json::Value>(&tampered, "https://issuer.example", "api")
            .is_err()
    );

    let mut missing_kid = header.clone();
    missing_kid.kid = None;
    let token = encode_with(&dir, "active", &missing_kid, &valid_claims);
    assert!(
        keys.verify::<serde_json::Value>(&token, "https://issuer.example", "api")
            .is_err()
    );
    let mut unknown_kid = header.clone();
    unknown_kid.kid = Some("unknown".into());
    let token = encode_with(&dir, "active", &unknown_kid, &valid_claims);
    assert!(
        keys.verify::<serde_json::Value>(&token, "https://issuer.example", "api")
            .is_err()
    );

    let mut wrong_alg = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::PS256);
    wrong_alg.kid = Some("active".into());
    wrong_alg.typ = Some("at+jwt".into());
    let token = encode_with(&dir, "active", &wrong_alg, &valid_claims);
    assert!(
        keys.verify::<serde_json::Value>(&token, "https://issuer.example", "api")
            .is_err()
    );

    for missing in ["exp", "iss", "aud"] {
        let mut incomplete = valid_claims.clone();
        incomplete.as_object_mut().unwrap().remove(missing);
        let token = encode_with(&dir, "active", &header, &incomplete);
        assert!(
            keys.verify::<serde_json::Value>(&token, "https://issuer.example", "api")
                .is_err(),
            "accepted token missing {missing}"
        );
    }
}

#[test]
fn rotation_publishes_overlap_and_verifies_previous_key() {
    let (_old_dir, old_path) = manifest("active", &[], &["next"]);
    let old = SigningKeys::load(&old_path).unwrap();
    let token = old
        .sign(&claims("https://issuer.example", "api", 300))
        .unwrap();
    let (_new_dir, new_path) = manifest("next", &["active"], &[]);
    let new = SigningKeys::load(&new_path).unwrap();
    assert_eq!(new.active_kid(), "next");
    assert!(new.jwks_json().contains("active"));
    assert!(
        new.verify::<Claims>(&token, "https://issuer.example", "api")
            .is_ok()
    );
    let (_without_old_dir, without_old_path) = manifest("next", &[], &[]);
    let without_old = SigningKeys::load(&without_old_path).unwrap();
    assert!(
        without_old
            .verify::<Claims>(&token, "https://issuer.example", "api")
            .is_err()
    );
}

#[test]
fn rejects_duplicate_kid_and_mismatched_active_pair() {
    let (_dir, path) = manifest("active", &["active"], &[]);
    assert!(SigningKeys::load(&path).is_err());
    let (dir, path) = manifest("active", &[], &[]);
    fs::copy(
        fixture("next-public.pem"),
        dir.path().join("active-public.pem"),
    )
    .unwrap();
    assert!(SigningKeys::load(&path).is_err());
}

#[test]
fn rejects_missing_and_malformed_public_keys() {
    let (dir, path) = manifest("active", &[], &[]);
    fs::remove_file(dir.path().join("active-public.pem")).unwrap();
    assert!(SigningKeys::load(&path).is_err());
    let (dir, path) = manifest("active", &[], &[]);
    fs::write(dir.path().join("active-public.pem"), "not a PEM key").unwrap();
    assert!(SigningKeys::load(&path).is_err());
}

#[cfg(unix)]
#[test]
fn rejects_private_key_with_broad_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, path) = manifest("active", &[], &[]);
    fs::set_permissions(
        dir.path().join("active-private.pem"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(SigningKeys::load(&path).is_err());
}

#[test]
fn rejects_non_regular_private_key_path() {
    let (dir, path) = manifest("active", &[], &[]);
    fs::remove_file(dir.path().join("active-private.pem")).unwrap();
    fs::create_dir(dir.path().join("active-private.pem")).unwrap();
    assert!(SigningKeys::load(&path).is_err());
}
