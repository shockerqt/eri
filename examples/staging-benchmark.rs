//! Staging-only internal latency diagnostic; never starts a listener or migrates.
use anyhow::{Context, ensure};
use axum::{body::Body, http::Request};
use eri::{AppState, Config, Database, SigningKeys, config::Mode, router};
use serde_json::{Value, json};
use std::{path::Path, time::Instant};
use tower::ServiceExt;
use uuid::Uuid;

const CONFIG: &str = "/etc/eri-staging/config.toml";
const MANIFEST: &str = "/etc/eri-staging/keys/manifest.json";
const ISSUER: &str = "https://auth-staging.shocker.cl";
const USERINFO: &str = "https://auth-staging.shocker.cl/userinfo";
const DEADLINE_SECONDS: u64 = 120;

fn source_sha() -> anyhow::Result<String> {
    let executable = std::env::current_exe()?.canonicalize()?;
    let path = executable.parent().context("marker")?.join("SOURCE_SHA");
    ensure!(std::fs::metadata(&path)?.len() <= 41, "marker");
    let marker = std::fs::read_to_string(path)?;
    let sha = marker.strip_suffix('\n').unwrap_or(&marker);
    ensure!(
        sha.len() == 40
            && sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "marker"
    );
    Ok(sha.to_owned())
}

fn preflight() -> anyhow::Result<Config> {
    ensure!(
        Path::new(CONFIG).canonicalize()? == Path::new(CONFIG),
        "config"
    );
    let config = Config::load(Path::new(CONFIG))?;
    ensure!(
        config.mode == Mode::Production && config.issuer.as_str() == format!("{ISSUER}/"),
        "config"
    );
    ensure!(config.bind.to_string() == "127.0.0.1:8092", "config");
    ensure!(
        config.signing.manifest == Path::new(MANIFEST)
            && Path::new(MANIFEST).canonicalize()? == Path::new(MANIFEST),
        "manifest"
    );
    ensure!(
        config
            .authorization
            .as_ref()
            .is_some_and(|a| a.google.is_some()),
        "provider"
    );
    ensure!(
        config.database.url.is_none() && config.database.url_env == "ERI_DATABASE_URL",
        "database"
    );
    let url = url::Url::parse(&std::env::var("ERI_DATABASE_URL")?)?;
    ensure!(
        matches!(url.scheme(), "postgres" | "postgresql"),
        "database"
    );
    ensure!(
        url.username() == "eri_staging" && url.path() == "/eri_staging",
        "database"
    );
    ensure!(
        matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "::1")),
        "database"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "database"
    );
    Ok(config)
}

fn stats(mut samples: Vec<u64>) -> Value {
    samples.sort_unstable();
    let percentile = |p: usize| samples[(samples.len() * p).div_ceil(100) - 1];
    json!({"samples": samples.len(), "p50_ns": percentile(50), "p95_ns": percentile(95), "p99_ns": percentile(99)})
}

async fn discovery(app: axum::Router) -> anyhow::Result<u64> {
    let request = Request::builder()
        .uri("/.well-known/openid-configuration")
        .body(Body::empty())?;
    let start = Instant::now();
    let response = app.oneshot(request).await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 65536).await?;
    let elapsed_ns = u64::try_from(start.elapsed().as_nanos())?;
    // Reject a bad response, but exclude JSON validation from dispatch/body time.
    ensure!(status == 200, "discovery");
    let metadata: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        metadata["issuer"] == ISSUER && metadata["userinfo_endpoint"] == USERINFO,
        "discovery"
    );
    ensure!(
        metadata["authorization_response_iss_parameter_supported"] == true,
        "discovery"
    );
    ensure!(
        metadata["code_challenge_methods_supported"]
            .as_array()
            .is_some_and(|v| v.iter().any(|m| m == "S256")),
        "discovery"
    );
    Ok(elapsed_ns)
}

async fn run(samples: usize, warmup: usize) -> anyhow::Result<Value> {
    let source = source_sha()?;
    let config = preflight()?; // DB/role safety precedes keys and pool setup.
    let keys = SigningKeys::load(&config.signing.manifest)?;
    let verification = SigningKeys::load(&config.signing.manifest)?;
    let now = chrono::Utc::now().timestamp();
    let token = keys.sign(
        &json!({"iss": ISSUER, "aud": [USERINFO], "sub": Uuid::new_v4(), "iat": now,
        "exp": now + 300, "client_id": "eri-staging-cli", "scope": "openid"}),
    )?;
    let database = Database::connect(&config.database).await?;
    let app = router(AppState::new(config, database, keys)?);
    // Setup and signing are outside the timing window. One global deadline covers
    // both warmup and measurement phases; no sample failure is discarded.
    let window_start = Instant::now();
    let measured = async {
        for _ in 0..warmup {
            ensure!(
                window_start.elapsed().as_secs() < DEADLINE_SECONDS,
                "deadline"
            );
            discovery(app.clone()).await?;
            let _: Value = verification.verify(&token, ISSUER, USERINFO)?;
        }
        let mut discovery_ns = Vec::with_capacity(samples);
        for _ in 0..samples {
            ensure!(
                window_start.elapsed().as_secs() < DEADLINE_SECONDS,
                "deadline"
            );
            let cloned = app.clone();
            discovery_ns.push(discovery(cloned).await?);
        }
        let mut verification_ns = Vec::with_capacity(samples);
        for _ in 0..samples {
            ensure!(
                window_start.elapsed().as_secs() < DEADLINE_SECONDS,
                "deadline"
            );
            let start = Instant::now();
            let _: Value = verification.verify(&token, ISSUER, USERINFO)?;
            verification_ns.push(u64::try_from(start.elapsed().as_nanos())?);
            // Synchronous RSA work must yield so the total deadline is polled.
            tokio::task::yield_now().await;
        }
        Ok::<_, anyhow::Error>(
            json!({"diagnostic": "eri-staging-benchmark", "result": "pass", "source_sha": source,
            "concurrency": 1, "warmup_per_phase": warmup, "deadline_seconds_after_setup": DEADLINE_SECONDS,
            "discovery": {"scope": "in_process_router_dispatch_and_complete_body_excludes_metadata_validation", "statistics": stats(discovery_ns)},
            "verification": {"scope": "cached_signingkeys_verify_including_kid_lookup_jose_claims_and_json_excludes_http_jwks_fetch_network", "statistics": stats(verification_ns)}}),
        )
    };
    tokio::time::timeout(std::time::Duration::from_secs(DEADLINE_SECONDS), measured).await?
}

fn arguments() -> anyhow::Result<Option<(usize, usize)>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!(
            "Usage: eri-benchmark [--samples 10000] [--warmup 1000]\nStaging only: /etc/eri-staging/config.toml; no network listener or mutations."
        );
        return Ok(None);
    }
    let mut samples = 10000;
    let mut warmup = 1000;
    let mut seen = std::collections::HashSet::new();
    for pair in args.chunks(2) {
        ensure!(pair.len() == 2 && seen.insert(pair[0].clone()), "arguments");
        let value: usize = pair[1].parse()?;
        match pair[0].as_str() {
            "--samples" => samples = value,
            "--warmup" => warmup = value,
            _ => anyhow::bail!("arguments"),
        }
    }
    ensure!(
        (100..=100000).contains(&samples) && (100..=10000).contains(&warmup),
        "arguments"
    );
    Ok(Some((samples, warmup)))
}

#[tokio::main]
async fn main() {
    let result = async {
        if let Some((samples, warmup)) = arguments()? {
            // Setup (including potentially blocking key reads) has a separate
            // outer safety bound; the unit's RuntimeMaxSec also bounds execution.
            let summary =
                tokio::time::timeout(std::time::Duration::from_secs(180), run(samples, warmup))
                    .await??;
            println!("{summary}");
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if result.is_err() {
        eprintln!("FAIL staging benchmark");
        std::process::exit(1);
    }
}
