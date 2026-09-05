use clap::Parser;
use eri::{AppState, Config, Database, SigningKeys, router};
use tokio::net::TcpListener;

#[derive(Parser)]
struct Args {
    /// Path to the TOML configuration file.
    #[arg(long, env = "ERI_CONFIG")]
    config: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = Config::load(&args.config)?;
    let keys = SigningKeys::load(&config.signing.manifest)?;
    let database = Database::connect(&config.database).await?;
    database.migrate().await?;
    let listener = TcpListener::bind(config.bind).await?;
    let app = router(AppState::new(config, database, keys)?);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
}
