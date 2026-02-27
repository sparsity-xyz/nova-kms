use std::sync::Arc;
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tracing::info; // Added for tracing::info! macro
use std::net::SocketAddr; // Added as per instruction
use std::str::FromStr; // Added as per instruction

use nova_kms_rust::config::Config;
use nova_kms_rust::state::AppState;
use nova_kms_rust::server::app_router; // Added for server::app_router

#[tokio::main]
async fn main() {
    let config = Config::load().unwrap_or_else(|err| {
        eprintln!("Failed to load configuration: {}", err);
        std::process::exit(1);
    });

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| format!("nova_kms_rust={}", config.log_level.to_lowercase()).into());

    if config.in_enclave {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    tracing::info!("Starting nova-kms-rust");
    tracing::debug!("Loaded Config: {:?}", config);

    let state = Arc::new(RwLock::new(AppState::new(config)));
    let app = server::app_router(state);

    // Bind to 0.0.0.0:8000
    let addr = "0.0.0.0:8000";
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("Listening on {}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("Shutting down signal received, initiating graceful shutdown");
}
