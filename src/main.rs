use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use nova_kms_rust::config::Config;
use nova_kms_rust::server::app_router;
use nova_kms_rust::state::AppState;
use nova_kms_rust::sync::{node_tick, sync_tick};

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

    let bind_addr = config.bind_addr.clone();
    let state = Arc::new(RwLock::new(AppState::new(config).await));
    start_background_tasks(state.clone());
    let app = app_router(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    tracing::info!("Listening on {}", bind_addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
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

fn start_background_tasks(state: Arc<RwLock<AppState>>) {
    let node_tick_state = state.clone();
    tokio::spawn(async move {
        let _ = node_tick(&node_tick_state).await;
        loop {
            let interval = {
                let s = node_tick_state.read().await;
                s.config.kms_node_tick_seconds.max(1)
            };
            sleep(Duration::from_secs(interval)).await;
            let _ = node_tick(&node_tick_state).await;
        }
    });

    let sync_state = state;
    tokio::spawn(async move {
        loop {
            let interval = {
                let s = sync_state.read().await;
                s.config.data_sync_interval_seconds.max(1)
            };
            sleep(Duration::from_secs(interval)).await;
            let _ = sync_tick(&sync_state).await;
        }
    });
}
