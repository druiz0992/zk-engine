pub mod handlers;
pub mod structs;

pub mod rest_api_entry {
    use anyhow::anyhow;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tracing_log::log;

    use super::handlers::block::handle_block;
    use super::handlers::keys::create_keys;
    use super::handlers::mint::create_mint;
    use super::handlers::preimage::get_preimages;
    use super::handlers::transfer::create_transfer;

    use common::structs::Transaction;

    use axum::{
        http::StatusCode,
        response::IntoResponse,
        routing::{get, post},
        Json, Router,
    };
    use curves::{pallas::PallasConfig, vesta::VestaConfig};
    use dotenvy::dotenv;
    use serde_json::json;

    use crate::services::{
        notifier::HttpNotifier, prover::in_memory_prover::InMemProver,
        storage::in_mem_storage::InMemStorage,
    };

    use crate::configuration::ApplicationSettings;

    pub enum AppError {
        TxError,
    }
    impl IntoResponse for AppError {
        fn into_response(self) -> axum::response::Response {
            let (status, error_msg) = match self {
                AppError::TxError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal Error"),
            };
            let body = Json(json!({
                "error": error_msg,
            }));
            (status, body).into_response()
        }
    }

    // type WriteDatabase = Arc<Mutex<dyn PreimageDB<E = PallasConfig> + Send + Sync>>;
    type WriteDatabase = Arc<Mutex<InMemStorage<PallasConfig, curves::pallas::Fq>>>;

    #[derive(Clone)]
    pub struct AppState {
        pub state_db: WriteDatabase,
        pub prover: Arc<Mutex<InMemProver<PallasConfig, VestaConfig, VestaConfig>>>,
        pub notifier: Arc<Mutex<HttpNotifier<Transaction<VestaConfig>>>>,
    }

    pub struct Application {
        port: u16,
        server: axum::serve::Serve<Router, Router>,
        #[allow(dead_code)]
        db: WriteDatabase,
        #[allow(dead_code)]
        prover: Arc<Mutex<InMemProver<PallasConfig, VestaConfig, VestaConfig>>>,
        #[allow(dead_code)]
        notifier: Arc<Mutex<HttpNotifier<Transaction<VestaConfig>>>>,
    }

    impl Application {
        pub async fn build(
            db: WriteDatabase,
            prover: Arc<Mutex<InMemProver<PallasConfig, VestaConfig, VestaConfig>>>,
            notifier: Arc<Mutex<HttpNotifier<Transaction<VestaConfig>>>>,
            configuration: ApplicationSettings,
        ) -> Result<Application, anyhow::Error> {
            let address = format!("{}:{}", configuration.host, configuration.port);
            let listener = tokio::net::TcpListener::bind(address)
                .await
                .map_err(|_| anyhow!("Unable to start application"))?;
            let port = listener.local_addr().unwrap().port();

            let server: axum::serve::Serve<Router, Router> =
                run_api(listener, db.clone(), prover.clone(), notifier.clone()).await;
            log::trace!("Launching server at {}:{}", configuration.host, port);

            Ok(Application {
                server,
                port,
                db: db.clone(),
                prover: prover.clone(),
                notifier: notifier.clone(),
            })
        }

        pub fn port(&self) -> u16 {
            self.port
        }

        pub async fn run_until_stopped(self) -> Result<(), std::io::Error> {
            log::trace!("Server launched");
            self.server.await
        }
    }

    pub async fn run_api(
        listener: tokio::net::TcpListener,
        db_state: WriteDatabase,
        prover: Arc<Mutex<InMemProver<PallasConfig, VestaConfig, VestaConfig>>>,
        notifier: Arc<Mutex<HttpNotifier<Transaction<VestaConfig>>>>,
    ) -> axum::serve::Serve<Router, Router> {
        dotenv().ok();
        let app_state = AppState {
            state_db: db_state,
            prover,
            notifier,
        };
        let app = Router::new()
            .route("/health", get(|| async { StatusCode::OK }))
            .route("/mint", post(create_mint))
            .route("/keys", post(create_keys))
            .route("/transfer", post(create_transfer))
            .route("/preimages", get(get_preimages))
            .route("/block", post(handle_block))
            .with_state(app_state);

        axum::serve(listener, app)
    }

    // pub async fn get_trees(
    //     State(db): State<WriteDatabase>,
    // ) -> Result<Json<StoredPreimageInfoVector<PallasConfig>>, AppError> {
    //     let db_locked = db.lock().await;
    //     let trees: StoredPreimageInfoVector<PallasConfig> = db_locked.get_all_trees();
    //     Ok(Json(trees))
    // }
    //
    // pub async fn get_keys(
    //     State(db): State<WriteDatabase>,
    // ) -> Result<Json<Vec<User<M-Esc>>, AppError> {
    //     let db_locked = db.lock().await;
    //     let keys: Vec<FullKey<PallasConfig>> = db_locked.get_all_keys();
    //     Ok(Json(keys))
    // }
}
