pub mod handlers;

pub mod sequencer_api {
    use std::sync::Arc;

    use crate::adapters::rest_api::handlers::{sequence, transactions};
    use crate::services::{
        prover::in_mem_sequencer_prover::InMemProver,
        storage::in_mem_sequencer_storage::InMemStorage,
    };
    use crate::usecase::block::TransactionProcessor;
    use anyhow::anyhow;
    use axum::{
        http::StatusCode,
        routing::{get, post},
        Router,
    };
    use common::configuration::ApplicationSettings;
    use common::services::notifier::HttpNotifier;
    use common::structs::Block;
    use curves::{pallas::PallasConfig, vesta::VestaConfig};
    use dotenvy::dotenv;
    use tokio::sync::Mutex;
    use tracing_log::log;

    type SequencerDB = Arc<Mutex<InMemStorage>>;
    type SequencerProve =
        Arc<Mutex<InMemProver<VestaConfig, VestaConfig, PallasConfig, PallasConfig>>>;
    type SequencerNotifier = Arc<Mutex<HttpNotifier<Block<curves::vesta::Fr>>>>;
    type SequencerProcessor =
        Arc<Mutex<TransactionProcessor<PallasConfig, VestaConfig, VestaConfig>>>;

    #[derive(Clone)]
    pub struct SequencerState {
        pub state_db: SequencerDB,
        pub prover: SequencerProve,
        pub notifier: SequencerNotifier,
        pub processor: SequencerProcessor,
    }
    pub struct Application {
        port: u16,
        server: axum::serve::Serve<Router, Router>,
        #[allow(dead_code)]
        db: SequencerDB,
        #[allow(dead_code)]
        prover: SequencerProve,
        #[allow(dead_code)]
        notifier: SequencerNotifier,
    }
    impl Application {
        pub async fn build(
            db: SequencerDB,
            prover: SequencerProve,
            notifier: SequencerNotifier,
            processor: SequencerProcessor,
            configuration: ApplicationSettings,
        ) -> Result<Application, anyhow::Error> {
            let address = format!("{}:{}", configuration.host, configuration.port);
            let listener = tokio::net::TcpListener::bind(address)
                .await
                .map_err(|_| anyhow!("Unable to start application"))?;
            let port = listener.local_addr().unwrap().port();

            let server: axum::serve::Serve<Router, Router> = run_api(
                listener,
                db.clone(),
                prover.clone(),
                notifier.clone(),
                processor.clone(),
            )
            .await;
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
        sequencer_db: SequencerDB,
        sequencer_prover: SequencerProve,
        sequencer_notifier: SequencerNotifier,
        sequencer_processor: SequencerProcessor,
    ) -> axum::serve::Serve<Router, Router> {
        dotenv().ok();
        let state = SequencerState {
            state_db: sequencer_db,
            prover: sequencer_prover,
            notifier: sequencer_notifier,
            processor: sequencer_processor,
        };

        let app = Router::new()
            .route("/health", get(|| async { StatusCode::OK }))
            .route("/transactions", post(transactions::handle_tx))
            .route("/transactions", get(transactions::get_tx))
            .route("/sequence", post(sequence::make_block))
            .with_state(state);

        axum::serve(listener, app)
    }
}
