// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use clap::*;
use ethers::types::Address as EthAddress;
use mysten_metrics::spawn_logged_monitored_task;
use mysten_metrics::start_prometheus_server;
use prometheus::Registry;
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use sui_bridge::{
    abi::{EthBridgeCommittee, EthSuiBridge},
    eth_client::EthClient,
    eth_syncer::EthSyncer,
};
use sui_bridge_indexer::postgres_manager::get_connection_pool;
use sui_bridge_indexer::postgres_manager::get_newest_token_transfer;
use sui_bridge_indexer::{
    config::load_config, worker::process_eth_transaction, worker::BridgeWorker,
};
use sui_data_ingestion_core::{
    DataIngestionMetrics, FileProgressStore, IndexerExecutor, ReaderOptions, WorkerPool,
};
use tokio::sync::oneshot;
use tracing::info;

#[derive(Parser, Clone, Debug)]
struct Args {
    /// Path to a yaml config
    #[clap(long, short)]
    config_path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _guard = telemetry_subscribers::TelemetryConfig::new()
        .with_env()
        .init();

    let args = Args::parse();

    // load config
    let config_path = if let Some(path) = args.config_path {
        path.join("config.yaml")
    } else {
        env::current_dir()
            .expect("Current directory is invalid.")
            .join("config.yaml")
    };

    let config = load_config(&config_path).unwrap();

    // start metrics server
    let (_exit_sender, exit_receiver) = oneshot::channel();
    let metrics = DataIngestionMetrics::new(&Registry::new());

    // Init metrics server
    let metrics_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1000);
    let registry_service = start_prometheus_server(metrics_address);
    let prometheus_registry = registry_service.default_registry();
    mysten_metrics::init_metrics(&prometheus_registry);
    info!("Metrics server started at port {}", 1000);

    // start eth client
    let provider = Arc::new(
        ethers::prelude::Provider::<ethers::providers::Http>::try_from(&config.eth_rpc_url)
            .unwrap_or_else(|_| {
                panic!(
                    "Cannot create Ethereum HTTP provider, URL: {}",
                    &config.eth_rpc_url
                )
            })
            .interval(std::time::Duration::from_millis(2000)),
    );
    let bridge_address = EthAddress::from_str(&config.eth_sui_bridge_contract_address)?;
    let sui_bridge = EthSuiBridge::new(bridge_address, provider.clone());
    let committee_address: EthAddress = sui_bridge.committee().call().await?;
    let limiter_address: EthAddress = sui_bridge.limiter().call().await?;
    let vault_address: EthAddress = sui_bridge.vault().call().await?;
    let committee = EthBridgeCommittee::new(committee_address, provider.clone());
    let config_address: EthAddress = committee.config().call().await?;

    let eth_client = Arc::new(
        EthClient::<ethers::providers::Http>::new(
            &config.eth_rpc_url,
            HashSet::from_iter(vec![
                bridge_address,
                committee_address,
                config_address,
                limiter_address,
                vault_address,
            ]),
        )
        .await?,
    );

    //
    let pg_pool = get_connection_pool(config.db_url.clone());

    let from_block = match get_newest_token_transfer(&pg_pool)? {
        Some(transfer) => transfer.block_height as u64 + 1,
        None => config.start_block,
    };

    println!("Starting from block: {}", from_block);

    let contract_addresses = HashMap::from_iter(vec![(bridge_address, from_block)]);

    let (_task_handles, eth_events_rx, _) = EthSyncer::new(eth_client, contract_addresses)
        .run()
        .await
        .expect("Failed to start eth syncer");

    let _task_handle = spawn_logged_monitored_task!(
        process_eth_transaction(eth_events_rx, provider.clone(), pg_pool),
        "indexer handler"
    );

    // start sui side
    let progress_store = FileProgressStore::new(config.progress_store_file.into());
    let mut executor = IndexerExecutor::new(progress_store, 1 /* workflow types */, metrics);
    let worker_pool = WorkerPool::new(
        BridgeWorker::new(vec![], config.db_url.clone()),
        "bridge worker".into(),
        config.concurrency as usize,
    );
    executor.register(worker_pool).await?;
    executor
        .run(
            config.checkpoints_path.into(),
            Some(config.remote_store_url),
            vec![], // optional remote store access options
            ReaderOptions::default(),
            exit_receiver,
        )
        .await?;

    Ok(())
}
