// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use clap::*;
use fastcrypto::encoding::{Base64, Encoding};
use fastcrypto::secp256k1::{Secp256k1KeyPair, Secp256k1PrivateKey};
use fastcrypto::traits::{EncodeDecodeBase64, KeyPair, ToFromBytes};
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::StructTag;
use shared_crypto::intent::Intent;
use shared_crypto::intent::IntentMessage;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use sui_bridge::client::bridge_authority_aggregator::BridgeAuthorityAggregator;
use sui_bridge::config::BridgeNodeConfig;
use sui_bridge::crypto::{BridgeAuthorityPublicKeyBytes, BridgeAuthoritySignInfo};
use sui_bridge::eth_transaction_builder::build_eth_transaction;
use sui_bridge::sui_client::{SuiBridgeClient, SuiClient};
use sui_bridge::sui_transaction_builder::build_sui_transaction;
use sui_bridge::tools::{
    make_action, select_contract_address, Args, BridgeCliConfig, BridgeValidatorCommand,
};
use sui_bridge::types::{AddTokensOnSuiAction, BridgeAction};
use sui_bridge::utils::{
    generate_bridge_authority_key_and_write_to_file, generate_bridge_client_key_and_write_to_file,
    generate_bridge_node_config_and_write_to_file,
};
use sui_config::{Config, NodeConfig};
use sui_json_rpc_types::SuiTransactionBlockResponseOptions;
use sui_json_rpc_types::{ObjectChange, SuiTransactionBlockEffectsAPI};
use sui_move_build::BuildConfig;
use sui_sdk::{SuiClient as SuiSdkClient, SuiClientBuilder};
use sui_types::base_types::{ObjectRef, SuiAddress};
use sui_types::bridge::{BridgeChainId, BRIDGE_MODULE_NAME};
use sui_types::crypto::{Signature, SuiKeyPair};
use sui_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use sui_types::transaction::{ObjectArg, Transaction, TransactionData};
use sui_types::{parse_sui_type_tag, BRIDGE_PACKAGE_ID};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Init logging
    let (_guard, _filter_handle) = telemetry_subscribers::TelemetryConfig::new()
        .with_env()
        .init();
    let args = Args::parse();

    match args.command {
        BridgeValidatorCommand::CreateBridgeValidatorKey { path } => {
            generate_bridge_authority_key_and_write_to_file(&path)?;
            println!("Bridge validator key generated at {}", path.display());
        }
        BridgeValidatorCommand::CreateBridgeClientKey { path, use_ecdsa } => {
            generate_bridge_client_key_and_write_to_file(&path, use_ecdsa)?;
            println!("Bridge client key generated at {}", path.display());
        }
        BridgeValidatorCommand::CreateBridgeNodeConfigTemplate { path, run_client } => {
            generate_bridge_node_config_and_write_to_file(&path, run_client)?;
            println!(
                "Bridge node config template generated at {}",
                path.display()
            );
        }

        BridgeValidatorCommand::GovernanceClient {
            config_path,
            chain_id,
            cmd,
        } => {
            let chain_id = BridgeChainId::try_from(chain_id).expect("Invalid chain id");
            println!("Chain ID: {:?}", chain_id);
            let config = BridgeCliConfig::load(config_path).expect("Couldn't load BridgeCliConfig");
            let sui_client = SuiClient::<SuiSdkClient>::new(&config.sui_rpc_url).await?;

            let (sui_key, sui_address, gas_object_ref) = config
                .get_sui_account_info()
                .await
                .expect("Failed to get sui account info");
            let bridge_summary = sui_client
                .get_bridge_summary()
                .await
                .expect("Failed to get bridge summary");
            let bridge_committee = Arc::new(
                sui_client
                    .get_bridge_committee()
                    .await
                    .expect("Failed to get bridge committee"),
            );
            let agg = BridgeAuthorityAggregator::new(bridge_committee);

            // Handle Sui Side
            if chain_id.is_sui_chain() {
                let sui_chain_id = BridgeChainId::try_from(bridge_summary.chain_id).unwrap();
                assert_eq!(
                    sui_chain_id, chain_id,
                    "Chain ID mismatch, expected: {:?}, got from url: {:?}",
                    chain_id, sui_chain_id
                );
                // Create BridgeAction
                let sui_action = make_action(sui_chain_id, &cmd);
                println!("Action to execute on Sui: {:?}", sui_action);
                let threshold = sui_action.approval_threshold();
                let certified_action = agg
                    .request_committee_signatures(sui_action, threshold)
                    .await
                    .expect("Failed to request committee signatures");
                let bridge_arg = sui_client
                    .get_mutable_bridge_object_arg()
                    .await
                    .expect("Failed to get mutable bridge object arg");
                let id_token_map = sui_client.get_token_id_map().await.unwrap();
                let tx = build_sui_transaction(
                    sui_address,
                    &gas_object_ref,
                    certified_action,
                    bridge_arg,
                    &id_token_map,
                )
                .expect("Failed to build sui transaction");
                let sui_sig = Signature::new_secure(
                    &IntentMessage::new(Intent::sui_transaction(), tx.clone()),
                    &sui_key,
                );
                let tx = Transaction::from_data(tx, vec![sui_sig]);
                let resp = sui_client
                    .execute_transaction_block_with_effects(tx)
                    .await
                    .expect("Failed to execute transaction block with effects");
                if resp.status_ok().unwrap() {
                    println!("Sui Transaction succeeded: {:?}", resp.digest);
                } else {
                    println!(
                        "Sui Transaction failed: {:?}. Effects: {:?}",
                        resp.digest, resp.effects
                    );
                }
                return Ok(());
            }

            // Handle eth side
            // TODO assert chain id returned from rpc matches chain_id
            let eth_signer_client = config
                .get_eth_signer_client()
                .await
                .expect("Failed to get eth signer client");
            println!("Using Eth address: {:?}", eth_signer_client.address());
            // Create BridgeAction
            let eth_action = make_action(chain_id, &cmd);
            println!("Action to execute on Eth: {:?}", eth_action);
            // Create Eth Signer Client
            let threshold = eth_action.approval_threshold();
            let certified_action = agg
                .request_committee_signatures(eth_action, threshold)
                .await
                .expect("Failed to request committee signatures");
            let contract_address = select_contract_address(&config, &cmd);
            let tx = build_eth_transaction(contract_address, eth_signer_client, certified_action)
                .await
                .expect("Failed to build eth transaction");
            println!("sending Eth tx: {:?}", tx);
            match tx.send().await {
                Ok(tx_hash) => {
                    println!("Transaction sent with hash: {:?}", tx_hash);
                }
                Err(err) => {
                    let revert = err.as_revert();
                    println!("Transaction reverted: {:?}", revert);
                }
            };

            return Ok(());
        }
        BridgeValidatorCommand::CommitteeRegistration {
            node_config_path,
            bridge_node_config_path,
            url,
        } => {
            let node_config = NodeConfig::load(node_config_path).expect("Couldn't load NodeConfig");
            let bridge_config = BridgeNodeConfig::load(bridge_node_config_path)
                .expect("Couldn't load BridgeNodeConfig");

            // Read bridge keypair
            let key_str = fs::read_to_string(bridge_config.bridge_authority_key_path_base64_raw)?;
            let bytes = Base64::decode(key_str.trim()).unwrap();
            let key = Secp256k1PrivateKey::from_bytes(&bytes).unwrap();
            let ecdsa_keypair = Secp256k1KeyPair::from(key);

            // Read sui node account key pair
            let keypair = node_config.account_key_pair.keypair();
            let address = SuiAddress::from(&keypair.public());
            println!("Starting bridge committee registration for Sui validator: {address}, with bridge public key: {}", ecdsa_keypair.public);

            let sui_client = SuiClientBuilder::default()
                .build(&bridge_config.sui.sui_rpc_url)
                .await?;

            let bridge_client = SuiClient::new(&bridge_config.sui.sui_rpc_url).await?;
            let bridge = bridge_client
                .get_mutable_bridge_object_arg_must_succeed()
                .await;

            let coins = sui_client
                .coin_read_api()
                .get_coins(address, None, None, None)
                .await?;
            let gas = coins.data.first().unwrap().object_ref();
            let ref_gas_price = sui_client.read_api().get_reference_gas_price().await?;

            let mut ptb = ProgrammableTransactionBuilder::default();

            let bridge_arg = ptb.obj(bridge)?;
            let system_arg = ptb.obj(ObjectArg::SUI_SYSTEM_MUT)?;
            let pub_key_arg = ptb.pure(ecdsa_keypair.public().as_bytes())?;
            let url_arg = ptb.pure(url)?;
            ptb.programmable_move_call(
                BRIDGE_PACKAGE_ID,
                BRIDGE_MODULE_NAME.into(),
                Identifier::new("committee_registration").unwrap(),
                vec![],
                vec![bridge_arg, system_arg, pub_key_arg, url_arg],
            );

            let tx_data = TransactionData::new_programmable(
                address,
                vec![gas],
                ptb.finish(),
                10000000,
                ref_gas_price,
            );
            let tx = Transaction::from_data_and_signer(tx_data, vec![keypair]);
            let response = sui_client
                .quorum_driver_api()
                .execute_transaction_block(
                    tx,
                    SuiTransactionBlockResponseOptions::new().with_effects(),
                    None,
                )
                .await?;
            if response.status_ok().unwrap() {
                println!(
                    "Committee registration successful. txn digest: {}",
                    response.digest
                )
            } else {
                return Err(anyhow!(
                    "Error returned from bridge committee registration transaction: {:?}.",
                    response.effects.as_ref().map(|e| e.status())
                ));
            }
        }
    }

    Ok(())
}

#[tokio::test]
async fn publish_and_register_token() {
    // Validator keys for paying for publish gas
    let validator_keypair = "AK/iy1DcANPmv79AWeuY59oTKYI/nCjFazDJ2X9t4k1m";
    let keypair = SuiKeyPair::decode_base64(validator_keypair).unwrap();
    let address = SuiAddress::from(&keypair.public());

    let sui_client = SuiClientBuilder::default()
        .build("http://sjc-bnt-rpc-00.mystenlabs.com:9000")
        .await
        .unwrap();

    let coins = sui_client
        .coin_read_api()
        .get_coins(address, None, None, None)
        .await
        .unwrap();
    let gas = coins.data.first().unwrap().object_ref();
    let ref_gas_price = sui_client
        .read_api()
        .get_reference_gas_price()
        .await
        .unwrap();

    let compiled_package = BuildConfig::new_for_testing()
        .build(PathBuf::from("/Users/patrick/sui/bridge/move/tokens/btc"))
        .unwrap();
    let all_module_bytes = compiled_package.get_package_bytes(false);
    let dependencies = compiled_package.get_dependency_original_package_ids();

    let mut ptb = ProgrammableTransactionBuilder::default();

    let cap = ptb.publish_upgradeable(all_module_bytes, dependencies);
    ptb.transfer_arg(address, cap);

    let tx_data = TransactionData::new_programmable(
        address,
        vec![gas],
        ptb.finish(),
        100000000,
        ref_gas_price,
    );
    let tx = Transaction::from_data_and_signer(tx_data, vec![&keypair]);
    let response = sui_client
        .quorum_driver_api()
        .execute_transaction_block(
            tx,
            SuiTransactionBlockResponseOptions::new()
                .with_effects()
                .with_object_changes(),
            None,
        )
        .await
        .unwrap();

    let (metadata, _) = find_new_object(response.object_changes.as_ref(), "CoinMetadata").unwrap();
    let (tc, coin_type) = find_new_object(response.object_changes.as_ref(), "TreasuryCap").unwrap();
    let (uc, _) = find_new_object(response.object_changes.as_ref(), "UpgradeCap").unwrap();
    println!("{:?}", coin_type);
    let bridge_client = SuiClient::new("http://sjc-bnt-rpc-00.mystenlabs.com:9000")
        .await
        .unwrap();
    let bridge = bridge_client
        .get_mutable_bridge_object_arg_must_succeed()
        .await;

    let mut ptb = ProgrammableTransactionBuilder::default();
    let tc_arg = ptb.obj(ObjectArg::ImmOrOwnedObject(tc)).unwrap();
    let uc_arg = ptb.obj(ObjectArg::ImmOrOwnedObject(uc)).unwrap();
    let metadata_arg = ptb.obj(ObjectArg::ImmOrOwnedObject(metadata)).unwrap();
    let bridge_arg = ptb.obj(bridge).unwrap();

    let coins = sui_client
        .coin_read_api()
        .get_coins(address, None, None, None)
        .await
        .unwrap();
    let gas = coins.data.first().unwrap().object_ref();

    ptb.programmable_move_call(
        BRIDGE_PACKAGE_ID,
        BRIDGE_MODULE_NAME.into(),
        Identifier::new("register_foreign_token").unwrap(),
        vec![coin_type.type_params.first().unwrap().clone()],
        vec![bridge_arg, tc_arg, uc_arg, metadata_arg],
    );

    let tx_data = TransactionData::new_programmable(
        address,
        vec![gas],
        ptb.finish(),
        100000000,
        ref_gas_price,
    );
    let tx = Transaction::from_data_and_signer(tx_data, vec![&keypair]);
    let response = sui_client
        .quorum_driver_api()
        .execute_transaction_block(
            tx,
            SuiTransactionBlockResponseOptions::new().with_effects(),
            None,
        )
        .await
        .unwrap();

    println!("{:?}", response.effects.unwrap())
}

fn find_new_object(oc: Option<&Vec<ObjectChange>>, type_: &str) -> Option<(ObjectRef, StructTag)> {
    oc?.iter().find_map(|o| match o {
        ObjectChange::Created {
            object_type,
            object_id,
            version,
            digest,
            ..
        } => {
            if object_type.name.to_string() == type_ {
                Some(((*object_id, *version, *digest), object_type.clone()))
            } else {
                None
            }
        }
        _ => None,
    })
}

#[tokio::test]
async fn approve_token() {
    let committee_keys = [
        "dKSogMiIPSbuZqYz0ABL4ZlszK8AHdM4ubrWv74tXVs=",
        "TkzW82A/Vgv/SFArumQj9aMWSez2Zz3LPuIhAyt43Xg=",
        "FsTY/h/Nhc6JPAsl8NG8C7ZZ0CLqaenuAncpFMnEkLs=",
        "R/6VQ04u/MVRzEPX2CcV7/VZ6ZaK/Msirp4ADkhhpcM=",
    ]
    .iter()
    .map(|key| {
        let bytes = Base64::decode(key).unwrap();
        let key = Secp256k1PrivateKey::from_bytes(&bytes).unwrap();
        Secp256k1KeyPair::from(key)
    })
    .collect::<Vec<_>>();

    // Validator keys for paying for publish gas
    let validator_keypair = "AK/iy1DcANPmv79AWeuY59oTKYI/nCjFazDJ2X9t4k1m";
    let keypair = SuiKeyPair::decode_base64(validator_keypair).unwrap();
    let address = SuiAddress::from(&keypair.public());

    let sui_client = SuiClientBuilder::default()
        .build("http://sjc-bnt-rpc-00.mystenlabs.com:9000")
        .await
        .unwrap();

    let bridge_client = SuiClient::new("http://sjc-bnt-rpc-00.mystenlabs.com:9000")
        .await
        .unwrap();
    let bridge = bridge_client
        .get_mutable_bridge_object_arg_must_succeed()
        .await;

    let coins = sui_client
        .coin_read_api()
        .get_coins(address, None, None, None)
        .await
        .unwrap();
    let gas = coins.data.first().unwrap().object_ref();
    let ref_gas_price = sui_client
        .read_api()
        .get_reference_gas_price()
        .await
        .unwrap();

    let add_token_action = BridgeAction::AddTokensOnSuiAction(AddTokensOnSuiAction {
        nonce: 1,
        chain_id: BridgeChainId::SuiLocalTest,
        native: false,
        token_ids: vec![1],
        token_type_names: vec![parse_sui_type_tag(
            "0x0dc3e4ed7806459f2078c21f054679564471be374afc293ad8c875ed867b8c51::btc::BTC",
        )
        .unwrap()],
        token_prices: vec![666200000],
    });

    let committee = bridge_client.get_bridge_committee().await.unwrap();
    //let comm = BridgeAuthorityAggregator::new(Arc::new(committee));
    let sigs = committee_keys
        .iter()
        .map(|key| {
            let sig = BridgeAuthoritySignInfo::new(&add_token_action, &key);
            let pubkey = BridgeAuthorityPublicKeyBytes::from(&key.public);
            println!("{:?}", pubkey.to_eth_address());

            sig.verify(&add_token_action, &committee).unwrap();
            sig.signature.as_bytes().to_vec()
        })
        .collect::<Vec<_>>();

    let mut ptb = ProgrammableTransactionBuilder::default();

    let bridge_arg = ptb.obj(bridge).unwrap();

    let source_chain = ptb.pure(3u8).unwrap();
    let seq_num = ptb.pure(1u64).unwrap();
    let native_token = ptb.pure(false).unwrap();
    let token_ids = ptb.pure(vec![1u8]).unwrap();
    let type_names = ptb
        .pure(vec![
            "0dc3e4ed7806459f2078c21f054679564471be374afc293ad8c875ed867b8c51::btc::BTC",
        ])
        .unwrap();
    let token_prices = ptb.pure(vec![666200000u64]).unwrap();

    let msg = ptb.programmable_move_call(
        BRIDGE_PACKAGE_ID,
        Identifier::new("message").unwrap(),
        Identifier::new("create_add_tokens_on_sui_message").unwrap(),
        vec![],
        vec![
            source_chain,
            seq_num,
            native_token,
            token_ids,
            type_names,
            token_prices,
        ],
    );

    let sigs_arg = ptb.pure(sigs).unwrap();

    ptb.programmable_move_call(
        BRIDGE_PACKAGE_ID,
        BRIDGE_MODULE_NAME.into(),
        Identifier::new("execute_system_message").unwrap(),
        vec![],
        vec![bridge_arg, msg, sigs_arg],
    );

    let tx_data = TransactionData::new_programmable(
        address,
        vec![gas],
        ptb.finish(),
        100000000,
        ref_gas_price,
    );
    let tx = Transaction::from_data_and_signer(tx_data, vec![&keypair]);
    let response = sui_client
        .quorum_driver_api()
        .execute_transaction_block(
            tx,
            SuiTransactionBlockResponseOptions::new().with_effects(),
            None,
        )
        .await
        .unwrap();

    println!("{:?}", response.effects.unwrap())
}

#[tokio::test]
async fn send_sui() {
    // Validator keys for paying for publish gas
    let validator_keypair = "AK/iy1DcANPmv79AWeuY59oTKYI/nCjFazDJ2X9t4k1m";
    let keypair = SuiKeyPair::decode_base64(validator_keypair).unwrap();
    let address = SuiAddress::from(&keypair.public());

    let sui_client = SuiClientBuilder::default()
        .build("http://sjc-bnt-rpc-00.mystenlabs.com:9000")
        .await
        .unwrap();

    let bc = SuiBridgeClient::new("http://sjc-bnt-rpc-00.mystenlabs.com:9000")
        .await
        .unwrap();

    let s = bc
        .query_events_by_module(
            BRIDGE_PACKAGE_ID,
            Identifier::from_str("bridge").unwrap(),
            None,
        )
        .await
        .unwrap();

    println!("{:?}", s);

    let coins = sui_client
        .coin_read_api()
        .get_coins(address, None, None, None)
        .await
        .unwrap();
    let gas = coins.data.first().unwrap().object_ref();
    let ref_gas_price = sui_client
        .read_api()
        .get_reference_gas_price()
        .await
        .unwrap();

    let mut ptb = ProgrammableTransactionBuilder::default();

    ptb.pay_sui(
        vec![SuiAddress::from_str(
            "0x2fd42dfdbd2eb7055a7bc7d4ce000ae53cc22f0c2f2006862bebc8df1f676027",
        )
        .unwrap()],
        vec![10_000_000_000],
    )
    .unwrap();

    let tx_data = TransactionData::new_programmable(
        address,
        vec![gas],
        ptb.finish(),
        100000000,
        ref_gas_price,
    );
    let tx = Transaction::from_data_and_signer(tx_data, vec![&keypair]);
    /*    let response = sui_client
        .quorum_driver_api()
        .execute_transaction_block(
            tx,
            SuiTransactionBlockResponseOptions::new()
                .with_effects()
                .with_object_changes(),
            None,
        )
        .await
        .unwrap();

    println!("{:?}", response.effects.unwrap())*/
}
