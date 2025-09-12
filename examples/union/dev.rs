use anyhow::Result;
use bitcoin::Network;
use reqwest::blocking::Client;
use serde_json::json;
use std::env;
use std::time::Instant;
use std::{thread, time::Duration};
use tracing::info;

use crate::participants::common::get_network_prefix;

fn measure_latency(url: &str, payload: Option<serde_json::Value>) -> f64 {
    let client = Client::new();
    let start = Instant::now();

    let result = if let Some(data) = payload {
        client.post(url).json(&data).send()
    } else {
        client.get(url).send()
    };

    let elapsed = start.elapsed().as_secs_f64();

    match result {
        Ok(resp) => {
            println!("Status: {}", resp.status());
        }
        Err(err) => {
            println!("Request failed: {}", err);
        }
    }

    elapsed
}

pub fn latency(network: Network) -> Result<()> {
    let prefix = get_network_prefix(network, true)?;
    let env_var_name = &format!("{}_BITCOIN_API", prefix);

    let url = match env::var(env_var_name) {
        Ok(val) => val,
        Err(_) => {
            info!(
                "Environment variable {} not set. Defaulting to free QuikNode URL.",
                env_var_name
            );
            "https://distinguished-intensive-frost.btc-testnet.quiknode.pro/38d0f064dc8e72fe44d8a9a762d448bc64c54619/".to_string()
        }
    };

    let payload = json!({
        "jsonrpc": "2.0",
        "method": "getblockchaininfo",
        "params": [],
        "id": 1
    });

    let requests_per_second = 10.0;
    let total_requests = 60;
    let sleep_interval = Duration::from_secs_f64(1.0 / requests_per_second);
    let mut total_latency = 0.0;

    println!(
        "Measuring latency for {} requests at {} requests/second...",
        total_requests, requests_per_second
    );
    println!(
        "Total duration: {} seconds",
        total_requests as f64 / requests_per_second
    );
    println!("URL: {}", url);
    println!("Payload: {}", payload);

    for _ in 0..total_requests {
        thread::sleep(sleep_interval);
        total_latency += measure_latency(&url, Some(payload.clone()));
    }

    let average_latency = total_latency / total_requests as f64;
    println!(
        "Average latency over {} requests: {:.4} seconds",
        total_requests, average_latency
    );
    Ok(())
}
