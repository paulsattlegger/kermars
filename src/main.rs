#![allow(non_snake_case)]

use hex_literal::hex;
use indicatif::{ProgressBar, ProgressStyle};
use openssl::sha;
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    io::{self, Read},
    process,
    sync::mpsc,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Serialize, Deserialize)]
struct Block {
    T: String,
    created: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    miner: Option<String>,
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    previd: Option<String>,
    txids: Vec<String>,
    r#type: String,
}

const T: [u8; 32] = hex!("00000002af000000000000000000000000000000000000000000000000000000");

fn read_input() -> io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    handle.read_to_end(&mut buffer)?;

    Ok(buffer)
}

fn parse_block(data: &Vec<u8>) -> serde_json::Result<Block> {
    let mut block: Block = serde_json::from_slice(data)?;

    block.created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    block.miner = Some("Kermars".to_string());

    Ok(block)
}

fn main() {
    let input = read_input().unwrap_or_else(|err| {
        println!("Cannot read until EOF: {}", err);
        process::exit(1);
    });

    let mut block = parse_block(&input).unwrap_or_else(|err| {
        println!("Block invalid: {}", err);
        process::exit(1);
    });

    let block_as_string = serde_json::to_string(&block).unwrap();
    let nonce_idx = block_as_string.find(r#"nonce"#).unwrap() + 8;

    let (tx, rx) = mpsc::channel();

    let size_total = usize::MAX;
    let num_threads = thread::available_parallelism().unwrap().get();
    let size_per_thread = size_total / num_threads;
    let send_delta = 16_384;

    let pb = ProgressBar::new(0);
    pb.set_style(
        ProgressStyle::with_template("{spinner:.red} [{elapsed_precise}] {per_sec}").unwrap(),
    );

    for thread_idx in 0..num_threads {
        let block_clone = block_as_string.clone();
        let tx_clone = tx.clone();

        thread::spawn(move || {
            let from = thread_idx * size_per_thread;
            let to = from + size_per_thread;

            for nonce in from..to {
                let nonce_as_string = format!("{:064x}", nonce);

                let mut hasher = sha::Sha256::new();

                hasher.update(&block_clone[..nonce_idx].as_bytes());
                hasher.update(&nonce_as_string.as_bytes());
                hasher.update(&block_clone[nonce_idx + 64..].as_bytes());

                let digest = hasher.finish();

                if digest < T {
                    let digest_as_string = hex::encode(digest);
                    tx_clone
                        .send(Some((digest_as_string, nonce_as_string)))
                        .unwrap();
                }

                if nonce % send_delta == 0 {
                    tx_clone.send(None).unwrap();
                }
            }
        });
    }

    for received in rx {
        match received {
            Some((digest, nonce)) => {
                block.nonce = nonce;
                println!("{}", serde_json::to_string(&block).unwrap());
                println!("Nonce found in {} s: {}", pb.elapsed().as_secs(), digest);
                break;
            }
            None => {
                pb.inc(send_delta.try_into().unwrap());
            }
        }
    }
}
