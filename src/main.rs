#![allow(non_snake_case)]

use ethnum::U256;
use indicatif::{ProgressBar, ProgressStyle};
use openssl::md::Md;
use openssl::md_ctx::MdCtx;
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

const T: U256 = U256::from_words(
    0x00000002af0000000000000000000000,
    0x00000000000000000000000000000000,
);

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
    let size_total = usize::MAX;
    let num_threads = 8;
    let size_per_thread = size_total / num_threads;
    let send_delta = 16_384;

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

    let pb = ProgressBar::new(0);
    pb.set_style(
        ProgressStyle::with_template("{spinner:.red} [{elapsed_precise}] {per_sec}").unwrap(),
    );

    let (tx, rx) = mpsc::channel();
    
    for thread_idx in 0..num_threads {
        let block_clone = block_as_string.clone();
        let tx_clone = tx.clone();

        thread::spawn(move || {
            let from = thread_idx * size_per_thread;
            let to = from + size_per_thread;

            let mut ctx = MdCtx::new().unwrap();

            for nonce in from..to {
                let nonce_as_string = format!("{:064x}", nonce);
                let mut digest = [0; 32];

                ctx.digest_init(Md::sha256()).unwrap();
                ctx.digest_update(&block_clone[..nonce_idx].as_bytes())
                    .unwrap();
                ctx.digest_update(&nonce_as_string.as_bytes()).unwrap();
                ctx.digest_update(&block_clone[nonce_idx + 64..].as_bytes())
                    .unwrap();
                ctx.digest_final(&mut digest).unwrap();
                let digest_as_U256 = U256::from_be_bytes(digest);

                if digest_as_U256 < T {
                    tx_clone
                        .send(Some((digest_as_U256, nonce_as_string)))
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
                println!(
                    "Nonce found in {} s: {:064x}",
                    pb.elapsed().as_secs(),
                    digest
                );
                break;
            }
            None => {
                pb.inc(send_delta.try_into().unwrap());
            }
        }
    }
}
