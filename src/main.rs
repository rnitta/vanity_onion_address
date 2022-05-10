use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use data_encoding::{BASE32_NOPAD, BASE64};
use ed25519_dalek::{Keypair, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use rand::Rng;
use rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest, Sha256, Sha512};

const BLINDED_SECRET_KEY_LENGTH: usize = 64;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let target_string: String = args
        .get(1)
        .unwrap_or(&"".to_string())
        .to_owned()
        .to_uppercase();
    // todo: check if it is base32able
    if target_string.len() > 56 || target_string.is_empty() {
        panic!("target string has invalid length");
    }

    let is_completed = Arc::new(AtomicBool::new(false));

    let thread_count = num_cpus::get() - 1;
    println!("{} threads will spawn", thread_count);
    let (tx, rx) = mpsc::channel();
    for tc in 0..thread_count {
        let tx = mpsc::Sender::clone(&tx);
        let target_string: String = target_string.clone();
        let is_completed = Arc::clone(&is_completed);

        thread::spawn(move || {
            let loop_max: usize = 32 * 32 * 32 * 4; // 適当、自分のマシン都合
            let mut start = Instant::now();

            'a: loop {
                let seed: u64 = rand::thread_rng().gen();
                for i in 0..loop_max {
                    let keypair: Keypair =
                        Keypair::generate(&mut StdRng::seed_from_u64(seed + i as u64));
                    let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = keypair.public.to_bytes();
                    let onion_address = get_onion_address(&public_key_bytes);

                    if onion_address.starts_with(&target_string) {
                        let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = keypair.secret.to_bytes();
                        let blinded_secret_key = blind_secret_key(&secret_key_bytes);

                        let ret = template_output(&public_key_bytes, &blinded_secret_key);
                        println!("found in thread: {}", tc);

                        is_completed.store(true, Ordering::Relaxed);
                        tx.send(ret).unwrap();
                        break 'a;
                    }
                }
                if is_completed.load(Ordering::Relaxed) {
                    break 'a;
                }
                let duration = start.elapsed();
                println!(
                    "thread#{}: {}H/sec, {} Hashes calculated in {}sec.",
                    tc,
                    loop_max / duration.as_secs() as usize,
                    loop_max,
                    duration.as_secs()
                );
                start = Instant::now();
            }
        });
    }
    let received = rx.recv().unwrap();
    println!("{}", received);
}

fn blind_secret_key(secret_key_bytes: &[u8; SECRET_KEY_LENGTH]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    sha2::Digest::update(&mut hasher, secret_key_bytes);
    let mut result: [u8; 64] = hasher.finalize().into();
    result[0] &= 248;
    result[31] &= 127;
    result[31] |= 64;
    result
}

fn get_onion_address(public_key_bytes: &[u8; PUBLIC_KEY_LENGTH]) -> String {
    // CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]
    let mut hasher = Sha256::new();
    let checksum_seed: [u8; 48] = unsafe {
        std::mem::transmute((
            (
                b'.', b'o', b'n', b'i', b'o', b'n', b' ', b'c', b'h', b'e', b'c', b'k', b's', b'u',
                b'm',
            ),
            *public_key_bytes,
            3u8,
        ))
    };
    sha2::Digest::update(&mut hasher, checksum_seed);
    let full_checksum: [u8; 32] = hasher.finalize().into();

    // onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
    let address_seed: [u8; 35] = unsafe {
        std::mem::transmute((*public_key_bytes, full_checksum[0], full_checksum[1], 3u8))
    };
    BASE32_NOPAD.encode(&address_seed)
}

fn format_public_key(public_key: &[u8; PUBLIC_KEY_LENGTH]) -> Vec<u8> {
    let mut header = Vec::from("== ed25519v1-public: type0 ==\x00\x00\x00");
    header.append(&mut public_key.to_vec());
    header
}

fn format_secret_key(secret_key: &[u8; BLINDED_SECRET_KEY_LENGTH]) -> Vec<u8> {
    let mut header = Vec::from("== ed25519v1-secret: type0 ==\x00\x00\x00");
    header.append(&mut secret_key.to_vec());
    header
}

fn template_output(
    public_key_bytes: &[u8; PUBLIC_KEY_LENGTH],
    blinded_secret_key: &[u8; BLINDED_SECRET_KEY_LENGTH],
) -> String {
    let onion_address = get_onion_address(public_key_bytes).to_lowercase();
    let public_key_bytes_vec = format_public_key(public_key_bytes);
    let private_key_bytes_vec = format_secret_key(blinded_secret_key);
    format!("address: {}.onion\ncommands:\n$ echo {} | base64 -d > hs_ed25519_public_key\n$ echo {} | base64 -d > hs_ed25519_private_key",
            onion_address,
            BASE64.encode(&public_key_bytes_vec),
            BASE64.encode(&private_key_bytes_vec))
}
