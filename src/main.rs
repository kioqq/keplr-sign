extern crate ripemd;
extern crate bech32;

use std::hash;

use bitcoin_hashes::{ripemd160, Hash};
use bech32::ToBase32;
use ethereum_types::H256;

// use hex_literal::hex;
use sha3::{Digest, Keccak256};

use libsecp256k1::{Message, RecoveryId, recover};

fn get_bech32_from_signature(signature: &str, message_bytes: &[u8]) -> Option<String> {
    // 1. Recover public key from signature and message

    let b64 = base64::decode(signature).ok()?;
    let hex_sign = hex::encode(b64);

    // let rpc_signature_to_compare = hex::encode(base64::decode(&signature.signature).unwrap());

    let mut hasher = Keccak256::default();
    hasher.update(message_bytes);
    let msg_hash = <[u8; 32]>::from(hasher.finalize());

    println!("msg_hash: {:?}, len: {}, lenb: {}", msg_hash, msg_hash.len(), message_bytes.len());
    let msg = Message::parse_slice(&msg_hash).unwrap();
    println!("msg: {:?}", msg);

    println!("hex_sign: {}", hex_sign);

    // let k = hex_sign[32..64];

    let v = H256::from_slice(hex_sign[32..64].as_bytes());

    println!("v: {:?}", v);

    println!("v[31]: {}", v[31]);

    // let bit: u8 = match v[31] {
    //     27 | 28 if v[..31] == [0; 31] => v[31] - 27,
    //     _ => {
    //         return 0u8;
    //     }
    // };

    // println!("bit: {}", bit);

    // let hash = H256::from(&input[0..32]);
    // let v = H256::from(&input[32..64]);
    // let r = H256::from(&input[64..96]);
    // let s = H256::from(&input[96..128]);

    // let bit = match v[31] {
    //     27 | 28 if v.0[..31] == [0; 31] => v[31] - 27,
    //     _ => {
    //         return Ok(vec![]);
    //     }
    // };
    
    let recovery_id = RecoveryId::parse(0).unwrap();
    println!("recovery_id: {:?}", recovery_id);

    println!("hex_sign: {}, len: {}, bytes_len: {}", hex_sign, hex_sign.len(), hex_sign.as_bytes().len());

    let bytes_sign = &hex_sign[64..128].as_bytes();

    println!("bytes_sign_len: {}", bytes_sign.len());
    let sig = libsecp256k1::Signature::parse_standard_slice(bytes_sign).unwrap();

    println!("sig: {:?}", sig);

    let recovered_pub_key = recover(&msg, &sig, &recovery_id).unwrap();

    let pub_key_bytes = recovered_pub_key.serialize();
    let sha256_hashed = sha256::digest(&pub_key_bytes);

    let ripemd160_hashed = ripemd160::Hash::from_slice(sha256_hashed.as_bytes()).unwrap();
    
    // 3. Convert the hashed public key into a Bech32 address
    // encode(prefix, ripemd160_hashed.to_base32()).ok()

    bech32::encode("haqq", ripemd160_hashed.to_base32(), bech32::Variant::Bech32).ok()
}

fn main() {
    let signature_bytes = "0TP9A23gb/dVM0PhwobPSH5xdO/0RS4f13d7pTGdc0krtldzG0QZhZB7D/wgHvOoQj9lxHuM4L8+gwf9YZkmEg==";
    let message_bytes = "hello".as_bytes();

    match get_bech32_from_signature(&signature_bytes, &message_bytes) {
        Some(address) => println!("Bech32 Address: {}", address),
        None => println!("Failed to derive address"),
    }
}
