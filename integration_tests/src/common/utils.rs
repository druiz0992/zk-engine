use anyhow::Result;
use client::domain::StoredPreimageInfo;
use common::structs::Block;
use common::structs::Transaction;
use curves::pallas::PallasConfig;
use curves::vesta::VestaConfig;
use std::fs::File;
use std::io::Read;
use std::io::Write;

pub fn save_to_file(filename: &str, body: &[u8]) -> Result<()> {
    let mut file =
        File::create(filename).map_err(|e| anyhow::anyhow!("Error creating file: {}", e))?;

    // Write the binary data (the body) to the file
    file.write_all(body)
        .map_err(|e| anyhow::anyhow!("Error writing to file: {}", e))?;
    Ok(())
}

pub fn read_from_file(path: &str) -> Result<String> {
    let mut file = File::open(path).map_err(|e| anyhow::anyhow!("Error opening file: {}", e))?;

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|e| anyhow::anyhow!("Error reading file: {}", e))?;

    let utf8_str = String::from_utf8(buffer)
        .map_err(|_| anyhow::anyhow!("Error converting binary to UTF-8"))?;

    Ok(utf8_str.to_string())
}

pub fn read_transaction_from_file(path: &str) -> Result<Transaction<VestaConfig>> {
    let data = read_from_file(path)?;

    serde_json::from_str::<Transaction<VestaConfig>>(&data)
        .map_err(|_| anyhow::anyhow!("Error deserializing Transaction received by sequencer"))
}

pub fn read_preimage_from_file(path: &str) -> Result<StoredPreimageInfo<PallasConfig>> {
    let preimage = read_from_file(path)?;
    serde_json::from_str::<StoredPreimageInfo<PallasConfig>>(&preimage)
        .map_err(|_| anyhow::anyhow!("Error deserializing Preimage"))
}

pub fn read_block_from_file(path: &str) -> Result<Block<curves::vesta::Fr>> {
    let block = read_from_file(path)?;
    serde_json::from_str::<Block<curves::vesta::Fr>>(&block)
        .map_err(|_| anyhow::anyhow!("Error deserializing Block"))
}

pub fn decimal_to_hex(decimal_str: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Parse the decimal string into a BigUint
    let decimal_value = num_bigint::BigUint::parse_bytes(decimal_str.as_bytes(), 10)
        .ok_or("Failed to parse decimal string")?;
    // Convert the BigUint value to a hexadecimal string
    Ok(decimal_value.to_str_radix(16))
}
