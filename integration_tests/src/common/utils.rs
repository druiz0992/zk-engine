use anyhow::Result;
use common::structs::Transaction;
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
