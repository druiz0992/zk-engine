use anyhow::Result;
use std::fs::File;
use std::io::Read;
use std::io::Write;

pub fn save_to_file(filename: &str, body: &[u8]) -> Result<()> {
    let mut file =
        File::create(filename).map_err(|e| anyhow::anyhow!("Error creating file: {}", e))?;

    // Write the binary data (the body) to the file
    file.write_all(&body)
        .map_err(|e| anyhow::anyhow!("Error writing to file: {}", e))?;
    Ok(())
}

pub fn read_from_file(path: &str) -> Result<String> {
    // Open the file
    let mut file = File::open(path).map_err(|e| anyhow::anyhow!("Error opening file: {}", e))?;

    // Read the file content into a vector of bytes
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|e| anyhow::anyhow!("Error reading file: {}", e))?;

    // Attempt to convert the bytes into a UTF-8 string
    let utf8_str = String::from_utf8(buffer)
        .map_err(|_| anyhow::anyhow!("Error converting binary to UTF-8"))?;

    Ok(utf8_str.to_string())
}
