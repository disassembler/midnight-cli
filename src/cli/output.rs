use crate::domain::{KeyInfo, KeyMaterial};
use serde::{Deserialize, Serialize};
use serde_json;

/// Output format options
#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Json,
    Text,
}

impl OutputFormat {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "text" => Ok(Self::Text),
            _ => Err(format!("Unknown format: {}", s)),
        }
    }
}

/// Simple key output for display
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyOutput {
    pub purpose: String,
    pub key_type: String,
    pub public_key: String,
    pub ss58_address: Option<String>,
    pub derivation_path: Option<String>,
}

impl From<&KeyMaterial> for KeyOutput {
    fn from(key: &KeyMaterial) -> Self {
        Self {
            purpose: key.purpose.as_str().to_string(),
            key_type: key.key_type.as_str().to_string(),
            public_key: format!("0x{}", hex::encode(&key.public_key)),
            ss58_address: key.metadata.ss58_address.clone(),
            derivation_path: key.derivation_path.clone(),
        }
    }
}

pub fn print_key_output(key: &KeyMaterial, format: OutputFormat) {
    let output = KeyOutput::from(key);

    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        OutputFormat::Text => {
            println!("Purpose: {}", output.purpose);
            println!("Key Type: {}", output.key_type);
            println!("Public Key: {}", output.public_key);
            if let Some(addr) = &output.ss58_address {
                println!("SS58 Address: {}", addr);
            }
            if let Some(path) = &output.derivation_path {
                println!("Derivation Path: {}", path);
            }
        }
    }
}
