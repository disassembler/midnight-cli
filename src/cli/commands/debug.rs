use anyhow::Result;
use clap::{Args, Subcommand};
use parity_scale_codec::{Compact, Decode};

#[derive(Args)]
pub struct DebugArgs {
    #[command(subcommand)]
    pub command: DebugCommands,
}

#[derive(Subcommand)]
pub enum DebugCommands {
    /// Decode and display a signing payload
    DecodePayload(DecodePayloadArgs),
}

#[derive(Args)]
pub struct DecodePayloadArgs {
    /// Hex-encoded signing payload (with or without 0x prefix)
    pub payload: String,
}

pub fn handle_debug_command(args: DebugArgs) -> Result<()> {
    match args.command {
        DebugCommands::DecodePayload(decode_args) => decode_payload(decode_args),
    }
}

fn decode_payload(args: DecodePayloadArgs) -> Result<()> {
    let payload_hex = args.payload.trim_start_matches("0x");
    let payload = hex::decode(payload_hex)?;

    println!("=== Signing Payload Decoder ===");
    println!("Total length: {} bytes", payload.len());
    println!();

    let mut cursor = 0;

    // Method (call data)
    println!("--- Method/Call Data ---");

    if cursor < payload.len() {
        println!("[{:02}] 0x{:02x} = {} - Pallet index", cursor, payload[cursor], payload[cursor]);
        cursor += 1;
    }

    if cursor < payload.len() {
        println!("[{:02}] 0x{:02x} = {} - Call index", cursor, payload[cursor], payload[cursor]);
        cursor += 1;
    }

    // For propose calls, decode the structure
    if cursor > 1 && payload[0] == 40 && payload[1] == 2 {
        // This is Council.propose
        if cursor < payload.len() {
            let threshold = decode_compact_u32(&payload, &mut cursor)?;
            println!("[{:02}] Compact({}) - Threshold", cursor - 1, threshold);
        }

        // Inner proposal call
        println!("\n--- Inner Proposal ---");
        if cursor < payload.len() {
            println!("[{:02}] 0x{:02x} = {} - Inner pallet index", cursor, payload[cursor], payload[cursor]);
            cursor += 1;
        }

        if cursor < payload.len() {
            println!("[{:02}] 0x{:02x} = {} - Inner call index", cursor, payload[cursor], payload[cursor]);
            cursor += 1;
        }

        // For System.remark_with_event (pallet 0, call 7)
        if cursor > 2 && payload[cursor - 2] == 0 && payload[cursor - 1] == 7 {
            if cursor < payload.len() {
                let string_len = decode_compact_u32(&payload, &mut cursor)? as usize;
                println!("[{:02}] Compact({}) - String length", cursor - 1, string_len);

                if cursor + string_len <= payload.len() {
                    let message = String::from_utf8_lossy(&payload[cursor..cursor + string_len]);
                    println!("[{:02}-{:02}] \"{}\" - Remark message", cursor, cursor + string_len - 1, message);
                    cursor += string_len;
                }
            }
        }

        // Proposal length
        if cursor < payload.len() {
            let prop_len = decode_compact_u32(&payload, &mut cursor)?;
            println!("[{:02}] Compact({}) - Proposal length", cursor - 1, prop_len);
        }
    }

    println!("\n--- Signing Parameters ---");

    // Era
    if cursor < payload.len() {
        println!("[{:02}] 0x{:02x} - Era", cursor, payload[cursor]);
        cursor += 1;
    }

    // Nonce
    if cursor < payload.len() {
        let nonce = decode_compact_u64(&payload, &mut cursor)?;
        println!("[{:02}] Compact({}) - Nonce", cursor - 1, nonce);
    }

    // Tip
    if cursor < payload.len() {
        let tip = decode_compact_u128(&payload, &mut cursor)?;
        println!("[{:02}] Compact({}) - Tip", cursor - 1, tip);
    }

    // Spec version
    if cursor + 4 <= payload.len() {
        let spec_version = u32::from_le_bytes([
            payload[cursor],
            payload[cursor + 1],
            payload[cursor + 2],
            payload[cursor + 3],
        ]);
        println!("[{:02}-{:02}] {} - Spec version", cursor, cursor + 3, spec_version);
        cursor += 4;
    }

    // Transaction version
    if cursor + 4 <= payload.len() {
        let tx_version = u32::from_le_bytes([
            payload[cursor],
            payload[cursor + 1],
            payload[cursor + 2],
            payload[cursor + 3],
        ]);
        println!("[{:02}-{:02}] {} - Transaction version", cursor, cursor + 3, tx_version);
        cursor += 4;
    }

    // Genesis hash
    if cursor + 32 <= payload.len() {
        let genesis_hash = hex::encode(&payload[cursor..cursor + 32]);
        println!("[{:02}-{:02}] 0x{} - Genesis hash", cursor, cursor + 31, genesis_hash);
        cursor += 32;
    }

    // Block hash
    if cursor + 32 <= payload.len() {
        let block_hash = hex::encode(&payload[cursor..cursor + 32]);
        println!("[{:02}-{:02}] 0x{} - Block hash", cursor, cursor + 31, block_hash);
        cursor += 32;
    }

    println!("\nDecoded {} of {} bytes", cursor, payload.len());

    if cursor < payload.len() {
        println!("\nRemaining {} bytes:", payload.len() - cursor);
        println!("  {:?}", &payload[cursor..]);
    }

    Ok(())
}

fn decode_compact_u32(data: &[u8], cursor: &mut usize) -> Result<u32> {
    let mut input = &data[*cursor..];
    let value = Compact::<u32>::decode(&mut input)?;
    *cursor += data.len() - input.len() - *cursor;
    Ok(value.0)
}

fn decode_compact_u64(data: &[u8], cursor: &mut usize) -> Result<u64> {
    let mut input = &data[*cursor..];
    let value = Compact::<u64>::decode(&mut input)?;
    *cursor += data.len() - input.len() - *cursor;
    Ok(value.0)
}

fn decode_compact_u128(data: &[u8], cursor: &mut usize) -> Result<u128> {
    let mut input = &data[*cursor..];
    let value = Compact::<u128>::decode(&mut input)?;
    *cursor += data.len() - input.len() - *cursor;
    Ok(value.0)
}
