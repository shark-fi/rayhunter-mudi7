//! Read-only local capture validation. Never prints cell/subscriber data or modifies reports.
use rayhunter::analysis::analyzer::{AnalyzerConfig, Harness};
use rayhunter::gsmtap::parser;
use rayhunter::qmdl::QmdlMessageReader;
use std::collections::BTreeMap;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("Provide a QMDL file")?;
    let mut reader = QmdlMessageReader::new(tokio::fs::File::open(path).await?).await?;
    let config = AnalyzerConfig {
        test_analyzer: true,
        ..AnalyzerConfig::default()
    };
    let mut harness = Harness::new_with_config(&config);
    let mut counts = BTreeMap::<String, usize>::new();
    while let Some(message) = reader.get_next_message().await? {
        let nas_shape = match &message {
            Ok(rayhunter::diag::Message::Log {
                body: rayhunter::diag::diaglog::LogBody::Nas4GMessage { msg, .. },
                ..
            }) if !msg.is_empty() => {
                let esm_type = if msg[0] & 15 == 2 {
                    msg.get(2).map_or(String::new(), |kind| {
                        format!(", ESM message type 0x{kind:02x}")
                    })
                } else {
                    String::new()
                };
                Some(format!(
                    "NAS protocol {}, security nibble {}, payload length {}{esm_type}",
                    msg[0] & 15,
                    msg[0] >> 4,
                    msg.len()
                ))
            }
            _ => None,
        };
        let channel = match &message {
            Ok(msg) => match parser::parse(msg.clone()) {
                Ok(Some((_, packet))) => format!("{:?}", packet.header.gsmtap_type),
                Ok(None) => "Unanalyzed DIAG response".into(),
                Err(_) => "GSMTAP parsing failure".into(),
            },
            Err(_) => "DIAG parsing failure".into(),
        };
        let row = harness.analyze_qmdl_message(message);
        let status = if let Some(reason) = row.skipped_message_reason {
            if reason.contains("CHOICE Additions not supported") {
                "unsupported ASN.1 CHOICE extension"
            } else if reason.contains("EncryptedNASMessage") {
                "encrypted NAS"
            } else if reason.contains("ID 7445 not found") {
                "unknown vendor log 0x1d15"
            } else if reason.contains("NASDecodingError") {
                "NAS decoding failure"
            } else if reason.contains("RRCDecodingError") {
                "RRC decoding failure"
            } else {
                "other parsing failure"
            }
        } else {
            "decoded"
        };
        *counts.entry(format!("{channel} / {status}")).or_default() += 1;
        if status == "NAS decoding failure" {
            if let Some(shape) = nas_shape {
                *counts.entry(shape).or_default() += 1;
            }
        }
        for (index, event) in row.events.iter().enumerate() {
            if let Some(event) = event {
                *counts
                    .entry(format!("Analyzer index {index} / {:?}", event.event_type))
                    .or_default() += 1;
            }
        }
    }
    if harness.finish_qmdl_analysis().is_some() {
        *counts
            .entry("Incomplete RRC assemblies at capture boundary".into())
            .or_default() += 1;
    }
    println!("{}", serde_json::to_string_pretty(&counts)?);
    Ok(())
}
