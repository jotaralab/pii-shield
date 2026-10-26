use pii_core::{PiiSessionVault, SecurityPolicy, ToolTrustLevel};
use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut vault = PiiSessionVault::new(SecurityPolicy::IndonesiaUuPdpStrict);

    for line in stdin.lock().lines() {
        let Ok(payload) = line else { break };
        if payload.trim().is_empty() {
            continue;
        }

        // If message is an outbound tool call, rehydrate arguments; otherwise scrub tool output
        let processed = if payload.contains(r#""method":"tools/call""#) {
            vault
                .rehydrate_for_tool(&payload, ToolTrustLevel::InternalTrusted)
                .unwrap_or_else(|_| payload.clone())
        } else {
            vault.redact(&payload)
        };

        let _ = writeln!(stdout, "{}", processed);
        let _ = stdout.flush();
    }
}
