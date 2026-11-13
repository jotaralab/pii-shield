use crate::vault::PiiSessionVault;

/// Stateful streaming token rehydrator for LLM Server-Sent Events (SSE).
/// Holds back partial `<TOKEN_...` chunks across token boundaries until `>` arrives.
/// Validates uppercase token alphabet immediately on `<` to flush HTML tags without buffering lag.
pub struct StreamingRehydrator {
    buffer: String,
    in_tag: bool,
}

impl Default for StreamingRehydrator {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingRehydrator {
    pub fn new() -> Self {
        Self {
            buffer: String::with_capacity(128),
            in_tag: false,
        }
    }

    pub fn push_chunk(&mut self, chunk: &str, vault: &PiiSessionVault) -> String {
        let mut output = String::with_capacity(chunk.len());

        for ch in chunk.chars() {
            if ch == '<' {
                if self.in_tag {
                    output.push_str(&self.buffer);
                    self.buffer.clear();
                }
                self.in_tag = true;
                self.buffer.push(ch);
            } else if ch == '>' && self.in_tag {
                self.buffer.push(ch);
                if !vault.rehydrate_token_into(&self.buffer, &mut output) {
                    output.push_str(&self.buffer);
                }
                self.buffer.clear();
                self.in_tag = false;
            } else if self.in_tag {
                // Validate uppercase token alphabet: A-Z, 0-9, _, :
                let is_valid_char =
                    ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_' || ch == ':';

                if !is_valid_char || self.buffer.len() > self.non_pii_buffer_cap() {
                    // Not a valid token character, immediately flush buffer + ch
                    output.push_str(&self.buffer);
                    output.push(ch);
                    self.buffer.clear();
                    self.in_tag = false;
                } else {
                    self.buffer.push(ch);
                }
            } else {
                output.push(ch);
            }
        }

        output
    }

    /// Tight cap for non-`<PII:` `<...>` sequences (HTML tags, prose like `< 5`).
    const NON_PII_BUFFER_CAP: usize = 160;
    /// Higher cap for sealed `<PII:...>` tokens, whose hex payload can exceed
    /// 160 bytes for long PII values.
    const SEALED_PII_BUFFER_CAP: usize = 2048;

    fn non_pii_buffer_cap(&self) -> usize {
        if self.buffer.starts_with("<PII:") {
            Self::SEALED_PII_BUFFER_CAP
        } else {
            Self::NON_PII_BUFFER_CAP
        }
    }

    pub fn flush(&mut self, vault: &PiiSessionVault) -> String {
        if self.buffer.is_empty() {
            return String::new();
        }
        let mut out = String::with_capacity(self.buffer.len());
        if !vault.rehydrate_token_into(&self.buffer, &mut out) {
            out.push_str(&self.buffer);
        }
        self.buffer.clear();
        self.in_tag = false;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::SecurityPolicy;

    #[test]
    fn test_streaming_split_tokens() {
        let mut vault = PiiSessionVault::new(SecurityPolicy::IndonesiaUuPdpStrict);
        let _ = vault.redact("Hubungi budi@jotaralab.com segera");

        let mut stream = StreamingRehydrator::new();
        // Simulate LLM streaming chunks where <EMAIL_1> is split across 3 SSE chunks
        let c1 = stream.push_chunk(" Dikirim ke <EM", &vault);
        let c2 = stream.push_chunk("AIL_", &vault);
        let c3 = stream.push_chunk("1> sekarang.", &vault);

        assert_eq!(
            format!("{}{}{}", c1, c2, c3),
            " Dikirim ke budi@jotaralab.com sekarang."
        );
    }

    #[test]
    fn test_streaming_html_tags_flush_immediately() {
        let vault = PiiSessionVault::new(SecurityPolicy::IndonesiaUuPdpStrict);
        let mut stream = StreamingRehydrator::new();

        // <div class="box"> has lowercase 'd', should flush immediately without lag
        let c1 = stream.push_chunk("<div ", &vault);
        assert_eq!(c1, "<div ");

        // Math: x < 5
        let c2 = stream.push_chunk("x < 5", &vault);
        assert_eq!(c2, "x < 5");
    }

    #[test]
    fn test_streaming_stateless_sealed_long_token_split() {
        let mut vault = PiiSessionVault::new(SecurityPolicy::IndonesiaUuPdpStrict);
        vault.set_stateless_mode(true);
        // >100-byte email so the sealed token far exceeds the 160-byte cap.
        let email = format!("{}@jotaralab.example.com", "a".repeat(120));
        let doc = format!("Dikirim ke {email} sekarang.");
        let redacted = vault.redact(&doc);
        assert!(redacted.contains("<PII:"));

        let mut stream = StreamingRehydrator::new();
        // Split the redacted document into ~8-byte pieces across chunks.
        let mut got = String::new();
        for chunk in redacted.chars().collect::<Vec<_>>().chunks(8) {
            got.push_str(&stream.push_chunk(&chunk.iter().collect::<String>(), &vault));
        }
        got.push_str(&stream.flush(&vault));
        assert_eq!(got, doc);
    }

    #[test]
    fn test_streaming_flush_eof() {
        let mut vault = PiiSessionVault::new(SecurityPolicy::IndonesiaUuPdpStrict);
        let _ = vault.redact("Hubungi budi@jotaralab.com");

        let mut stream = StreamingRehydrator::new();
        let c1 = stream.push_chunk("Hubungi <EMAIL_1", &vault);
        assert_eq!(c1, "Hubungi ");
        let flushed = stream.flush(&vault);
        assert_eq!(flushed, "<EMAIL_1");
    }
}
