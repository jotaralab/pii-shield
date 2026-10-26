use crate::vault::PiiSessionVault;

/// Stateful streaming token rehydrator for LLM Server-Sent Events (SSE).
/// Holds back partial `<TOKEN_...` chunks across token boundaries until `>` arrives.
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
            buffer: String::with_capacity(64),
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
                let hydrated = vault.rehydrate(&self.buffer);
                output.push_str(&hydrated);
                self.buffer.clear();
                self.in_tag = false;
            } else if self.in_tag {
                self.buffer.push(ch);
                // Guard against non-placeholder '<' symbols
                if self.buffer.len() > 24 || ch.is_whitespace() {
                    output.push_str(&self.buffer);
                    self.buffer.clear();
                    self.in_tag = false;
                }
            } else {
                output.push(ch);
            }
        }

        output
    }

    pub fn flush(&mut self, vault: &PiiSessionVault) -> String {
        if self.buffer.is_empty() {
            return String::new();
        }
        let hydrated = vault.rehydrate(&self.buffer);
        self.buffer.clear();
        self.in_tag = false;
        hydrated
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

        assert_eq!(format!("{}{}{}", c1, c2, c3), " Dikirim ke budi@jotaralab.com sekarang.");
    }
}
