/// Validates credit card numbers using the Luhn algorithm (mod 10).
///
/// Enforces:
/// - First and last bytes must be ASCII digits (no leading/trailing separators)
/// - Rejects consecutive spaces or hyphens (`--`, `  `)
/// - Total digits in 13..=19
/// - Mod-10 checksum sum % 10 == 0 and sum > 0
#[inline]
pub fn validate_luhn(input: &str) -> bool {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    // Must start and end on an ASCII digit
    if !bytes[0].is_ascii_digit() || !bytes[bytes.len() - 1].is_ascii_digit() {
        return false;
    }

    let mut sum = 0u32;
    let mut double = false;
    let mut digit_count = 0usize;
    let mut last_was_sep = false;

    // Scan backwards
    for &b in bytes.iter().rev() {
        if b == b' ' || b == b'-' {
            if last_was_sep {
                return false; // consecutive separators not allowed
            }
            last_was_sep = true;
            continue;
        }
        last_was_sep = false;

        if !b.is_ascii_digit() {
            return false;
        }
        let mut d = (b - b'0') as u32;
        digit_count += 1;

        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }

    (13..=19).contains(&digit_count) && sum > 0 && sum.is_multiple_of(10)
}

/// Validates International Bank Account Number (IBAN) using ISO 7064 Mod 97-10.
/// - 15..=34 alphanumeric characters
/// - Rearrange first 4 characters to end
/// - Convert letters to digits (A=10, B=11, ..., Z=35)
/// - Compute mod-97 remainder == 1
#[inline]
pub fn validate_iban_mod97(input: &str) -> bool {
    let trimmed = input.trim();
    let mut buf = [0u8; 34];
    let mut len = 0usize;

    for &b in trimmed.as_bytes() {
        if b == b' ' || b == b'-' {
            continue;
        }
        if !b.is_ascii_alphanumeric() {
            return false;
        }
        if len < 34 {
            buf[len] = b.to_ascii_uppercase();
        }
        len += 1;
    }

    if !(15..=34).contains(&len) {
        return false;
    }

    // Country code must be two ASCII letters
    if !buf[0].is_ascii_uppercase() || !buf[1].is_ascii_uppercase() {
        return false;
    }

    // Rearrange: move first 4 characters to end
    let mut rearranged = [0u8; 34];
    rearranged[..len - 4].copy_from_slice(&buf[4..len]);
    rearranged[len - 4..len].copy_from_slice(&buf[0..4]);

    // Compute mod-97 incrementally
    let mut remainder = 0u64;
    for &b in &rearranged[..len] {
        if b.is_ascii_digit() {
            remainder = (remainder * 10 + (b - b'0') as u64) % 97;
        } else if b.is_ascii_uppercase() {
            let val = (b - b'A' + 10) as u64;
            remainder = (remainder * 100 + val) % 97;
        }
    }

    remainder == 1
}

/// Generic E.164-compatible international phone validator for PHONE_US, PHONE_EU, PHONE_SG.
/// - Starts and ends on an ASCII digit (or leading `+`)
/// - Rejects consecutive hyphens/spaces
/// - 8 to 15 total digits
#[inline]
pub fn validate_e164_phone(input: &str) -> bool {
    let bytes = input.trim().as_bytes();
    if bytes.is_empty() {
        return false;
    }

    let mut digit_count = 0usize;
    let mut last_was_sep = false;

    let (start_idx, starts_digit) = if bytes[0] == b'+' {
        (1, true)
    } else if bytes[0].is_ascii_digit() {
        (0, true)
    } else {
        (0, false)
    };

    if !starts_digit || start_idx >= bytes.len() || !bytes[bytes.len() - 1].is_ascii_digit() {
        return false;
    }

    for &b in &bytes[start_idx..] {
        if b == b' ' || b == b'-' || b == b'(' || b == b')' || b == b'.' {
            if last_was_sep {
                return false;
            }
            last_was_sep = true;
            continue;
        }
        last_was_sep = false;
        if !b.is_ascii_digit() {
            return false;
        }
        digit_count += 1;
    }

    (8..=15).contains(&digit_count)
}
