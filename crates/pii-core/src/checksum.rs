/// Validates credit card numbers using the Luhn algorithm (mod 10).
#[inline]
pub fn validate_luhn(input: &str) -> bool {
    let mut sum = 0u32;
    let mut double = false;
    let mut digit_count = 0usize;

    for b in input.bytes().rev() {
        if b == b' ' || b == b'-' {
            continue;
        }
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

    (13..=19).contains(&digit_count) && sum > 0 && sum % 10 == 0
}

/// Validates an Indonesian 16-digit NIK (Nomor Induk Kependudukan).
/// Checks province prefix, DDMMYY structure (supports +40 female day offset), and non-zero serial.
#[inline]
pub fn validate_indonesian_nik(input: &str) -> bool {
    let bytes = input.as_bytes();
    if bytes.len() != 16 || !bytes.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }

    // Province code (digits 0..2): valid BPS codes range from 11 (Aceh) to 96 (Papua Barat Daya)
    let prov = (bytes[0] - b'0') * 10 + (bytes[1] - b'0');
    if !(11..=96).contains(&prov) {
        return false;
    }

    // Regency/City code (digits 2..4) and District code (digits 4..6) must not be 00
    let city = (bytes[2] - b'0') * 10 + (bytes[3] - b'0');
    let dist = (bytes[4] - b'0') * 10 + (bytes[5] - b'0');
    if city == 0 || dist == 0 {
        return false;
    }

    // Date of birth DDMMYY (digits 6..12); females have DD + 40
    let raw_day = (bytes[6] - b'0') * 10 + (bytes[7] - b'0');
    let day = if raw_day > 40 { raw_day - 40 } else { raw_day };
    let month = (bytes[8] - b'0') * 10 + (bytes[9] - b'0');

    if !(1..=31).contains(&day) || !(1..=12).contains(&month) {
        return false;
    }

    // Serial number (digits 12..16) cannot be 0000
    let serial = &bytes[12..16];
    serial != b"0000"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_nik() {
        // Malang (3573), Kecamatan Blimbing (01), DOB 22-03-95, Serial 0001
        assert!(validate_indonesian_nik("3573012203950001"));
        // Female DOB (+40 -> 62-03-95)
        assert!(validate_indonesian_nik("3573016203950002"));
        // Invalid province 00
        assert!(!validate_indonesian_nik("0073012203950001"));
        // Invalid serial 0000
        assert!(!validate_indonesian_nik("3573012203950000"));
    }

    #[test]
    fn test_luhn() {
        assert!(validate_luhn("4532015112830366"));
        assert!(validate_luhn("4532-0151-1283-0366"));
        assert!(!validate_luhn("4532015112830367"));
    }
}
