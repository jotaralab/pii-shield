/// Valid 38 Indonesian BPS / Kemendagri province codes:
/// 11-19 (Sumatra), 21 (Kep. Riau), 31-36 (Java), 51-53 (Bali/Nusa Tenggara),
/// 61-65 (Kalimantan), 71-76 (Sulawesi), 81-82 (Maluku), 91-96 (Papua).
pub const VALID_INDONESIAN_PROVINCES: [u8; 38] = [
    11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 31, 32, 33, 34, 35, 36, 51, 52, 53, 61, 62, 63, 64, 65,
    71, 72, 73, 74, 75, 76, 81, 82, 91, 92, 93, 94, 95, 96,
];

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

/// Validates an Indonesian 16-digit NIK (Nomor Induk Kependudukan).
/// Checks:
/// - Exact 16 ASCII digits (trimmed slice)
/// - Valid province code matching one of the 38 Kemendagri/BPS codes
/// - Non-zero regency/city (digits 2..4) and district (digits 4..6)
/// - Valid calendar date with leap-year awareness and female +40 day offset
/// - Non-zero serial number (digits 12..16 != "0000")
#[inline]
pub fn validate_indonesian_nik(input: &str) -> bool {
    let trimmed = input.trim();
    let bytes = trimmed.as_bytes();
    if bytes.len() != 16 || !bytes.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }

    // Province code (digits 0..2)
    let prov = (bytes[0] - b'0') * 10 + (bytes[1] - b'0');
    if VALID_INDONESIAN_PROVINCES.binary_search(&prov).is_err() {
        return false;
    }

    // Regency/City (digits 2..4) and District (digits 4..6) must not be 00
    let city = (bytes[2] - b'0') * 10 + (bytes[3] - b'0');
    let dist = (bytes[4] - b'0') * 10 + (bytes[5] - b'0');
    if city == 0 || dist == 0 {
        return false;
    }

    // Date of birth DDMMYY (digits 6..12); females have DD + 40
    let raw_day = (bytes[6] - b'0') * 10 + (bytes[7] - b'0');
    let day = if raw_day > 40 { raw_day - 40 } else { raw_day };
    let month = (bytes[8] - b'0') * 10 + (bytes[9] - b'0');
    let year = (bytes[10] - b'0') * 10 + (bytes[11] - b'0');

    if !(1..=12).contains(&month) {
        return false;
    }

    let max_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            // NIK YY represents either 19YY or 20YY. A 2-digit year YY is a leap year if YY % 4 == 0.
            if year.is_multiple_of(4) {
                29
            } else {
                28
            }
        }
        _ => return false,
    };

    if day < 1 || day > max_days {
        return false;
    }

    // Serial number (digits 12..16) cannot be 0000
    let serial = &bytes[12..16];
    serial != b"0000"
}

/// Validates an Indonesian NPWP (Nomor Pokok Wajib Pajak).
/// Supports:
/// - 15-digit unformatted (`012345678123000`)
/// - 16-digit unformatted (`0012345678123000` under PMK 112/2022 NITKU)
/// - Formatted (`01.234.567.8-123.000`)
///
/// Enforces:
/// - Valid taxpayer category prefix (01..=09)
/// - Non-zero 6-digit taxpayer serial
/// - Valid KPP office code (001..=999)
/// - Valid branch code (000..=099)
#[inline]
pub fn validate_indonesian_npwp(input: &str) -> bool {
    let trimmed = input.trim();
    let mut digits = [0u8; 16];
    let mut count = 0usize;

    for &b in trimmed.as_bytes() {
        if b == b'.' || b == b'-' {
            continue;
        }
        if !b.is_ascii_digit() {
            return false;
        }
        if count < 16 {
            digits[count] = b - b'0';
        }
        count += 1;
    }

    if count != 15 && count != 16 {
        return false;
    }

    // Offset for 16-digit format with leading 0
    let offset = if count == 16 {
        // If 16 digits, first digit is typically 0, and digits 1..3 form the 01-09 category
        if digits[0] == 0 {
            1
        } else {
            0
        }
    } else {
        0
    };

    let cat = digits[offset] * 10 + digits[offset + 1];
    if !(1..=9).contains(&cat) {
        return false;
    }

    // Taxpayer serial (digits 2..8)
    let serial_sum: u32 = digits[offset + 2..offset + 8]
        .iter()
        .map(|&d| d as u32)
        .sum();
    if serial_sum == 0 {
        return false;
    }

    // KPP code (digits 9..12)
    let kpp = digits[offset + 9] as u32 * 100
        + digits[offset + 10] as u32 * 10
        + digits[offset + 11] as u32;
    if kpp == 0 {
        return false;
    }

    // Branch code (digits 12..15)
    let branch = digits[offset + 12] as u32 * 100
        + digits[offset + 13] as u32 * 10
        + digits[offset + 14] as u32;
    if branch > 999 {
        return false;
    }

    true
}

/// Validates Indonesian mobile and landline phone numbers.
/// Supports:
/// - Mobile: `+628xx`, `628xx`, `08xx` with allocated cellular prefixes (Telkomsel, Indosat, XL, Smartfren, Tri)
/// - Landline: Area codes `021`, `022`, `024`, `031`, `0341`, `061`, `0274`, `0361`, etc.
#[inline]
pub fn validate_indonesian_phone(input: &str) -> bool {
    let trimmed = input.trim();
    let bytes = trimmed.as_bytes();
    if bytes.is_empty() {
        return false;
    }

    let mut digits = [0u8; 16];
    let mut count = 0usize;

    for &b in bytes {
        if b == b'+' || b == b'-' || b == b' ' {
            continue;
        }
        if !b.is_ascii_digit() {
            return false;
        }
        if count < 16 {
            digits[count] = b - b'0';
        }
        count += 1;
    }

    if !(9..=15).contains(&count) {
        return false;
    }

    // Normalize prefix: convert 62 -> 0, or keep 0
    let (start_idx, has_zero) = if count >= 10 && digits[0] == 6 && digits[1] == 2 {
        (2, true)
    } else if digits[0] == 0 {
        (1, true)
    } else {
        (0, false)
    };

    if !has_zero || start_idx >= count {
        return false;
    }

    let remaining_len = count - start_idx;

    // Mobile: starts with 8 (from 08xx)
    if digits[start_idx] == 8 {
        if !(9..=12).contains(&remaining_len) {
            return false;
        }
        let pfx2 = digits[start_idx + 1];
        let pfx3 = digits[start_idx + 2];
        let _pfx = pfx2 * 10 + pfx3;
        // Valid Indonesian mobile prefixes (81x, 82x, 83x, 85x, 87x, 88x, 89x)
        match pfx2 {
            1 => (1..=9).contains(&pfx3),
            2 => (1..=3).contains(&pfx3),
            3 => (1..=3).contains(&pfx3) || pfx3 == 8,
            5 => (1..=3).contains(&pfx3) || (5..=9).contains(&pfx3),
            7 => pfx3 == 7 || pfx3 == 8,
            8 => (1..=9).contains(&pfx3),
            9 => (5..=9).contains(&pfx3),
            _ => false,
        }
    } else {
        // Landline: area codes like 21, 22, 24, 31, 341, 61, 274, 361, etc.
        if !(7..=10).contains(&remaining_len) {
            return false;
        }
        let a1 = digits[start_idx];
        let a2 = digits[start_idx + 1];
        let area2 = a1 * 10 + a2;
        matches!(area2, 21 | 22 | 24 | 31 | 61 | 71 | 75 | 77)
            || a1 == 2
            || a1 == 3
            || a1 == 4
            || a1 == 5
            || a1 == 9
    }
}

/// Validates US Social Security Number (SSN).
/// - 9 digits
/// - Area number (first 3 digits) != 000, 666, and not in 900..=999
/// - Group number (middle 2 digits) != 00
/// - Serial number (last 4 digits) != 0000
#[inline]
pub fn validate_us_ssn(input: &str) -> bool {
    let trimmed = input.trim();
    let mut digits = [0u8; 9];
    let mut count = 0usize;

    for &b in trimmed.as_bytes() {
        if b == b'-' || b == b' ' {
            continue;
        }
        if !b.is_ascii_digit() {
            return false;
        }
        if count < 9 {
            digits[count] = b - b'0';
        }
        count += 1;
    }

    if count != 9 {
        return false;
    }

    let area = digits[0] as u32 * 100 + digits[1] as u32 * 10 + digits[2] as u32;
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }

    let group = digits[3] as u32 * 10 + digits[4] as u32;
    if group == 0 {
        return false;
    }

    let serial =
        digits[5] as u32 * 1000 + digits[6] as u32 * 100 + digits[7] as u32 * 10 + digits[8] as u32;
    if serial == 0 {
        return false;
    }

    true
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

/// Validates Singapore NRIC / FIN checksum.
/// Prefix: S, T, F, G, M followed by 7 digits and a check letter.
#[inline]
pub fn validate_sg_nric(input: &str) -> bool {
    let trimmed = input.trim();
    let bytes = trimmed.as_bytes();
    if bytes.len() != 9 {
        return false;
    }

    let pfx = bytes[0].to_ascii_uppercase();
    if !matches!(pfx, b'S' | b'T' | b'F' | b'G' | b'M') {
        return false;
    }

    let check_char = bytes[8].to_ascii_uppercase();
    let weights = [2, 7, 6, 5, 4, 3, 2];
    let mut sum = match pfx {
        b'T' => 4,
        b'G' => 4,
        b'M' => 3,
        _ => 0,
    };

    for i in 0..7 {
        let b = bytes[i + 1];
        if !b.is_ascii_digit() {
            return false;
        }
        sum += (b - b'0') as u32 * weights[i];
    }

    let rem = (sum % 11) as usize;
    let expected = match pfx {
        b'S' | b'T' => b"JZIHGFEDCBA"[rem],
        b'F' | b'G' => b"XWUTRQPNMLK"[rem],
        b'M' => b"XWUTRQPNJLH"[rem],
        _ => return false,
    };

    check_char == expected
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

/// Checks whether a validator name is recognized by the built-in registry.
pub fn is_known_validator(name: &str) -> bool {
    matches!(
        name,
        "" | "none"
            | "luhn"
            | "id_nik"
            | "id_npwp"
            | "id_phone"
            | "us_ssn"
            | "iban_mod97"
            | "sg_nric"
            | "e164_phone"
    )
}

/// Dispatches a validator by its string name registered in TOML catalogs.
/// Returns true if the validator passes, or if `validator` is "none" or empty.
/// Unknown validator names return false.
#[inline]
pub fn validate_by_name(validator: &str, slice: &str) -> bool {
    match validator {
        "" | "none" => true,
        "luhn" => validate_luhn(slice),
        "id_nik" => validate_indonesian_nik(slice),
        "id_npwp" => validate_indonesian_npwp(slice),
        "id_phone" => validate_indonesian_phone(slice),
        "us_ssn" => validate_us_ssn(slice),
        "iban_mod97" => validate_iban_mod97(slice),
        "sg_nric" => validate_sg_nric(slice),
        "e164_phone" => validate_e164_phone(slice),
        _ => false,
    }
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
        // Leap year Feb 29 (1996)
        assert!(validate_indonesian_nik("3573012902960001"));
        // Non-leap year Feb 29 (1995) must fail
        assert!(!validate_indonesian_nik("3573012902950001"));
        // Feb 31 must fail
        assert!(!validate_indonesian_nik("3573013102950001"));
        // Invalid province 00
        assert!(!validate_indonesian_nik("0073012203950001"));
        // Unassigned province 20
        assert!(!validate_indonesian_nik("2073012203950001"));
        // Invalid serial 0000
        assert!(!validate_indonesian_nik("3573012203950000"));
    }

    #[test]
    fn test_luhn() {
        assert!(validate_luhn("4532015112830366"));
        assert!(validate_luhn("4532-0151-1283-0366"));
        assert!(!validate_luhn("4532015112830367"));
        // Consecutive hyphens must fail
        assert!(!validate_luhn("4532--0151-1283-0366"));
        // Leading/trailing hyphens must fail
        assert!(!validate_luhn("-4532015112830366-"));
    }

    #[test]
    fn test_npwp() {
        assert!(validate_indonesian_npwp("01.234.567.8-123.000"));
        assert!(validate_indonesian_npwp("012345678123000"));
        // 16-digit PMK 112/2022
        assert!(validate_indonesian_npwp("0012345678123000"));
        // Invalid category 00 or 99
        assert!(!validate_indonesian_npwp("00.234.567.8-123.000"));
        assert!(!validate_indonesian_npwp("99.234.567.8-123.000"));
    }

    #[test]
    fn test_phone_indonesia() {
        assert!(validate_indonesian_phone("081234567890"));
        assert!(validate_indonesian_phone("+6281234567890"));
        assert!(validate_indonesian_phone("6285212345678"));
        assert!(validate_indonesian_phone("021-5551234"));
        assert!(!validate_indonesian_phone("080012345678"));
        assert!(!validate_indonesian_phone("01123456789"));
    }

    #[test]
    fn test_us_ssn() {
        assert!(validate_us_ssn("123-45-6789"));
        assert!(validate_us_ssn("123456789"));
        assert!(!validate_us_ssn("000-12-3456")); // 000 area
        assert!(!validate_us_ssn("666-12-3456")); // 666 area
        assert!(!validate_us_ssn("900-12-3456")); // 900+ area
        assert!(!validate_us_ssn("123-00-6789")); // 00 group
        assert!(!validate_us_ssn("123-45-0000")); // 0000 serial
    }

    #[test]
    fn test_iban() {
        assert!(validate_iban_mod97("DE89370400440532013000"));
        assert!(!validate_iban_mod97("DE89370400440532013001"));
    }

    #[test]
    fn test_sg_nric() {
        assert!(validate_sg_nric("S1234567D"));
        assert!(!validate_sg_nric("S1234567A"));
    }

    #[test]
    fn test_validate_by_name() {
        assert!(validate_by_name("none", "anything"));
        assert!(validate_by_name("id_nik", "3573012203950001"));
        assert!(!validate_by_name("id_nik", "0073012203950001"));
        assert!(!validate_by_name("unknown_val", "foo"));
    }
}
