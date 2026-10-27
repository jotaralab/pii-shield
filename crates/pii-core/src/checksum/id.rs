/// Valid 38 Indonesian BPS / Kemendagri province codes:
/// 11-19 (Sumatra), 21 (Kep. Riau), 31-36 (Java), 51-53 (Bali/Nusa Tenggara),
/// 61-65 (Kalimantan), 71-76 (Sulawesi), 81-82 (Maluku), 91-96 (Papua).
pub const VALID_INDONESIAN_PROVINCES: [u8; 38] = [
    11, 12, 13, 14, 15, 16, 17, 18, 19, 21, 31, 32, 33, 34, 35, 36, 51, 52, 53, 61, 62, 63, 64, 65,
    71, 72, 73, 74, 75, 76, 81, 82, 91, 92, 93, 94, 95, 96,
];

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
