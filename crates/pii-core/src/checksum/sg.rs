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
