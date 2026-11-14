/// Validates US Social Security Number (SSN).
/// - Exactly 9 contiguous digits, OR `XXX-XX-XXXX` / `XXX XX XXXX` where both
///   separators are the SAME character anchored at positions 3 and 6 only
///   (no `"1-2-3-..."` mosaics or doubled separators)
/// - Area number (first 3 digits) != 000, 666, and not in 900..=999
/// - Group number (middle 2 digits) != 00
/// - Serial number (last 4 digits) != 0000
#[inline]
pub fn validate_us_ssn(input: &str) -> bool {
    let b = input.as_bytes();
    if b.len() != 9 && b.len() != 11 {
        return false;
    }
    if b.len() == 11 && (b[3] != b[6] || (b[3] != b'-' && b[3] != b' ')) {
        return false;
    }

    let mut digits = [0u8; 9];
    let mut n = 0usize;
    for (i, &c) in b.iter().enumerate() {
        if b.len() == 11 && (i == 3 || i == 6) {
            continue;
        }
        if !c.is_ascii_digit() {
            return false;
        }
        if n < 9 {
            digits[n] = c - b'0';
        }
        n += 1;
    }
    if n != 9 {
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

    serial != 0
}

/// Validates an Individual Taxpayer Identification Number (ITIN).
/// - Exactly 9 contiguous digits, OR `9XX-XX-XXXX` / `9XX XX XXXX` where both
///   separators are the SAME character anchored at positions 3 and 6 only
///   (no `"9-1-1-"` mosaics, no mixed `"911-70 1234"` styles)
/// - Must start with digit `9` (mathematically disjoint from `us_ssn`, which
///   rejects the 900..=999 area range)
/// - 4th and 5th digits (group) must be 50..=65, 70..=88, 90..=92 or 94..=99
/// - Last 4 digits (serial) must not be 0000
#[inline]
pub fn validate_us_itin(input: &str) -> bool {
    let b = input.as_bytes();
    if b.len() != 9 && b.len() != 11 {
        return false;
    }
    if b.len() == 11 && (b[3] != b[6] || (b[3] != b'-' && b[3] != b' ')) {
        return false;
    }

    let mut digits = [0u8; 9];
    let mut n = 0usize;
    for (i, &c) in b.iter().enumerate() {
        if b.len() == 11 && (i == 3 || i == 6) {
            continue;
        }
        if !c.is_ascii_digit() {
            return false;
        }
        if n < 9 {
            digits[n] = c - b'0';
        }
        n += 1;
    }
    if n != 9 || digits[0] != 9 {
        return false;
    }
    let group = digits[3] * 10 + digits[4];
    if !(50..=65).contains(&group)
        && !(70..=88).contains(&group)
        && !(90..=92).contains(&group)
        && !(94..=99).contains(&group)
    {
        return false;
    }
    if digits[5..9] == [0, 0, 0, 0] {
        return false;
    }
    true
}

/// Validates a 9-digit ABA routing number (ABA transit number).
/// - 9 contiguous digits (no separators of any kind)
/// - Federal Reserve prefix must be 01..=12, 21..=32, 61..=72 or 80
/// - Checksum: `(3*(d0+d3+d6) + 7*(d1+d4+d7) + (d2+d5+d8)) % 10 == 0`
#[inline]
pub fn validate_us_aba_routing(input: &str) -> bool {
    let b = input.as_bytes();
    if b.len() != 9 || !b.iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let d = [
        b[0] - b'0',
        b[1] - b'0',
        b[2] - b'0',
        b[3] - b'0',
        b[4] - b'0',
        b[5] - b'0',
        b[6] - b'0',
        b[7] - b'0',
        b[8] - b'0',
    ];
    let fed = d[0] * 10 + d[1];
    if !(1..=12).contains(&fed)
        && !(21..=32).contains(&fed)
        && !(61..=72).contains(&fed)
        && fed != 80
    {
        return false;
    }
    let digitsum = 3 * ((d[0] + d[3] + d[6]) as u32)
        + 7 * ((d[1] + d[4] + d[7]) as u32)
        + (d[2] + d[5] + d[8]) as u32;
    digitsum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_us_ssn() {
        assert!(validate_us_ssn("123-45-6789"));
        assert!(validate_us_ssn("123 45 6789"));
        assert!(validate_us_ssn("123456789"));
        // Positional separator mosaics and mixed/doubled separators rejected
        assert!(!validate_us_ssn("1-2-3-4-5-6-7-8-9"));
        assert!(!validate_us_ssn("123--45--6789"));
        assert!(!validate_us_ssn("1 23-45 6789"));
        assert!(!validate_us_ssn(" 123456789"));
        assert!(!validate_us_ssn("000-12-3456"));
        assert!(!validate_us_ssn("666-12-3456"));
        assert!(!validate_us_ssn("900-12-3456"));
        assert!(!validate_us_ssn("123-00-6789"));
        assert!(!validate_us_ssn("123-45-0000"));
    }

    #[test]
    fn test_us_itin() {
        assert!(validate_us_itin("911-70-1234"));
        assert!(validate_us_itin("911 72 1000"));
        assert!(validate_us_itin("911701234"));
        // SSN area range (starts with 8) fails ITIN
        assert!(!validate_us_itin("811-70-1234"));
        // Out-of-range group 49
        assert!(!validate_us_itin("911-49-1234"));
        // Serial 0000
        assert!(!validate_us_itin("911-50-0000"));
        // Consecutive separators / asymmetric placement / positional mosaics
        assert!(!validate_us_itin("911--70-1234"));
        assert!(!validate_us_itin("9-1-1-7-0-1-2-3-4"));
        assert!(!validate_us_itin("8.3.5.0.3.0.5.6.8"));
        // Full-validation echo of the mosaic with matched separator counts
        assert!(!validate_us_itin(" 911-70-1234"));
        assert!(!validate_us_itin("911-70-1234-"));
    }

    #[test]
    fn test_us_aba_routing() {
        assert!(validate_us_aba_routing("121000248"));
        // 02 = Fed prefix 2 (01..=12) + correct mod-10 checksum
        assert!(validate_us_aba_routing("021000021"));
        // Fed prefix 83 out of range
        assert!(!validate_us_aba_routing("835030568"));
        // Bad checksum
        assert!(!validate_us_aba_routing("121000249"));
        // Hyphens are not part of the ABA space (contiguous digits only)
        assert!(!validate_us_aba_routing("12100002-8"));
        assert!(!validate_us_aba_routing(" 121000248"));
        // Trailing separator
        assert!(!validate_us_aba_routing("121000248 "));
    }
}
