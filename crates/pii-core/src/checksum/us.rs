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

/// Validates an Individual Taxpayer Identification Number (ITIN).
/// - 9 digits with optional single spaces/hyphens between the 3-2-4 groups
///   (strict separator discipline)
/// - Must start with digit `9` (mathematically disjoint from `us_ssn`, which
///   rejects the 900..=999 area range)
/// - 4th and 5th digits (group) must be 50..=65, 70..=88, 90..=92 or 94..=99
/// - Last 4 digits (serial) must not be 0000
#[inline]
pub fn validate_us_itin(input: &str) -> bool {
    let Some(d) = super::common::strict_digits(input, b" -") else {
        return false;
    };
    if d.len() != 9 || d[0] != 9 {
        return false;
    }
    let group = d[3] * 10 + d[4];
    if !(50..=65).contains(&group)
        && !(70..=88).contains(&group)
        && !(90..=92).contains(&group)
        && !(94..=99).contains(&group)
    {
        return false;
    }
    if d[5] == 0 && d[6] == 0 && d[7] == 0 && d[8] == 0 {
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
    let d: Vec<u8> = b.iter().map(|c| c - b'0').collect();
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
        // Consecutive separators / leading separator
        assert!(!validate_us_itin("911--70-1234"));
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
