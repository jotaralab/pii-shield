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
