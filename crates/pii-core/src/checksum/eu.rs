//! GDPR-era European national identifier validators.
//!
//! Every validator enforces strict separator discipline: it rejects leading
//! and trailing separators, consecutive separators, and any character outside
//! the allowed alphabet. Separators are further restricted to their
//! conventional grouping positions (no `"9-1-1-..."` mosaics).

use super::common::strict_alnum_buf;

// ---------------------------------------------------------------------------
// DE_STEUER_ID — German Steuer-Identifikationsnummer
// ---------------------------------------------------------------------------

/// Validates the 11-digit German tax identification number (Steuer-ID).
/// - 11 digits with optional single spaces between digits
/// - First digit must not be 0
/// - First 10 digits: exactly one pair of equal digits (or one triple), and no
///   three consecutive identical digits anywhere
/// - 11th digit is the ISO 7064 Mod 11,10 check digit
#[inline]
pub fn validate_de_steuer_id(input: &str) -> bool {
    let mut buf = [0u8; 11];
    let Some(d) = parse_digits(input, b' ', &mut buf) else {
        return false;
    };
    if d.len() != 11 || d[0] == 0 {
        return false;
    }
    let d10 = &d[..10];

    // Frequency histogram constraint over the first 10 digits.
    let mut freq = [0u8; 10];
    for &x in d10 {
        freq[x as usize] += 1;
    }
    let ones = freq.iter().filter(|&&f| f == 1).count();
    let twos = freq.iter().filter(|&&f| f == 2).count();
    let threes = freq.iter().filter(|&&f| f == 3).count();
    let hist_ok =
        (ones == 8 && twos == 1 && threes == 0) || (ones == 7 && twos == 0 && threes == 1);
    if !hist_ok {
        return false;
    }

    // No three consecutive identical digits.
    if d10.windows(3).any(|w| w[0] == w[1] && w[1] == w[2]) {
        return false;
    }

    // ISO 7064 Mod 11,10: the complement is taken mod 10, so a product of 1
    // correctly yields check digit 0 instead of 10.
    let mut product = 10u32;
    for &x in d10 {
        let mut t = (product + x as u32) % 10;
        if t == 0 {
            t = 10;
        }
        product = (2 * t) % 11;
    }
    let check = (11 - product) % 10;
    check == d[10] as u32
}

// ---------------------------------------------------------------------------
// FR_NIR — French Numéro d'Inscription au Répertoire
// ---------------------------------------------------------------------------

/// Validates the 15-character French NIR (social security number).
/// - 15 alphanumeric characters after stripping single spaces/hyphens
/// - Uppercase normalized; sex digit in `1..=4 | 7 | 8`
/// - Year, month (`01..=12 | 20..=99`), commune, serial and key positions must
///   all be digits
/// - Department `2A`→19, `2B`→18 before the mod-97 key computation; domestic
///   departments reject `00` and `96`; overseas (`97`/`98`) requires 3-digit
///   department `971..=978` or `984..=988`
/// - Zero commune and zero serial blocks are rejected (INSEE never issues them)
/// - Last two digits (key, `01..=97`) satisfy `key == 97 - (nir13 mod 97)`
#[inline]
pub fn validate_fr_nir(input: &str) -> bool {
    let mut buf = [0u8; 15];
    let Some(raw) = strict_alnum_buf(input, b" -", &mut buf) else {
        return false;
    };
    if raw.len() != 15 {
        return false;
    }
    // Sex digit.
    if !matches!(raw[0], b'1'..=b'4' | b'7' | b'8') {
        return false;
    }
    // Year raw[1..3] and month raw[3..5] must both be digits.
    if !raw[1..5].iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let month = (raw[3] - b'0') * 10 + (raw[4] - b'0');
    if !((1..=12).contains(&month) || (20..=99).contains(&month)) {
        return false;
    }
    // Key must be two digits.
    if !raw[13..15].iter().all(|c| c.is_ascii_digit()) {
        return false;
    }

    // Build the pure-digit 13-digit basis for the mod-97 computation.
    if raw[5] == b'2' && (raw[6] == b'A' || raw[6] == b'B') {
        // Corse: 2A -> 19, 2B -> 18.
        if !raw[7..13].iter().all(|c| c.is_ascii_digit()) {
            return false;
        }
        // Reject zero commune/serial (positions shift: commune raw[7..10],
        // serial raw[10..13]).
        if raw[7..10] == *b"000" || raw[10..13] == *b"000" {
            return false;
        }
    } else if raw[5] == b'9' && (raw[6] == b'7' || raw[6] == b'8') {
        // Overseas DOM-TOM: 3-digit department 971..=978 or 984..=988, then a
        // 2-digit commune and a 3-digit serial.
        let third = match raw[7] {
            c @ b'0'..=b'9' => c - b'0',
            _ => return false,
        };
        let dep_ok = if raw[6] == b'7' {
            (1..=8).contains(&third)
        } else {
            (4..=8).contains(&third)
        };
        if !dep_ok {
            return false;
        }
        if !raw[8..13].iter().all(|c| c.is_ascii_digit()) {
            return false;
        }
        if raw[8..10] == *b"00" || raw[10..13] == *b"000" {
            return false;
        }
    } else {
        // Domestic: 2-digit department, 3-digit commune, 3-digit serial.
        if !raw[5].is_ascii_digit() || !raw[6].is_ascii_digit() {
            return false;
        }
        let dep = (raw[5] - b'0') * 10 + (raw[6] - b'0');
        if dep == 0 || dep == 96 {
            return false;
        }
        if !raw[7..13].iter().all(|c| c.is_ascii_digit()) {
            return false;
        }
        if raw[7..10] == *b"000" || raw[10..13] == *b"000" {
            return false;
        }
    }

    // Assemble the 13-digit basis: Corse "2A"/"2B" at positions 5..7 rewrite
    // to 19/18 (the $10^6$ subtraction), every other position is a digit.
    let mut nir13 = 0u64;
    let mut i = 0usize;
    while i < 13 {
        if i == 5 && raw[5] == b'2' && (raw[6] == b'A' || raw[6] == b'B') {
            nir13 = nir13 * 100 + if raw[6] == b'A' { 19 } else { 18 };
            i += 2;
            continue;
        }
        nir13 = nir13 * 10 + (raw[i] - b'0') as u64;
        i += 1;
    }

    if nir13 == 0 {
        return false;
    }
    let key = (raw[13] - b'0') * 10 + (raw[14] - b'0');
    (1..=97).contains(&key) && key as u64 == 97 - nir13 % 97
}

// ---------------------------------------------------------------------------
// ES_DNI / NIE — Spanish Documento Nacional de Identidad
// ---------------------------------------------------------------------------

/// Validates the 9-character Spanish DNI (or NIE starting with X/Y/Z).
/// - Optional single hyphen or space allowed only immediately before the check
///   letter (so exactly 9 or 10 characters total)
/// - First char is a digit (DNI) or `X`→0, `Y`→1, `Z`→2 (NIE)
/// - Followed by 7 digits, then the check letter from
///   `TRWAGMYFPDXBNJZSQVHLCKE[num mod 23]` (uppercase only)
#[inline]
pub fn validate_es_dni(input: &str) -> bool {
    let b = input.as_bytes();
    if b.len() != 9 && b.len() != 10 {
        return false;
    }
    // Optional separator only between the 8-doc-char body and the letter.
    let (num_part, letter) = if b.len() == 10 {
        if b[8] != b'-' && b[8] != b' ' {
            return false;
        }
        (&b[..8], b[9])
    } else {
        (&b[..8], b[8])
    };
    if !letter.is_ascii_uppercase() || !letter.is_ascii_alphabetic() {
        return false;
    }

    // First char: digit or X/Y/Z.
    let mut num: u64;
    match num_part[0] {
        c @ b'0'..=b'9' => num = (c - b'0') as u64,
        b'X' => num = 0,
        b'Y' => num = 1,
        b'Z' => num = 2,
        _ => return false,
    }
    for &c in &num_part[1..] {
        if !c.is_ascii_digit() {
            return false;
        }
        num = num * 10 + (c - b'0') as u64;
    }
    b"TRWAGMYFPDXBNJZSQVHLCKE"[(num % 23) as usize] == letter
}

// ---------------------------------------------------------------------------
// IT_CODICE_FISCALE — Italian Fiscal Code / Codice Fiscale
// ---------------------------------------------------------------------------

const IT_CONTROL_TABLE: &[u8; 36] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
// 1-based "dispari" (odd) table.
const IT_ODD: &[u8; 36] = &[
    1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6,
    8, 12, 14, 16, 10, 22, 25, 24, 23,
];
// Even ("pari") table: digits 0..=9 and letters A..Z map to 0..=25
// (D.M. 23 dicembre 1976 / Agenzia delle Entrate).
const IT_EVEN: &[u8; 36] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    19, 20, 21, 22, 23, 24, 25,
];
// Omocodia alphabetic digit substitutes.
const IT_OMOCODIA: &[&[u8]; 10] = &[b"L", b"M", b"N", b"P", b"Q", b"R", b"S", b"T", b"U", b"V"];

#[inline]
fn it_omocodia_digit(c: u8) -> Option<u8> {
    if c.is_ascii_digit() {
        return Some(c - b'0');
    }
    IT_OMOCODIA
        .iter()
        .position(|&l| l[0] == c)
        .map(|idx| idx as u8)
}

#[inline]
fn it_is_flexible_digit(c: u8) -> bool {
    c.is_ascii_digit()
        || matches!(
            c,
            b'L' | b'M' | b'N' | b'P' | b'Q' | b'R' | b'S' | b'T' | b'U' | b'V'
        )
}

/// Validates the 16-character Italian codice fiscale.
/// - Enforces all positional character classes
///   (`[A-Z]{6}[0-9LMNPQRSTUV]{2}[ABCDEHLMPRST][0-9LMNPQRSTUV]{2}[A-Z][0-9LMNPQRSTUV]{3}[A-Z]`)
/// - Birth-day part (chars 9-10) decodes omocodia letters L→0..V→9 and must be
///   in `1..=31 | 41..=71`
/// - Last character is the check char `b'A' + (sum mod 26)` where 0-based even
///   indices use the official 1-based odd table and odd indices the even table
#[inline]
pub fn validate_it_codice_fiscale(input: &str) -> bool {
    let b = input.as_bytes();
    if b.len() != 16 {
        return false;
    }
    // Positional character classes.
    if !b[..6].iter().all(|c| c.is_ascii_uppercase()) {
        return false;
    }
    for &c in b[6..8]
        .iter()
        .chain(b[9..11].iter())
        .chain(b[12..15].iter())
    {
        if !it_is_flexible_digit(c) {
            return false;
        }
    }
    if !b"ABCDEHLMPRST".contains(&b[8]) {
        return false;
    }
    if !b[11].is_ascii_uppercase() {
        return false;
    }
    if !b[15].is_ascii_uppercase() {
        return false;
    }

    // Decode the birth-day segment (indexes 9..=10) with omocodia values.
    let (Some(d9), Some(d10)) = (it_omocodia_digit(b[9]), it_omocodia_digit(b[10])) else {
        return false;
    };
    let day = d9 * 10 + d10;
    if !(1..=31).contains(&day) && !(41..=71).contains(&day) {
        return false;
    }

    // Compute the check character.
    let mut sum: u32 = 0;
    for (i, &c) in b[..15].iter().enumerate() {
        let idx = IT_CONTROL_TABLE
            .iter()
            .position(|&t| t == c)
            .expect("charset already validated");
        sum += if i % 2 == 0 {
            IT_ODD[idx]
        } else {
            IT_EVEN[idx]
        } as u32;
    }
    b[15] == b'A' + (sum % 26) as u8
}

// ---------------------------------------------------------------------------
// NL_BSN — Netherlands Burgerservicenummer
// ---------------------------------------------------------------------------

/// Validates the 9-digit Dutch BSN (11-proef).
/// - Contiguous `XXXXX XXXX`… actually exactly 9 digits, OR dot-separated
///   `XXXX.XX.XXX` (no hyphens — kept disjoint from US SSN/ITIN; separators
///   only at positions 4 and 7)
/// - Must not start with `000`
/// - 11-proef: `9*d0 + 8*d1 + ... + 2*d7 - d8 ≡ 0 (mod 11)` with a positive sum
#[inline]
pub fn validate_nl_bsn(input: &str) -> bool {
    let b = input.as_bytes();
    // Exactly contiguous 9 digits, or dot-separated XXXX.XX.XXX with the two
    // dots anchored at positions 4 and 7 only.
    if b.len() == 9 {
        // fall through to digit parse below
    } else if b.len() == 11 {
        if b[4] != b'.' || b[7] != b'.' {
            return false;
        }
    } else {
        return false;
    }
    let mut digits = [0u8; 9];
    let mut n = 0usize;
    for (i, &c) in b.iter().enumerate() {
        if b.len() == 11 && (i == 4 || i == 7) {
            if c != b'.' {
                return false;
            }
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
    let d = digits;
    if d[0] == 0 && d[1] == 0 && d[2] == 0 {
        return false;
    }
    let weights = [9, 8, 7, 6, 5, 4, 3, 2, -1];
    let sum: i32 = weights
        .iter()
        .zip(d.iter())
        .map(|(&w, &x)| w * x as i32)
        .sum();
    sum > 0 && sum % 11 == 0
}

// ---------------------------------------------------------------------------
// PL_PESEL — Polish Powszechny Elektroniczny System Ewidencji Ludności
// ---------------------------------------------------------------------------

/// Validates the 11-digit Polish PESEL.
/// - 11 contiguous digits (no separators)
/// - Month+century encoding (`raw{10,20,..,80}` block) must decode to month
///   `1..=12`; the calendar date is validated including leap years
/// - Serial part (digits 6..=9) must not be `0000`
/// - Check digit uses weights `[1,3,7,9,1,3,7,9,1,3]`
#[inline]
pub fn validate_pl_pesel(input: &str) -> bool {
    let b = input.as_bytes();
    if b.len() != 11 || !b.iter().all(|c| c.is_ascii_digit()) {
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
        b[9] - b'0',
        b[10] - b'0',
    ];
    let raw_mm = d[2] * 10 + d[3];
    let mm = raw_mm % 20;
    if mm == 0 || mm > 12 {
        return false;
    }
    // Decode the birth year using the raw month block. The 1800-century block
    // (`80..=92`) is intentionally NOT accepted: it would misclassify many
    // Indonesian `628xxxxxxxx` 11-digit mobile numbers (PHONE_ID) as
    // century-encoded PESELs, and no living person has an 1800s birth year.
    let year_base: u16 = if (0..=12).contains(&raw_mm) {
        1900
    } else if (20..=32).contains(&raw_mm) {
        2000
    } else if (40..=52).contains(&raw_mm) {
        2100
    } else if (60..=72).contains(&raw_mm) {
        2200
    } else {
        // The 1800-century block (`80..=92`) is intentionally NOT accepted:
        // it would misclassify many Indonesian `628xxxxxxxx` 11-digit mobile
        // numbers (PHONE_ID) as century-encoded PESELs, and no living person
        // has an 1800s birth year.
        return false;
    };
    let year = year_base + (d[0] * 10 + d[1]) as u16;
    let dd = d[4] * 10 + d[5];

    let leap = year.is_multiple_of(4) && !year.is_multiple_of(100) || year.is_multiple_of(400);
    let days = match mm {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => 0,
    };
    if dd == 0 || dd > days {
        return false;
    }
    if d[6..10] == [0, 0, 0, 0] {
        return false;
    }

    // Check digit: weights [1,3,7,9,1,3,7,9,1,3] over the first 10 digits.
    let weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
    let sum: u32 = weights
        .iter()
        .zip(d.iter())
        .map(|(&w, &x)| (w as u32) * (x as u32))
        .sum();
    (10 - (sum % 10)) % 10 == d[10] as u32
}

// ---------------------------------------------------------------------------
// UK_NHS — National Health Service number
// ---------------------------------------------------------------------------

/// Validates the 10-digit UK NHS number.
/// - 10 digits contiguous, OR one-separator-char groups `XXX XXX XXXX` /
///   `XXX-XXX-XXXX` (both separators must be the same character at positions
///   3 and 7 only — no mixed or interleaved separators)
/// - Must not be all identical digits
/// - Mod-11 check with weights `10,9,8,...,2`: `(11 - sum%11) % 11 == d9`
///   and the check digit must be below 10 (values 10 are excluded)
#[inline]
pub fn validate_uk_nhs(input: &str) -> bool {
    let b = input.as_bytes();
    let sep = if b.len() == 12 {
        if b[3] != b[7] || (b[3] != b' ' && b[3] != b'-') {
            return false;
        }
        b[3]
    } else if b.len() != 10 {
        return false;
    } else {
        0
    };
    let mut digits = [0u8; 10];
    let mut n = 0usize;
    for (i, &c) in b.iter().enumerate() {
        if sep != 0 && (i == 3 || i == 7) {
            if c != sep {
                return false;
            }
            continue;
        }
        if !c.is_ascii_digit() {
            return false;
        }
        if n < 10 {
            digits[n] = c - b'0';
        }
        n += 1;
    }
    if n != 10 {
        return false;
    }
    if digits.windows(2).all(|w| w[0] == w[1]) {
        return false;
    }
    let weights = [10, 9, 8, 7, 6, 5, 4, 3, 2];
    let sum: u32 = weights
        .iter()
        .zip(digits.iter())
        .map(|(&w, &x)| w * x as u32)
        .sum();
    let check = (11 - sum % 11) % 11;
    check < 10 && check == digits[9] as u32
}

// ---------------------------------------------------------------------------
// UK_NINO — National Insurance number
// ---------------------------------------------------------------------------

/// Validates the 9-character UK National Insurance number.
/// - 2 uppercase letters + 6 digits + suffix `[A-D]`, contiguous, or spaced
///   `QQ 12 34 56 A` (a single, consistent separator character at positions
///   2, 5, 8, 11 only; uppercase-only, lowercase is rejected not normalized)
/// - First letter must not be D, F, I, Q, U, V
/// - Second letter must not be D, F, I, O, Q, U, V
/// - Prefix must not be one of BG, GB, NK, KN, TN, NT, ZZ
#[inline]
pub fn validate_uk_nino(input: &str) -> bool {
    // Uppercase-only (strict): lowercase letters are rejected rather than
    // normalized, unlike FR NIR which is uppercase-normalized by spec.
    if input.as_bytes().iter().any(|c| c.is_ascii_lowercase()) {
        return false;
    }
    let b = input.as_bytes();
    let sep = if b.len() == 13 {
        if b[2] != b[5] || b[2] != b[8] || b[2] != b[11] || (b[2] != b' ' && b[2] != b'-') {
            return false;
        }
        b[2]
    } else if b.len() != 9 {
        return false;
    } else {
        0
    };
    let mut compact = [0u8; 9];
    let mut n = 0usize;
    for (i, &c) in b.iter().enumerate() {
        if sep != 0 && (i == 2 || i == 5 || i == 8 || i == 11) {
            if c != sep {
                return false;
            }
            continue;
        }
        if n < 9 {
            compact[n] = c;
        }
        n += 1;
    }
    if n != 9 {
        return false;
    }
    let c = compact;
    if !c[..2].iter().all(|x| x.is_ascii_uppercase()) {
        return false;
    }
    if !c[2..8].iter().all(|x| x.is_ascii_digit()) {
        return false;
    }
    if !(b'A'..=b'D').contains(&c[8]) {
        return false;
    }
    let first_excl = b"DFIQUV";
    let second_excl = b"DFIOQUV";
    if first_excl.contains(&c[0]) || second_excl.contains(&c[1]) {
        return false;
    }
    let excl_prefixes: [&[u8; 2]; 7] = [b"BG", b"GB", b"NK", b"KN", b"TN", b"NT", b"ZZ"];
    !excl_prefixes.iter().any(|p| &c[..2] == *p)
}

/// Parses digits separated by a single repeating separator character, strictly:
/// the value must start and end on a digit with no doubled separators and the
/// separator may not appear at fixed arbitrary positions. Cleans up the
/// digits into `buf`, returning `None` on any violation.
#[inline]
fn parse_digits<'a>(input: &str, sep: u8, buf: &'a mut [u8]) -> Option<&'a [u8]> {
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let is_sep = |c: u8| c == sep;
    if is_sep(bytes[0]) || is_sep(bytes[bytes.len() - 1]) {
        return None;
    }
    let mut n = 0usize;
    let mut last_sep = false;
    for &c in bytes {
        if is_sep(c) {
            if last_sep {
                return None;
            }
            last_sep = true;
            continue;
        }
        last_sep = false;
        if !c.is_ascii_digit() {
            return None;
        }
        if n < buf.len() {
            buf[n] = c - b'0';
        }
        n += 1;
    }
    Some(&buf[..n.min(buf.len())])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_de_steuer_id() {
        assert!(validate_de_steuer_id("51928327648"));
        assert!(validate_de_steuer_id("51 928327648")); // single space, strict grouping
                                                        // Check digit 0 (product == 1) must be accepted
        assert!(validate_de_steuer_id("51928327460"));
        // Bad check digit
        assert!(!validate_de_steuer_id("51928327649"));
        // Leading zero
        assert!(!validate_de_steuer_id("01928327648"));
        // Consecutive separators and leading separator
        assert!(!validate_de_steuer_id("51  928327648"));
        assert!(!validate_de_steuer_id(" 51928327648"));
        // Wrong histogram: two pairs is invalid
        assert!(!validate_de_steuer_id("11223456789"));
        // Three-run is invalid
        assert!(!validate_de_steuer_id("51112227648"));
    }

    #[test]
    fn test_fr_nir() {
        assert!(validate_fr_nir("195024610200145"));
        assert!(validate_fr_nir("1 95 02 46 102 001 45"));
        assert!(validate_fr_nir("181022A10200402")); // Corse 2A -> 19
        assert!(validate_fr_nir("181022B10200429")); // Corse 2B -> 18
        assert!(validate_fr_nir("181 022 B 102 004 29")); // spaced 2B
        assert!(validate_fr_nir("195099710200141")); // overseas 971
        assert!(validate_fr_nir("195099854200106")); // overseas 984
                                                     // Bad key
        assert!(!validate_fr_nir("195024610200146"));
        // Invalid month 13
        assert!(!validate_fr_nir("195013610200145"));
        // Sex digit 0 rejected
        assert!(!validate_fr_nir("095024610200145"));
        // Leading separator / consecutive separators
        assert!(!validate_fr_nir(" 195024610200145"));
        assert!(!validate_fr_nir("1  95024610200145"));
        // Domestic dept 96 rejected
        assert!(!validate_fr_nir("19509610200198"));

        // Letters outside the 2A/2B department positions must fail:
        assert!(!validate_fr_nir("19502461020012I")); // letter in key
        assert!(!validate_fr_nir("195A24610200105")); // letter in month
        assert!(!validate_fr_nir("19502461020Z015")); // letter in serial
                                                      // Zero commune & zero serial blocks
        assert!(!validate_fr_nir("195024600000145"));
        assert!(!validate_fr_nir("195024610000145"));
        // Overseas 979 is not an allowed 3-digit department
        assert!(!validate_fr_nir("195099791200188"));
    }

    #[test]
    fn test_es_dni() {
        assert!(validate_es_dni("12345678-Z"));
        assert!(validate_es_dni("12345678Z"));
        assert!(validate_es_dni("Y2345678Z"));
        // Wrong letter
        assert!(!validate_es_dni("12345678-A"));
        // NIE with wrong letter for its Y prefix
        assert!(!validate_es_dni("Y2345678A"));
        // Lowercase check letter rejected
        assert!(!validate_es_dni("12345678z"));
        // Separator in the middle rejected
        assert!(!validate_es_dni("1234-5678Z"));
    }

    #[test]
    fn test_it_codice_fiscale() {
        // Genuine Agenzia-delle-Entrate samples (correct even table).
        assert!(validate_it_codice_fiscale("RSSMRA85M01H501Q"));
        assert!(validate_it_codice_fiscale("MLNBBA65T51F205I"));
        assert!(!validate_it_codice_fiscale("rssmra85m01h501q"));
        assert!(!validate_it_codice_fiscale("RSSMRA85M01H501A"));
        // Impossible birth day (99 via omocodia decode)
        assert!(!validate_it_codice_fiscale("RSSMRA85M99H501Q"));
        // Non-omocodia letters in the day slot (also catches the u8 overflow)
        assert!(!validate_it_codice_fiscale("RSSMRA85MZZH501Q"));
        // Invalid month letter
        assert!(!validate_it_codice_fiscale("RSSMRA85MJZ1H501Q"));
    }

    #[test]
    fn test_nl_bsn() {
        assert!(validate_nl_bsn("835030568"));
        assert!(validate_nl_bsn("8350.30.568"));
        // Bad checksum
        assert!(!validate_nl_bsn("835030569"));
        // 000 prefix
        assert!(!validate_nl_bsn("000135053"));
        // Hyphen rejected (kept disjoint from US SSN/ITIN)
        assert!(!validate_nl_bsn("8350-30-568"));
        // Leading dot / misplaced dots
        assert!(!validate_nl_bsn(".835030568"));
        assert!(!validate_nl_bsn("83.50.30.568"));
        // Separator mosaic ("8.3.5.0.3.0.5.6.8") rejected
        assert!(!validate_nl_bsn("8.3.5.0.3.0.5.6.8"));
    }

    #[test]
    fn test_pl_pesel() {
        assert!(validate_pl_pesel("95022812342"));
        // Bad check digit
        assert!(!validate_pl_pesel("95022812343"));
        // Feb 29 in a non-leap year
        assert!(!validate_pl_pesel("95022912349"));
        // Invalid month block 13
        assert!(!validate_pl_pesel("95132812342"));
        // Invalid day 32
        assert!(!validate_pl_pesel("95023212349"));
        // 1800-century block (80..=92) removed: must not claim this shape
        assert!(!validate_pl_pesel("62812345678"));
        // Separators rejected
        assert!(!validate_pl_pesel("9502281234 2"));
        assert!(!validate_pl_pesel("95-02-28-1234-2"));
    }

    #[test]
    fn test_uk_nhs() {
        assert!(validate_uk_nhs("4139537671"));
        assert!(validate_uk_nhs("413 953 7671"));
        assert!(validate_uk_nhs("413-953-7671"));
        // Bad check digit
        assert!(!validate_uk_nhs("4139537672"));
        // All identical digits
        assert!(!validate_uk_nhs("5555555555"));
        // Consecutive separators
        assert!(!validate_uk_nhs("413  953 7671"));
        // Leading separator
        assert!(!validate_uk_nhs(" 4139537671"));
        // Mixed separators
        assert!(!validate_uk_nhs("413-953 7671"));
        // Separator mosaic rejected
        assert!(!validate_uk_nhs("4-1-3-9-5-3-7-6-7-1"));
    }

    #[test]
    fn test_uk_nino() {
        assert!(validate_uk_nino("AA123456A"));
        assert!(validate_uk_nino("AA 12 34 56 A"));
        assert!(validate_uk_nino("JL-12-34-56-C"));
        // Reserved first letter D (prefix DG)
        assert!(!validate_uk_nino("DG123456A"));
        // Reserved second letter O
        assert!(!validate_uk_nino("AO123456A"));
        // Forbidden prefix BG
        assert!(!validate_uk_nino("BG123456A"));
        // Forbidden suffix
        assert!(!validate_uk_nino("AA123456E"));
        // Lowercase letters rejected
        assert!(!validate_uk_nino("aa123456a"));
        // Trailing separator
        assert!(!validate_uk_nino("AA123456A "));
        // Separator mosaic rejected
        assert!(!validate_uk_nino("A-1-2-3-4-5-6-A"));
        // Mixed separators
        assert!(!validate_uk_nino("AA 12-34 56 A"));
    }
}
