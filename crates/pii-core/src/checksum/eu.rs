//! GDPR-era European national identifier validators.
//!
//! Every validator enforces strict separator discipline: it rejects leading
//! and trailing separators, consecutive separators, and any character outside
//! the allowed alphabet.

use super::common::{strict_alnum, strict_digits};

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
    let Some(d) = strict_digits(input, b" ") else {
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

    let (check, _) = de_steuer_check(d10);
    check == d[10]
}

/// Computes the ISO 7064 Mod 11,10 check digit over 10 digits.
#[inline]
fn de_steuer_check(d10: &[u8]) -> (u8, u32) {
    let mut product = 10u32;
    for &x in d10 {
        let mut t = (product + x as u32) % 10;
        if t == 0 {
            t = 10;
        }
        product = (2 * t) % 11;
    }
    let check = (11 - product) % 11;
    (check as u8, product)
}

// ---------------------------------------------------------------------------
// FR_NIR — French Numéro d'Inscription au Répertoire
// ---------------------------------------------------------------------------

/// Validates the 15-character French NIR (social security number).
/// - 15 alphanumeric characters after stripping single spaces/hyphens
/// - Uppercase normalized; sex digit in `1..=4 | 7 | 8`
/// - Month in `01..=12 | 20..=99`
/// - Department `2A`→19, `2B`→18 before the mod-97 key computation; domestic
///   departments reject `00` and `96`; overseas (`97`/`98`) requires 3-digit
///   department `971..=978` or `984..=988`
/// - Last two digits (key, `01..=97`) satisfy `key == 97 - (nir13 mod 97)`
#[inline]
pub fn validate_fr_nir(input: &str) -> bool {
    let Some(raw) = strict_alnum(input, b" -") else {
        return false;
    };
    if raw.len() != 15 {
        return false;
    }
    // Sex digit.
    if !matches!(raw[0], b'1'..=b'4' | b'7' | b'8') {
        return false;
    }
    // Year (raw[1..3]) is unconstrained (00..=99).
    // Month (raw[3..5]).
    let month = (raw[3] - b'0') * 10 + (raw[4] - b'0');
    if !((1..=12).contains(&month) || month >= 20) {
        return false;
    }

    // Build the pure-digit 13-digit basis for the mod-97 computation.
    let mut digits13 = [0u8; 13];
    for i in 0..5 {
        digits13[i] = raw[i] - b'0';
    }
    match (&raw[5..7], raw[7]) {
        (b"2A", _) | (b"2B", _) => {
            digits13[5] = b'1' - b'0';
            digits13[6] = if raw[6] == b'A' { 9 } else { 8 };
            digits13[7] = raw[7] - b'0';
            for i in 8..13 {
                digits13[i] = raw[i] - b'0';
            }
        }
        (t, c3) if t[0] == b'9' && (t[1] == b'7' || t[1] == b'8') => {
            // Overseas DOM-TOM: 3-digit department 971..=978 or 984..=988.
            let third = c3.wrapping_sub(b'0');
            let dep_ok = if t[1] == b'7' {
                (1..=8).contains(&third)
            } else {
                (4..=8).contains(&third)
            };
            if !dep_ok || !c3.is_ascii_digit() {
                return false;
            }
            for i in 5..13 {
                digits13[i] = raw[i] - b'0';
            }
        }
        (t, _) => {
            if !t[0].is_ascii_digit() || !t[1].is_ascii_digit() {
                return false;
            }
            let dep = (t[0] - b'0') * 10 + (t[1] - b'0');
            if dep == 0 || dep == 96 {
                return false;
            }
            for i in 5..13 {
                digits13[i] = raw[i] - b'0';
            }
        }
    }

    // Parse the 13-digit basis and validate the key.
    let mut nir13: u64 = 0;
    for &x in digits13.iter() {
        nir13 = nir13 * 10 + x as u64;
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

// 1-based "dispari" (odd) table with value 1 for digits 0-9 at even index 0.
const IT_CONTROL_TABLE: &[u8; 36] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const IT_ODD: &[u8; 36] = &[
    1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6,
    8, 12, 14, 16, 10, 22, 25, 24, 23,
];
const IT_EVEN: &[u8; 36] = &[
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
];

/// Validates the 16-character Italian codice fiscale.
/// - 16 uppercase letters/digits, `[A-Z]{6}[0-9LMNPQRSTUV]{2}[ABCDEHLMPRST]`.
/// - Birth-day part (chars 9-10) decodes omocodia letters L→0..V→9 and must be
///   in `1..=31 | 41..=71` (41..=71 for foreign citizens onFemaleSign days)
/// - Last character is the check char `b'A' + (sum mod 26)` where 0-based even
///   indices use the official 1-based odd table and odd indices the even table.
#[inline]
pub fn validate_it_codice_fiscale(input: &str) -> bool {
    let b = input.as_bytes();
    if b.len() != 16 {
        return false;
    }
    for &c in b {
        if !(c.is_ascii_digit() || c.is_ascii_uppercase()) {
            return false;
        }
    }
    // Decode the birth-day segment (indexes 9..=10) with omocodia values.
    let omocodia = |c: u8| -> u8 {
        match c {
            b'L' => 0,
            b'M' => 1,
            b'N' => 2,
            b'P' => 3,
            b'Q' => 4,
            b'R' => 5,
            b'S' => 6,
            b'T' => 7,
            b'U' => 8,
            b'V' => 9,
            _ => c - b'0',
        }
    };
    let day = omocodia(b[9]) * 10 + omocodia(b[10]);
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
/// - 9 digits, contiguous or dot-separated `XXXX.XX.XXX` (no hyphens)
/// - Must not start with `000`
/// - 11-proef: `9*d0 + 8*d1 + ... + 2*d7 - d8 ≡ 0 (mod 11)` with a positive sum
#[inline]
pub fn validate_nl_bsn(input: &str) -> bool {
    let Some(d) = strict_digits(input, b".") else {
        return false;
    };
    if d.len() != 9 || (d[0] == 0 && d[1] == 0 && d[2] == 0) {
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
/// - Month+century encoding (`raw{10,20,..,90}` block) must decode to month
///   `1..=12`; the calendar date is validated including leap years
/// - Serial part (digits 6..=9) must not be `0000`
/// - Check digit uses weights `[1,3,7,9,1,3,7,9,1,3]`
#[inline]
pub fn validate_pl_pesel(input: &str) -> bool {
    if input.len() != 11 || !input.as_bytes().iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let d: Vec<u8> = input.as_bytes().iter().map(|c| c - b'0').collect();
    let raw_mm = d[2] * 10 + d[3];
    let mm = raw_mm % 20;
    if mm == 0 || mm > 12 {
        return false;
    }
    // Decode the birth year using the raw month block.
    let year_base: u16 = if (0..=12).contains(&raw_mm) {
        1900
    } else if (20..=32).contains(&raw_mm) {
        2000
    } else if (40..=52).contains(&raw_mm) {
        2100
    } else if (60..=72).contains(&raw_mm) {
        2200
    } else if (80..=92).contains(&raw_mm) {
        1800
    } else {
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
        .zip(d.iter().take(10))
        .map(|(&w, &x)| (w as u32) * (x as u32))
        .sum();
    (10 - (sum % 10)) % 10 == d[10] as u32
}

// ---------------------------------------------------------------------------
// UK_NHS — National Health Service number
// ---------------------------------------------------------------------------

/// Validates the 10-digit UK NHS number.
/// - 10 digits, contiguous or `XXX XXX XXXX` / `XXX-XXX-XXXX`
/// - Must not be all identical digits
/// - Mod-11 check with weights `10,9,8,...,2`: `(11 - sum%11) % 11 == d9`
///   and the check digit must be below 10 (values 10 are excluded)
#[inline]
pub fn validate_uk_nhs(input: &str) -> bool {
    let Some(d) = strict_digits(input, b" -") else {
        return false;
    };
    if d.len() != 10 {
        return false;
    }
    if d.windows(2).all(|w| w[0] == w[1]) {
        return false;
    }
    let weights = [10, 9, 8, 7, 6, 5, 4, 3, 2];
    let sum: u32 = weights
        .iter()
        .zip(d.iter())
        .map(|(&w, &x)| w * x as u32)
        .sum();
    let check = (11 - sum % 11) % 11;
    check < 10 && check == d[9] as u32
}

// ---------------------------------------------------------------------------
// UK_NINO — National Insurance number
// ---------------------------------------------------------------------------

/// Validates the 9-character UK National Insurance number.
/// - 2 uppercase letters + 6 digits + suffix `[A-D]`, with optional single
///   spaces/hyphens between characters (strict separator discipline)
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
    let Some(c) = strict_alnum(input, b" -") else {
        return false;
    };
    if c.len() != 9 || !c[8].is_ascii_uppercase() {
        return false;
    }
    if !c[..2].iter().all(|b| b.is_ascii_uppercase()) {
        return false;
    }
    if !(b'A'..=b'D').contains(&c[8]) {
        return false;
    }
    for &x in &c[2..8] {
        if !x.is_ascii_digit() {
            return false;
        }
    }
    let first_excl = b"DFIQUV";
    let second_excl = b"DFIOQUV";
    if first_excl.contains(&c[0]) || second_excl.contains(&c[1]) {
        return false;
    }
    let excl_prefixes: [&[u8; 2]; 7] = [b"BG", b"GB", b"NK", b"KN", b"TN", b"NT", b"ZZ"];
    !excl_prefixes.iter().any(|p| &c[..2] == *p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_de_steuer_id() {
        assert!(validate_de_steuer_id("51928327648"));
        assert!(validate_de_steuer_id("51 928327648")); // single space, strict grouping
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
        // Domestic dept 96 rejected (checksum adjusted to a wrong key anyway)
        assert!(!validate_fr_nir("19509610200198"));
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
        assert!(validate_it_codice_fiscale("RSSMRA85M01H501E"));
        assert!(!validate_it_codice_fiscale("rssmra85m01h501e"));
        assert!(!validate_it_codice_fiscale("RSSMRA85M01H501A"));
        // Impossible birth day (00 or 99 via omocodia decode '99' day)
        assert!(!validate_it_codice_fiscale("RSSMRA85M99H501E"));
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
        // Leading dot
        assert!(!validate_nl_bsn(".835030568"));
    }

    #[test]
    fn test_pl_pesel() {
        assert!(validate_pl_pesel("95022812342"));
        // Bad check digit
        assert!(!validate_pl_pesel("95022812343"));
        // Feb 29 in a non-leap year
        assert!(!validate_pl_pesel("95022912341"));
        // Invalid month block 13
        assert!(!validate_pl_pesel("95132812342"));
        // Invalid day 32
        assert!(!validate_pl_pesel("95023212342"));
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
    }
}
