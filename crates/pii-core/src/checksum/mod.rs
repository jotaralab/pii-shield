pub mod common;
pub mod id;
pub mod sg;
pub mod us;

pub use common::*;
pub use id::*;
pub use sg::*;
pub use us::*;

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
