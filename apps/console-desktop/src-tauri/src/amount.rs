//! KUNA amounts as integer atoms.
//!
//! One KUNA is `10^9` atoms. Parsing and formatting never use floating point.

/// Decimal places of the native coin.
pub const KUNA_DECIMALS: u32 = 9;

const ATOM_SCALE: u128 = 1_000_000_000;

/// Parse a KUNA amount into atoms.
///
/// Accepts a whole number or a decimal with at most 9 fractional digits.
pub fn parse_kuna_atoms(text: &str) -> Result<u64, String> {
    let text = text.trim();
    if text.is_empty() || text == "." {
        return Err("Enter a KUNA amount.".to_string());
    }
    let mut dot = None;
    for (index, byte) in text.bytes().enumerate() {
        if byte == b'.' {
            if dot.is_some() {
                return Err("Enter a KUNA amount.".to_string());
            }
            dot = Some(index);
            continue;
        }
        if !byte.is_ascii_digit() {
            return Err("Enter a KUNA amount.".to_string());
        }
    }
    let (whole, frac) = match dot {
        Some(index) => (&text[..index], &text[index + 1..]),
        None => (text, ""),
    };
    if frac.len() > KUNA_DECIMALS as usize {
        return Err("KUNA amounts use at most 9 decimal places.".to_string());
    }
    if whole.is_empty() && frac.is_empty() {
        return Err("Enter a KUNA amount.".to_string());
    }
    let whole_units = if whole.is_empty() {
        0
    } else {
        parse_u128(whole)?
    };
    let whole_atoms = whole_units
        .checked_mul(ATOM_SCALE)
        .ok_or_else(|| "That amount is larger than KUNA can send.".to_string())?;
    let mut frac_digits = [b'0'; KUNA_DECIMALS as usize];
    for (slot, byte) in frac_digits.iter_mut().zip(frac.bytes()) {
        *slot = byte;
    }
    let frac_atoms = parse_u128(std::str::from_utf8(&frac_digits).unwrap_or("0"))?;
    let total = whole_atoms
        .checked_add(frac_atoms)
        .ok_or_else(|| "That amount is larger than KUNA can send.".to_string())?;
    u64::try_from(total).map_err(|_| "That amount is larger than KUNA can send.".to_string())
}

/// Format atoms as a KUNA decimal. Trailing fractional zeros are omitted.
pub fn format_kuna_atoms(atoms: u64) -> String {
    let atoms = u128::from(atoms);
    let whole = atoms / ATOM_SCALE;
    let frac = atoms % ATOM_SCALE;
    if frac == 0 {
        return whole.to_string();
    }
    let digits = format!("{frac:09}");
    let trimmed = digits.trim_end_matches('0');
    format!("{whole}.{trimmed}")
}

fn parse_u128(text: &str) -> Result<u128, String> {
    let mut value: u128 = 0;
    for byte in text.bytes() {
        let digit = u128::from(byte - b'0');
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(digit))
            .ok_or_else(|| "That amount is larger than KUNA can send.".to_string())?;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_zero_one_atom_one_kuna_and_the_max() {
        assert_eq!(parse_kuna_atoms("0").unwrap(), 0);
        assert_eq!(parse_kuna_atoms("0.000000001").unwrap(), 1);
        assert_eq!(parse_kuna_atoms("1").unwrap(), 1_000_000_000);
        assert_eq!(parse_kuna_atoms("18446744073.709551615").unwrap(), u64::MAX);
        assert_eq!(format_kuna_atoms(0), "0");
        assert_eq!(format_kuna_atoms(1), "0.000000001");
        assert_eq!(format_kuna_atoms(1_000_000_000), "1");
        assert_eq!(format_kuna_atoms(u64::MAX), "18446744073.709551615");
    }

    #[test]
    fn rejects_more_than_nine_decimal_places() {
        assert!(parse_kuna_atoms("0.0000000001").is_err());
        assert!(parse_kuna_atoms("1.0000000001").is_err());
        assert!(parse_kuna_atoms("1e9").is_err());
        assert!(parse_kuna_atoms("-1").is_err());
        assert!(parse_kuna_atoms("18446744073.709551616").is_err());
    }

    #[test]
    fn jarvis_amount_edge_cases() {
        for bad in [
            "",
            " ",
            ".",
            "1,5",
            "1 000",
            "+1",
            "-0",
            "1e-9",
            "0x10",
            "1_000",
            "\u{FF11}",
            "1..2",
            "NaN",
            "Infinity",
            "1.0000000000",
            "18446744074",
        ] {
            assert!(parse_kuna_atoms(bad).is_err(), "accepted {bad:?}");
        }
        assert_eq!(parse_kuna_atoms(" 1.5 ").unwrap(), 1_500_000_000);
        assert_eq!(parse_kuna_atoms(".5").unwrap(), 500_000_000);
        assert_eq!(parse_kuna_atoms("5.").unwrap(), 5_000_000_000);
        assert_eq!(
            parse_kuna_atoms("000000000000000000000000000000000000000001").unwrap(),
            1_000_000_000
        );
        assert!(parse_kuna_atoms(&"9".repeat(60)).is_err());
    }
}
