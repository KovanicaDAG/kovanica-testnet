//! KUNA amounts for the CLI and the interactive wallet.
//!
//! The chain counts atoms. One KUNA is `10^9` atoms. Parsing is exact integer
//! arithmetic: no floating point. A CLI amount must name its unit: a decimal
//! or a `KUNA` suffix is KUNA, and an `atoms` suffix is atoms. A bare integer
//! such as `5` is rejected.

use std::fmt;

/// Atoms in one KUNA. Matches the chain's 9 decimal places.
pub const ATOMS_PER_KUNA: u128 = 1_000_000_000;

/// Why a KUNA amount was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmountError {
    /// The field was empty.
    Empty,
    /// The text was not a plain decimal number.
    Invalid,
    /// A bare integer did not say whether it was KUNA or atoms.
    NeedsUnit,
    /// More than 9 digits followed the decimal point.
    TooPrecise,
    /// The value does not fit in a `u64` atom count.
    Overflow,
    /// Zero is not a useful transfer, stake, or delegation.
    Zero,
}

impl fmt::Display for AmountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "enter an amount",
            Self::Invalid => "amount must be KUNA such as 1.5 or 1.5KUNA, or atoms such as 5atoms",
            Self::NeedsUnit => "amount needs a unit, for example 5KUNA or 5atoms",
            Self::TooPrecise => "KUNA has 9 decimal places",
            Self::Overflow => "amount is too large",
            Self::Zero => "amount must be greater than 0",
        })
    }
}

impl std::error::Error for AmountError {}

/// Why a fee was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FeeError {
    /// The field was empty.
    Empty,
    /// The text was not a whole number of atoms.
    Invalid,
    /// The mempool rejects a zero fee.
    Zero,
    /// The value does not fit in a `u64`.
    Overflow,
}

impl fmt::Display for FeeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "enter a fee in atoms",
            Self::Invalid => "fee must be a whole number of atoms",
            Self::Zero => "fee must be at least 1 atom",
            Self::Overflow => "fee is too large",
        })
    }
}

/// Parse a decimal KUNA amount into atoms.
///
/// A trailing `KUNA` suffix is accepted. Scientific notation, signs, grouping
/// separators, and more than 9 fractional digits are not.
pub(crate) fn parse_kuna(input: &str) -> Result<u64, AmountError> {
    let text = strip_suffix(input, "kuna");
    if text.is_empty() {
        return Err(AmountError::Empty);
    }
    if text.ends_with('.') || text.starts_with('+') || text.starts_with('-') {
        return Err(AmountError::Invalid);
    }
    let (whole, frac) = match text.split_once('.') {
        Some((whole, frac)) => (whole, frac),
        None => (text, ""),
    };
    if whole.is_empty() && frac.is_empty() {
        return Err(AmountError::Invalid);
    }
    if !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !frac.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(AmountError::Invalid);
    }
    if frac.len() > 9 {
        return Err(AmountError::TooPrecise);
    }
    let whole_atoms: u128 = if whole.is_empty() {
        0
    } else {
        whole.parse::<u128>().map_err(|_| AmountError::Overflow)?
    };
    let frac_scale = 10u128.pow((9 - frac.len()) as u32);
    let frac_atoms: u128 = if frac.is_empty() {
        0
    } else {
        frac.parse::<u128>().map_err(|_| AmountError::Overflow)?
    };
    let atoms = whole_atoms
        .checked_mul(ATOMS_PER_KUNA)
        .and_then(|value| value.checked_add(frac_atoms.checked_mul(frac_scale)?))
        .ok_or(AmountError::Overflow)?;
    u64::try_from(atoms).map_err(|_| AmountError::Overflow)
}

/// Parse a CLI amount into atoms.
///
/// `1.5`, `1.5KUNA`, and `1.5 KUNA` are one and a half KUNA. `1KUNA` is one
/// KUNA. `5atoms` and `5atom` are five atoms. A bare integer is rejected:
/// `5` does not say which unit it is. More than 9 fractional digits and
/// values that do not fit in `u64` atoms are rejected. The conversion does
/// not use floating point.
pub fn parse_cli_amount(input: &str) -> Result<u64, AmountError> {
    let text = input.trim();
    if text.is_empty() {
        return Err(AmountError::Empty);
    }
    if let Some(body) = strip_kuna_suffix(text) {
        if body.is_empty() {
            return Err(AmountError::Empty);
        }
        return parse_kuna(text);
    }
    if let Some(body) =
        strip_named_suffix(text, "atoms").or_else(|| strip_named_suffix(text, "atom"))
    {
        return parse_atom_count(body);
    }
    if text.contains('.') {
        return parse_kuna(text);
    }
    if text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AmountError::NeedsUnit);
    }
    Err(AmountError::Invalid)
}

fn parse_atom_count(body: &str) -> Result<u64, AmountError> {
    if body.is_empty() {
        return Err(AmountError::Empty);
    }
    if !body.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AmountError::Invalid);
    }
    body.parse::<u64>().map_err(|_| AmountError::Overflow)
}

/// Parse a KUNA amount that must be greater than zero.
pub(crate) fn parse_positive_kuna(input: &str) -> Result<u64, AmountError> {
    match parse_kuna(input)? {
        0 => Err(AmountError::Zero),
        amount => Ok(amount),
    }
}

/// Parse a fee in whole atoms. The minimum accepted fee is 1 atom.
pub(crate) fn parse_fee_atoms(input: &str) -> Result<u64, FeeError> {
    let text = strip_suffix(input, "atoms");
    let text = strip_suffix(text, "atom");
    if text.is_empty() {
        return Err(FeeError::Empty);
    }
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(FeeError::Invalid);
    }
    let fee = text.parse::<u64>().map_err(|_| FeeError::Overflow)?;
    if fee == 0 {
        return Err(FeeError::Zero);
    }
    Ok(fee)
}

/// Format an atom count as KUNA with all 9 decimal places.
pub fn format_kuna_fixed(atoms: u64) -> String {
    format!("{} KUNA", format_kuna_decimal(atoms))
}

/// Decimal KUNA with exactly 9 digits after the point, without a suffix.
pub fn format_kuna_decimal(atoms: u64) -> String {
    let whole = atoms / 1_000_000_000;
    let frac = atoms % 1_000_000_000;
    format!("{whole}.{frac:09}")
}

/// Format an atom count as a KUNA decimal, trimming trailing fractional zeros.
pub(crate) fn format_kuna(atoms: u64) -> String {
    let whole = atoms / 1_000_000_000;
    let frac = atoms % 1_000_000_000;
    if frac == 0 {
        return format!("{whole} KUNA");
    }
    let mut frac_text = format!("{frac:09}");
    while frac_text.ends_with('0') {
        frac_text.pop();
    }
    format!("{whole}.{frac_text} KUNA")
}

/// Format an atom count as KUNA plus the exact atom count.
pub(crate) fn format_atoms_pair(atoms: u64) -> String {
    format!("{} ({atoms} atoms)", format_kuna(atoms))
}

/// Format a fee, using the singular when it is one atom.
pub(crate) fn format_fee(atoms: u64) -> String {
    if atoms == 1 {
        "1 atom".to_string()
    } else {
        format!("{atoms} atoms")
    }
}

fn strip_kuna_suffix(input: &str) -> Option<&str> {
    strip_named_suffix(input, "kuna")
}

fn strip_named_suffix<'a>(input: &'a str, suffix: &str) -> Option<&'a str> {
    if input.len() >= suffix.len()
        && input[input.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    {
        Some(input[..input.len() - suffix.len()].trim())
    } else {
        None
    }
}

fn strip_suffix<'a>(input: &'a str, suffix: &str) -> &'a str {
    let text = input.trim();
    if text.len() >= suffix.len() && text[text.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    {
        text[..text.len() - suffix.len()].trim()
    } else {
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tokenomics_amounts() {
        assert_eq!(parse_kuna("2.5").unwrap(), 2_500_000_000);
        assert_eq!(parse_kuna("2.50 KUNA").unwrap(), 2_500_000_000);
        assert_eq!(parse_kuna("50000").unwrap(), 50_000_000_000_000);
        assert_eq!(parse_kuna("0.000000001").unwrap(), 1);
        assert_eq!(parse_kuna(".5").unwrap(), 500_000_000);
        assert_eq!(parse_kuna("0").unwrap(), 0);
        assert_eq!(parse_positive_kuna("0"), Err(AmountError::Zero));
    }

    #[test]
    fn rejects_ambiguous_amounts() {
        assert_eq!(parse_kuna(""), Err(AmountError::Empty));
        assert_eq!(parse_kuna("   "), Err(AmountError::Empty));
        assert_eq!(parse_kuna("1."), Err(AmountError::Invalid));
        assert_eq!(parse_kuna("1e9"), Err(AmountError::Invalid));
        assert_eq!(parse_kuna("-1"), Err(AmountError::Invalid));
        assert_eq!(parse_kuna("+1"), Err(AmountError::Invalid));
        assert_eq!(parse_kuna("1,000"), Err(AmountError::Invalid));
        assert_eq!(parse_kuna("0.0000000001"), Err(AmountError::TooPrecise));
    }

    #[test]
    fn cli_amount_requires_a_unit() {
        assert_eq!(parse_cli_amount("1.5").unwrap(), 1_500_000_000);
        assert_eq!(parse_cli_amount("1.5KUNA").unwrap(), 1_500_000_000);
        assert_eq!(parse_cli_amount("1.5kuna").unwrap(), 1_500_000_000);
        assert_eq!(parse_cli_amount("1.5 KUNA").unwrap(), 1_500_000_000);
        assert_eq!(parse_cli_amount("1KUNA").unwrap(), 1_000_000_000);
        assert_eq!(parse_cli_amount("0.000000001").unwrap(), 1);
        assert_eq!(parse_cli_amount("5atoms").unwrap(), 5);
        assert_eq!(parse_cli_amount("5atom").unwrap(), 5);
        assert_eq!(parse_cli_amount("5 ATOMS").unwrap(), 5);
        assert_eq!(parse_cli_amount("1500000000atoms").unwrap(), 1_500_000_000);
        assert_eq!(parse_cli_amount("0002atoms").unwrap(), 2);
        assert_eq!(
            parse_cli_amount("18446744073709551615atoms").unwrap(),
            u64::MAX
        );
        // `5` does not say KUNA or atoms.
        assert_eq!(parse_cli_amount("1"), Err(AmountError::NeedsUnit));
        assert_eq!(parse_cli_amount("5"), Err(AmountError::NeedsUnit));
        assert_eq!(parse_cli_amount("1500000000"), Err(AmountError::NeedsUnit));
        assert_eq!(parse_cli_amount("0002"), Err(AmountError::NeedsUnit));
        assert!(parse_cli_amount("5")
            .unwrap_err()
            .to_string()
            .contains("5KUNA"));
        assert_eq!(format_kuna_fixed(1_500_000_000), "1.500000000 KUNA");
        assert_eq!(format_kuna_decimal(1), "0.000000001");
        assert_eq!(format_kuna_fixed(1), "0.000000001 KUNA");
    }

    #[test]
    fn cli_amount_rejects_extra_decimals_overflow_and_non_integers() {
        assert_eq!(
            parse_cli_amount("0.0000000001"),
            Err(AmountError::TooPrecise)
        );
        assert_eq!(
            parse_cli_amount("1.0000000001"),
            Err(AmountError::TooPrecise)
        );
        assert_eq!(
            parse_cli_amount("18446744073709551616atoms"),
            Err(AmountError::Overflow)
        );
        assert_eq!(parse_cli_amount("atoms"), Err(AmountError::Empty));
        assert_eq!(
            parse_cli_amount("18446744074KUNA"),
            Err(AmountError::Overflow)
        );
        assert_eq!(parse_cli_amount("1e9"), Err(AmountError::Invalid));
        assert_eq!(parse_cli_amount("1."), Err(AmountError::Invalid));
        assert_eq!(parse_cli_amount("-1.5"), Err(AmountError::Invalid));
        assert_eq!(parse_cli_amount("+1"), Err(AmountError::Invalid));
        assert_eq!(parse_cli_amount("1,000"), Err(AmountError::Invalid));
        assert_eq!(parse_cli_amount(""), Err(AmountError::Empty));
        assert_eq!(parse_cli_amount("KUNA"), Err(AmountError::Empty));
    }

    #[test]
    fn formats_whole_and_fractional_kuna() {
        assert_eq!(format_kuna(0), "0 KUNA");
        assert_eq!(format_kuna(2_500_000_000), "2.5 KUNA");
        assert_eq!(format_kuna(1), "0.000000001 KUNA");
        assert_eq!(format_kuna(50_000_000_000_000), "50000 KUNA");
        assert_eq!(
            format_atoms_pair(2_500_000_000),
            "2.5 KUNA (2500000000 atoms)"
        );
        assert_eq!(format_fee(1), "1 atom");
        assert_eq!(format_fee(2), "2 atoms");
    }

    #[test]
    fn fee_requires_a_positive_atom_count() {
        assert_eq!(parse_fee_atoms("1").unwrap(), 1);
        assert_eq!(parse_fee_atoms("0002 atoms").unwrap(), 2);
        assert_eq!(parse_fee_atoms("1 atom").unwrap(), 1);
        assert_eq!(parse_fee_atoms(""), Err(FeeError::Empty));
        assert_eq!(parse_fee_atoms("0"), Err(FeeError::Zero));
        assert_eq!(parse_fee_atoms("1.5"), Err(FeeError::Invalid));
        assert_eq!(parse_fee_atoms("-1"), Err(FeeError::Invalid));
    }
}
