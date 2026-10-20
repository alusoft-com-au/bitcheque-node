//! The 18-digit cheque message (DESIGN.md §10.2).
use crate::damm;

pub const COLS: usize = 18;
pub const ROWS: usize = 10;
pub const PAYEE_DIGITS: usize = 11;
/// Columns of printed part A (recipient and check digit); the rest (amount, exponent, fee tier) are part B.
pub const PART_A: usize = PAYEE_DIGITS + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    pub payee: u32,
    pub mantissa: u16, // 0..=9999
    pub exponent: u8,  // 0..=9
    pub tier: u8,      // 0..=9
}

impl Message {
    pub fn new(payee: u32, mantissa: u16, exponent: u8, tier: u8) -> Message {
        Message { payee, mantissa, exponent, tier }
    }
    /// The 18 digits, each 0..=9, one per column.
    pub fn digits(&self) -> [u8; COLS] {
        let mut d = [0u8; COLS];
        let mut p = self.payee as u64;
        for i in (0..PAYEE_DIGITS).rev() {
            d[i] = (p % 10) as u8;
            p /= 10;
        }
        d[PAYEE_DIGITS] = damm::check_digit(&d[..PAYEE_DIGITS]);
        let mut m = self.mantissa;
        for i in (12..16).rev() {
            d[i] = (m % 10) as u8;
            m /= 10;
        }
        d[16] = self.exponent;
        d[17] = self.tier;
        d
    }
    pub fn display(&self) -> String {
        let d = self.digits();
        let s: String = d.iter().map(|x| (b'0' + x) as char).collect();
        format!("{}-{} {} e{} f{}", &s[..11], &s[11..12], &s[12..16], &s[16..17], &s[17..])
    }
    pub fn is_zero(&self) -> bool { self.mantissa == 0 && self.exponent == 0 }
    pub fn is_sweep(&self) -> bool { self.mantissa == 0 && self.exponent == 9 }
    /// Amount in base units; `None` for a sweep.
    pub fn amount(&self) -> Option<u64> {
        if self.is_sweep() { None } else { Some(self.mantissa as u64 * 10u64.pow(self.exponent as u32)) }
    }
}

/// Decode and validate 18 digits. Every rule here is consensus.
pub fn parse(d: &[u8; COLS]) -> Result<Message, &'static str> {
    if d.iter().any(|&x| x > 9) {
        return Err("digit out of range");
    }
    if !damm::valid(&d[..PAYEE_DIGITS + 1]) {
        return Err("payee check digit wrong");
    }
    let payee = d[..PAYEE_DIGITS].iter().fold(0u64, |a, &x| a * 10 + x as u64);
    if payee > u32::MAX as u64 {
        return Err("payee number out of range");
    }
    let mantissa = d[12..16].iter().fold(0u16, |a, &x| a * 10 + x as u16);
    let m = Message { payee: payee as u32, mantissa, exponent: d[16], tier: d[17] };
    if m.mantissa == 0 && m.exponent != 0 && m.exponent != 9 {
        return Err("mantissa 0000 only with exponent 0 (zero) or 9 (sweep)");
    }
    if m.tier == 0 && !m.is_zero() {
        return Err("fee tier 0 only for zero-amount cheques");
    }
    Ok(m)
}
