//! Minimal unsigned 256-bit integer for proof-of-work targets: compare, add,
//! multiply/divide by u64, and Bitcoin's compact "bits" encoding.
use std::cmp::Ordering;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct U256(pub [u64; 4]); // little-endian limbs

impl U256 {
    pub const ZERO: U256 = U256([0; 4]);
    pub const MAX: U256 = U256([u64::MAX; 4]);

    pub fn one_shl(bits: u32) -> U256 {
        let mut v = [0u64; 4];
        if bits < 256 {
            v[(bits / 64) as usize] = 1u64 << (bits % 64);
        }
        U256(v)
    }
    pub fn from_u64(x: u64) -> U256 { U256([x, 0, 0, 0]) }

    /// Interpret a 32-byte hash as a little-endian integer (as Bitcoin does for PoW).
    pub fn from_le_bytes(b: &[u8; 32]) -> U256 {
        let mut v = [0u64; 4];
        for i in 0..4 {
            v[i] = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
        }
        U256(v)
    }
    pub fn is_zero(&self) -> bool { self.0 == [0; 4] }

    pub fn add(&self, o: &U256) -> U256 {
        let mut r = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let s = self.0[i] as u128 + o.0[i] as u128 + carry;
            r[i] = s as u64;
            carry = s >> 64;
        }
        U256(r)
    }
    pub fn mul_u64(&self, m: u64) -> U256 {
        let mut r = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            let p = self.0[i] as u128 * m as u128 + carry;
            r[i] = p as u64;
            carry = p >> 64;
        }
        if carry != 0 { return U256::MAX; }   // saturate: an easier-than-possible target is capped by the caller
        U256(r)
    }
    pub fn div_u64(&self, d: u64) -> U256 {
        let mut r = [0u64; 4];
        let mut rem = 0u128;
        for i in (0..4).rev() {
            let cur = (rem << 64) | self.0[i] as u128;
            r[i] = (cur / d as u128) as u64;
            rem = cur % d as u128;
        }
        U256(r)
    }
    pub fn bits(&self) -> u32 {
        for i in (0..4).rev() {
            if self.0[i] != 0 {
                return i as u32 * 64 + (64 - self.0[i].leading_zeros());
            }
        }
        0
    }
    pub fn shr(&self, s: u32) -> U256 {
        let mut r = [0u64; 4];
        let limb = (s / 64) as usize;
        let sh = s % 64;
        for i in 0..4 {
            if i + limb < 4 {
                r[i] = self.0[i + limb] >> sh;
                if sh > 0 && i + limb + 1 < 4 {
                    r[i] |= self.0[i + limb + 1] << (64 - sh);
                }
            }
        }
        U256(r)
    }
    pub fn shl(&self, s: u32) -> U256 {
        let mut r = [0u64; 4];
        let limb = (s / 64) as usize;
        let sh = s % 64;
        for i in (0..4).rev() {
            if i >= limb {
                r[i] = self.0[i - limb] << sh;
                if sh > 0 && i > limb {
                    r[i] |= self.0[i - limb - 1] >> (64 - sh);
                }
            }
        }
        U256(r)
    }
    pub fn low_u64(&self) -> u64 { self.0[0] }

    /// Bitcoin compact encoding: exponent byte + 3-byte mantissa.
    pub fn from_compact(bits: u32) -> U256 {
        let exp = bits >> 24;
        let mant = bits & 0x007F_FFFF;
        if exp <= 3 {
            U256::from_u64((mant >> (8 * (3 - exp))) as u64)
        } else {
            U256::from_u64(mant as u64).shl(8 * (exp - 3))
        }
    }
    pub fn to_compact(&self) -> u32 {
        let mut size = (self.bits() + 7) / 8;
        let mut mant: u64 = if size <= 3 {
            self.low_u64() << (8 * (3 - size))
        } else {
            self.shr(8 * (size - 3)).low_u64()
        };
        if mant & 0x0080_0000 != 0 {
            mant >>= 8;
            size += 1;
        }
        ((size << 24) | (mant as u32 & 0x007F_FFFF)) as u32
    }
}

impl Ord for U256 {
    fn cmp(&self, o: &U256) -> Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&o.0[i]) {
                Ordering::Equal => continue,
                x => return x,
            }
        }
        Ordering::Equal
    }
}
impl PartialOrd for U256 {
    fn partial_cmp(&self, o: &U256) -> Option<Ordering> { Some(self.cmp(o)) }
}
