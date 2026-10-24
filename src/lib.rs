//! Bitcheque consensus core. Module map follows DESIGN.md:
//! params (§12.1) · crypto (§3.1) · damm/message (§10.2, §10.4) · book (§3.2 rows 4-6)
//! tx (§2.2) · state (§2.1, §10.11, §10.12) · block (§1, §12) · pow (§1.1) · wallet (§4, §5, non-consensus helpers)
pub mod params;
pub mod sha256;
pub mod crypto;
pub mod damm;
pub mod message;
pub mod book;
pub mod u256;
pub mod pow;
pub mod tx;
pub mod state;
pub mod block;
pub mod wallet;
pub mod store;
pub mod net;
pub mod rpc;
