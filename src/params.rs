//! Consensus parameters fixed at genesis (DESIGN.md §12.1). Tests build a `Params`
//! with shorter maturities and easier targets; mainnet values are the defaults.
use crate::u256::U256;

pub const COIN: u64 = 100_000_000;

#[derive(Clone, Debug)]
pub struct Params {
    pub block_target_seconds: u32,
    pub reward_base: u64,
    pub halving_interval: u32,
    pub slow_start_blocks: u32,
    pub reward_maturity: u32,
    pub number_maturity: u32,
    pub lwma_window: usize,
    pub lwma_clamp: u64,
    pub initial_bits: u32,     // block 0's target (mined at startup, so it must be cheap)
    pub min_bits: u32,         // the easiest target any later block may use
    pub max_block_bytes: usize,
    pub max_future_seconds: u32,
    pub reg_pow_target: U256,
    pub reg_pow_window: u32,
    pub reg_pow_per_block_cap: u32,
    pub fee_unit: u64,
    pub reg_fee: u64,
    pub renew_fee: u64,
    pub unfunded_pow_lifetime: u32,
    pub number_quarantine: u32,
    pub batch_lifetime: u32,
    pub piece_lifetime: u32,
    pub max_batch: u32,
    pub max_book_size: u32,
    pub printed_book_size: u32,
    pub stall_relief: bool,   // a block more than 2 targets late may use a doubled target per 2 targets of silence (testnets)
    pub magic: [u8; 4],
}

impl Params {
    pub fn mainnet() -> Params {
        Params {
            // one-minute blocks with Bitcoin's issuance per hour: a tenth of the reward, ten times the blocks
            block_target_seconds: 60,
            reward_base: 5 * COIN,
            halving_interval: 2_100_000,   // about four years
            slow_start_blocks: 200_000,
            reward_maturity: 100,
            number_maturity: 100,
            lwma_window: 60,
            lwma_clamp: 3,
            initial_bits: 0x1E00_FFFF,
            min_bits: 0x1E00_FFFF,
            max_block_bytes: 1_000_000,    // about 1 MB a minute: well within what home connections relay
            max_future_seconds: 720,       // twelve blocks, as Bitcoin's two hours are twelve of its blocks
            reg_pow_target: U256::one_shl(228), // 2^256 / 2^28
            reg_pow_window: 20_160,        // two weeks
            reg_pow_per_block_cap: 200,
            fee_unit: 1000,
            reg_fee: 100 * 1000,
            renew_fee: 10 * 1000,
            unfunded_pow_lifetime: 43_200, // 30 days
            number_quarantine: 525_600,    // a year
            batch_lifetime: 2_100_000,     // about four years
            piece_lifetime: 10_000,        // about a week
            max_batch: 16,                 // every registration covers at most 16 cheques and pays its own proof of work
            max_book_size: 256,            // a book grows 16 cheques at a time, up to 256, on one account number
            printed_book_size: 11,
            stall_relief: false,
            magic: [0xBC, 0x4E, 0x51, 0x00],
        }
    }
    pub fn testnet() -> Params {
        // no slow start and stall relief: a public test network should hand out coins at once and never get stranded
        // the easiest target is about 2^19 hashes a block: under a second for any computer, and about a second for
        // the edge node's backup miner (WebAssembly, ~0.8 MH/s), which mines only when nobody else has for 50
        // seconds. Real miners joining raise it within a few blocks (LWMA, up to 3x per block).
        Params { initial_bits: 0x1F00_FFFF, min_bits: 0x1E20_0000, slow_start_blocks: 1, stall_relief: true, magic: [0xBC, 0x4E, 0x51, 0x01], ..Params::mainnet() }
    }
    /// Private network for running several nodes on one machine: 1-minute blocks, short maturities, easy work.
    pub fn local() -> Params {
        Params { block_target_seconds: 60, initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, slow_start_blocks: 1, reward_maturity: 10, number_maturity: 10,
                 reg_pow_target: U256::one_shl(240), stall_relief: true, magic: [0xBC, 0x4E, 0x51, 0x02], ..Params::mainnet() }
    }
    /// Block subsidy at `height` with the slow start of §12.5.
    pub fn block_reward(&self, height: u32) -> u64 {
        let halvings = height / self.halving_interval;
        if halvings >= 64 {
            return 0;
        }
        let base = self.reward_base >> halvings;
        if height < self.slow_start_blocks {
            (base as u128 * height as u128 / self.slow_start_blocks as u128) as u64
        } else {
            base
        }
    }
}

// genesis blocks (Chain::genesis(params, time, GENESIS_MESSAGE)); shared by the node and the edge node
pub const GENESIS_MESSAGE: &[u8] = b"Bitcheque genesis. Message text and launch timestamp to be set (DESIGN.md 12.4).";
pub const LAUNCH_TIME: u32 = 1_798_761_600; // placeholder: 2027-01-01 00:00 UTC (no block may precede it, §12.2)
pub const TESTNET_TIME: u32 = 1792245600; // launch of the public research network, 2026-10-17 14:00 UTC
pub const LOCAL_TIME: u32 = 1_790_000_000; // local devnet genesis, fixed so it never moves with the research network
