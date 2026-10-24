//! Consensus parameters fixed at genesis (DESIGN.md §12.1). Tests build a `Params`
//! with shorter maturities and easier targets; mainnet values are the defaults.
use crate::u256::U256;

pub const COIN: u64 = 100_000_000;
/// Cheques per registration: every batch has exactly this many (also the decoder's cap).
pub const MAX_BATCH: u32 = 16;
/// The public research network's magic. Its books derive cells without the magic, as they always have (DESIGN.md §4.2).
pub const TESTNET_MAGIC: [u8; 4] = [0xBC, 0x4E, 0x51, 0x01];

#[derive(Clone, Debug)]
pub struct Params {
    pub block_target_seconds: u32,
    pub reward_base: u64,
    pub halving_interval: u32,
    pub launch_blocks: u32,   // the launch year: blocks 1..=launch_blocks pay launch_reward
    pub launch_reward: u64,
    pub reward_maturity: u32,
    pub number_maturity: u32,
    pub lwma_window: usize,
    pub lwma_clamp: u64,
    pub initial_bits: u32,     // block 0's target (every node mines block 0 at start-up, without a table, so it must be cheap)
    pub min_bits: u32,         // the easiest target any later block may use
    pub max_block_bytes: usize,
    pub max_future_seconds: u32,
    pub reg_pow_target: U256,
    pub reg_pow_window: u32,   // the registration target's time constant: it moves by (window+1)/(window+reg_per_blocks×registrations) every block
    pub reg_per_blocks: u32,   // the registration target settles at one registration per this many blocks
    pub reg_anchor_window: u32, // a registration's proof of work names one of the last this many block hashes
    pub reg_pow_per_block_cap: u32,
    pub fee_unit: u64,
    pub reg_fee: u64,
    pub renew_fee: u64,
    pub min_fund: u64,         // a balance this large makes an account permanent (funded)
    pub renew_window: u32,     // a batch may be renewed only this close to its expiry (so a renewal, which anyone may send, costs its owner one fee per lifetime at most)
    pub max_reorg: u32,        // reorgs deeper than this need twice the work of what they replace (and snapshots are kept to cover this deep)
    pub unfunded_pow_lifetime: u32,
    pub number_quarantine: u32,
    pub batch_lifetime: u32,
    pub piece_lifetime: u32,
    pub max_batch: u32,
    pub book_size: u32,
    pub stall_relief: bool,   // a block more than 2 targets late may use a doubled target per further target of silence (testnets)
    pub magic: [u8; 4],
}

impl Params {
    pub fn mainnet() -> Params {
        Params {
            // one-minute blocks with Bitcoin's issuance per hour: a tenth of the reward, ten times the blocks
            block_target_seconds: 60,
            // a fair launch: the first year (525,000 blocks, about 365 days) mines 4 coins a block, 2,100,000 coins or
            // 10% of the supply, so people have time to hear of it and join. After that 4.5 coins, halving every
            // 2,100,000 blocks (about four years): 18,900,000 more, so each of years 2-4 mines more than the first.
            reward_base: 4 * COIN + COIN / 2,
            halving_interval: 2_100_000,   // about four years
            launch_blocks: 525_000,
            launch_reward: 4 * COIN,
            reward_maturity: 100,
            number_maturity: 100,
            lwma_window: 60,
            lwma_clamp: 3,
            initial_bits: 0x2004_0000,     // ~2^6 tries: a quarter of a second at start-up
            min_bits: 0x1E10_0000,         // the floor, ~2^20 tries: an hour for a processor without the table, nothing for a graphics card
            max_block_bytes: 1_000_000,    // about 1 MB a minute: well within what home connections relay
            max_future_seconds: 720,       // twelve blocks, as Bitcoin's two hours are twelve of its blocks
            reg_pow_target: U256::one_shl(228), // 2^256 / 2^28
            reg_pow_window: 1_440,         // a day: an empty block makes registering 0.07% easier (e-fold in a day), one
                                           // registration 0.6% harder, a block at the cap 10% harder (twice as hard in 7)
            reg_per_blocks: 10,            // one registration per 10 blocks at equilibrium (the edge node's memory, below)
            reg_anchor_window: 144,        // a mined registration must be mined into a block within about 2.4 hours
            reg_pow_per_block_cap: 16,     // about what fits in a block (a registration of 16 cheques is ~58 KB)
            fee_unit: 1000,
            reg_fee: 100 * 1000,
            renew_fee: 10 * 1000,
            min_fund: COIN,                // permanence costs a coin held, not one base unit
            renew_window: 43_200,          // the last 30 days of a batch's life
            max_reorg: 100,                // as deep as number_maturity: replacing a final number takes twice the work
            // a day. Worst-case state of unfunded registrations (each 16 cheques × 180 cells × 16 bytes ≈ 46 KB, twice that
            // for an n32 book's 32-byte cells): the target settles at one per 10 blocks, so at the floor target 1,440 / 10 =
            // 144 live ≈ 6.6 MB, about 13 MB if every one is an n32 book (the edge node's Durable Object has 128 MB; at the
            // former one a block for 4,320 blocks it was ~200 MB). More needs more work: within one lifetime, every further
            // 144 registrations (6.6-13 MB) make each one e ≈ 2.7 times harder, so 128 MB would need its last registrations
            // to cost ~10^4-10^8 floor registrations' work each
            unfunded_pow_lifetime: 1_440,
            number_quarantine: 525_600,    // a year
            batch_lifetime: 2_100_000,     // about four years
            piece_lifetime: 10_000,        // about a week
            max_batch: MAX_BATCH,           // every registration covers exactly 16 cheques and pays its own proof of work
            book_size: 256,                // every book: 256 cheques on one account number, registered 16 at a time
            stall_relief: false,
            magic: [0xBC, 0x4E, 0x51, 0x00],
        }
    }
    pub fn testnet() -> Params {
        // no slow start and stall relief: a public test network should hand out coins at once and never get stranded.
        // The floor is about 2^8 tries a block: a second for a processor without the table (about 250 tries a second a
        // core), and a second or two for the edge node's backup miner (WebAssembly, ~170 tries a second), which mines only
        // when nobody else has for 50 seconds. Real miners joining raise it within the LWMA window (up to 3x per block).
        Params { initial_bits: 0x2004_0000, min_bits: 0x2001_0000, stall_relief: true, magic: TESTNET_MAGIC, ..Params::mainnet() }
    }
    /// Private network for running several nodes on one machine: 1-minute blocks, short maturities, easy work.
    pub fn local() -> Params {
        Params { block_target_seconds: 60, initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, reward_maturity: 10, number_maturity: 10,
                 reg_pow_target: U256::one_shl(240), stall_relief: true, magic: [0xBC, 0x4E, 0x51, 0x02], ..Params::mainnet() }
    }
    /// The easiest target any block of this network may carry (block 0's or the floor, whichever is easier), compared as
    /// targets: the compact encodings are not ordered as integers (a larger exponent with a small mantissa can be harder).
    pub fn easiest_target(&self) -> U256 { U256::from_compact(self.min_bits).max(U256::from_compact(self.initial_bits)) }
    /// Block subsidy at `height` (§12.5): nothing for block 0, `launch_reward` through the launch year, then
    /// `reward_base` halving every `halving_interval` blocks.
    pub fn block_reward(&self, height: u32) -> u64 {
        if height == 0 { return 0; }
        if height <= self.launch_blocks { return self.launch_reward; }
        let halvings = (height - self.launch_blocks - 1) / self.halving_interval;
        if halvings >= 64 { 0 } else { self.reward_base >> halvings }
    }
    /// Every coin the schedule will ever create, in base units.
    pub fn max_supply(&self) -> u64 {
        self.launch_blocks as u64 * self.launch_reward + (0..64u32).map(|k| self.reward_base >> k).sum::<u64>() * self.halving_interval as u64
    }
    /// The first height above `height` where the reward halves (the end of the launch year raises it, so it does not count).
    pub fn next_halving(&self, height: u32) -> u32 {
        // halvings take effect at launch_blocks + k × halving_interval + 1, k = 1, 2, …
        let k = if height <= self.launch_blocks { 1 } else { (height - self.launch_blocks - 1) / self.halving_interval + 1 };
        self.launch_blocks + k * self.halving_interval + 1
    }
}

// genesis blocks (Chain::genesis(params, time, GENESIS_MESSAGE)); shared by the node and the edge node
pub const GENESIS_MESSAGE: &[u8] = b"Bitcheque genesis. Message text and launch timestamp to be set (DESIGN.md 12.4).";
pub const LAUNCH_TIME: u32 = 1_798_761_600; // placeholder: 2027-01-01 00:00 UTC (no block may precede it, §12.2)
pub const TESTNET_TIME: u32 = 1792245600; // launch of the public research network, 2026-10-17 14:00 UTC
pub const LOCAL_TIME: u32 = 1_790_000_000; // local devnet genesis, fixed so it never moves with the research network
