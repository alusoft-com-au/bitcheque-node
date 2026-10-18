//! Commitments and Merkle structure of a cheque book (DESIGN.md §3.2 rows 4-6).
//! Column tree: 10 commits padded to 16 zero leaves, depth 4. Cheque leaf: H over the
//! 18 column roots. Account tree: `book_size` leaves padded to a power of two.
use crate::crypto::{addr, h, TAG_ACCTNODE, TAG_COLNODE, TAG_COMMIT, TAG_SHARE, TAG_LEAF};
use crate::message::{COLS, ROWS};

pub type Bytes = Vec<u8>;
/// Share hashes of one cheque: `[col][row][k]`. A one-seed book has one share per cell; a split book has m.
pub type ChequeShares = Vec<Vec<Vec<Bytes>>>;
/// Commitments of one cheque: `[col][row]`.
pub type ChequeCommits = Vec<Vec<Bytes>>;

const COL_LEAVES: usize = 16;
const COL_DEPTH: u8 = 4;

pub fn share_hash(salt: &[u8; 16], n: usize, cheque: u16, col: u8, row: u8, k: u8, cell: &[u8]) -> Bytes {
    h(salt, n, &addr(TAG_SHARE, cheque, col, row, k), cell)
}
pub fn commit(salt: &[u8; 16], n: usize, cheque: u16, col: u8, row: u8, shares: &[Bytes]) -> Bytes {
    h(salt, n, &addr(TAG_COMMIT, cheque, col, row, 0), &shares.concat())
}
pub fn column_root(salt: &[u8; 16], n: usize, cheque: u16, col: u8, commits: &[Bytes]) -> Bytes {
    debug_assert_eq!(commits.len(), ROWS);
    let mut level: Vec<Bytes> = commits.to_vec();
    level.resize(COL_LEAVES, vec![0u8; n]);
    for lv in 1..=COL_DEPTH {
        level = (0..level.len() / 2)
            .map(|i| h(salt, n, &addr(TAG_COLNODE, cheque, col, i as u8, lv), &[level[2 * i].as_slice(), level[2 * i + 1].as_slice()].concat()))
            .collect();
    }
    level.pop().unwrap()
}
pub fn cheque_leaf(salt: &[u8; 16], n: usize, cheque: u16, col_roots: &[Bytes]) -> Bytes {
    debug_assert_eq!(col_roots.len(), COLS);
    h(salt, n, &addr(TAG_LEAF, cheque, 0, 0, 0), &col_roots.concat())
}
/// Leaf and commitments of a cheque from its submitted half hashes.
pub fn leaf_from_shares(salt: &[u8; 16], n: usize, cheque: u16, shares: &ChequeShares) -> (Bytes, ChequeCommits) {
    let commits: ChequeCommits = (0..COLS)
        .map(|c| (0..ROWS).map(|r| commit(salt, n, cheque, c as u8, r as u8, &shares[c][r])).collect())
        .collect();
    let roots: Vec<Bytes> = (0..COLS).map(|c| column_root(salt, n, cheque, c as u8, &commits[c])).collect();
    (cheque_leaf(salt, n, cheque, &roots), commits)
}
pub fn tree_depth(book_size: u32) -> u8 {
    let mut d = 0u8;
    while (1u64 << d) < book_size as u64 {
        d += 1;
    }
    d
}
fn acct_node(salt: &[u8; 16], n: usize, index: u32, level: u8, left: &[u8], right: &[u8]) -> Bytes {
    h(salt, n, &addr(TAG_ACCTNODE, (index & 0xFFFF) as u16, level, (index >> 16) as u8, 0), &[left, right].concat())
}
/// Root of an aligned subtree whose `leaves` (count a power of two) start at leaf `start`.
pub fn subtree_root(salt: &[u8; 16], n: usize, start: u32, leaves: &[Bytes]) -> Bytes {
    let mut level: Vec<Bytes> = leaves.to_vec();
    let mut lv = 0u8;
    let mut base = start; // index of the first node at this level
    while level.len() > 1 {
        lv += 1;
        base /= 2;
        level = (0..level.len() / 2)
            .map(|i| acct_node(salt, n, base + i as u32, lv, &level[2 * i], &level[2 * i + 1]))
            .collect();
    }
    level.pop().unwrap()
}
pub fn account_root(salt: &[u8; 16], n: usize, leaves: &[Bytes], book_size: u32) -> Bytes {
    let depth = tree_depth(book_size);
    let mut padded = leaves.to_vec();
    padded.resize(1usize << depth, vec![0u8; n]);
    subtree_root(salt, n, 0, &padded)
}
/// Climb from the root of subtree `[start, start+count)` to the account root via sibling `path`.
pub fn climb(salt: &[u8; 16], n: usize, start: u32, count: u32, sub_root: &[u8], path: &[Bytes], book_size: u32) -> Result<Bytes, &'static str> {
    let depth = tree_depth(book_size);
    let mut lv = (count.trailing_zeros()) as u8;
    let mut idx = start / count;
    let mut node = sub_root.to_vec();
    for sib in path {
        if sib.len() != n {
            return Err("path node has wrong length");
        }
        lv += 1;
        node = if idx % 2 == 0 { acct_node(salt, n, idx / 2, lv, &node, sib) } else { acct_node(salt, n, idx / 2, lv, sib, &node) };
        idx /= 2;
    }
    if lv != depth {
        return Err("path does not reach the account root");
    }
    Ok(node)
}
/// Sibling path for an aligned subtree, computed from all leaves (wallet side).
pub fn subtree_path(salt: &[u8; 16], n: usize, start: u32, count: u32, leaves: &[Bytes], book_size: u32) -> Vec<Bytes> {
    let depth = tree_depth(book_size);
    let mut padded = leaves.to_vec();
    padded.resize(1usize << depth, vec![0u8; n]);
    // build all levels
    let mut levels: Vec<Vec<Bytes>> = vec![padded];
    let mut lv = 0u8;
    while levels.last().unwrap().len() > 1 {
        lv += 1;
        let prev = levels.last().unwrap();
        let next: Vec<Bytes> = (0..prev.len() / 2).map(|i| acct_node(salt, n, i as u32, lv, &prev[2 * i], &prev[2 * i + 1])).collect();
        levels.push(next);
    }
    let mut path = Vec::new();
    let mut level = count.trailing_zeros() as usize;
    let mut idx = start / count;
    while level < depth as usize {
        path.push(levels[level][(idx ^ 1) as usize].clone());
        idx /= 2;
        level += 1;
    }
    path
}
