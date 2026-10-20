//! Test helper: mine one block the way `bitcheque mine` does (template, nonce search, submit).
use bitcheque::block::Block;
use bitcheque::net::Node;

pub fn mine(node: &Node, payee: u32) -> Result<Block, &'static str> {
    let mut b = node.template(payee)?;
    b.header.mine();
    node.submit_block(&b, None)?;
    Ok(b)
}
/// The node's tip hash: the anchor a registration's proof of work names.
#[allow(dead_code)]
pub fn tip(node: &Node) -> [u8; 32] { node.store.lock().unwrap().chain.tip() }
