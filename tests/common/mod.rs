//! Test helper: mine one block the way `bitcheque mine` does (template, nonce search, submit).
use bitcheque::block::Block;
use bitcheque::net::Node;

pub fn mine(node: &Node, payee: u32) -> Result<Block, &'static str> {
    let mut b = node.template(payee)?;
    b.header.mine();
    node.submit_block(&b, None)?;
    Ok(b)
}
