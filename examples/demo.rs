//! Local demo chain for the website and explorer: `cargo run --release --example demo`.
//! Fast blocks (5 s target), a miner book, a two-domain printed book with its honesty check,
//! a payment each way, then steady mining. RPC on 127.0.0.1:8732. Sample seeds, not keys.
use bitcheque::{block::Chain, message::Message, net::{now, Node}, params::Params, store::Store, tx::Payment, u256::U256,
                wallet::{mine_registration, Book, Domain}};

fn main() {
    let p = Params { initial_bits: 0x1F0F_FFFF, min_bits: 0x1F0F_FFFF, block_target_seconds: 5, reg_pow_target: U256::MAX.shr(10), slow_start_blocks: 1,
                     reward_maturity: 2, number_maturity: 2, ..Params::testnet() };
    let g = Chain::genesis(&p, now() - 3600, b"Bitcheque local demo");
    let node = Node::new(Store::open(p.clone(), &g, None).unwrap());
    println!("rpc on {}", node.serve_rpc("127.0.0.1:8732").expect("port 8732 busy"));
    let mine = |n: u32| loop { let Ok(mut b) = node.template(n) else { continue }; b.header.mine(); if node.submit_block(&b, None).is_ok() { println!("block {}", node.height()); break; } };
    let miner = Book { salt: [1; 16], n256: false, book_size: 64, domains: vec![Domain([7; 32])] };
    let saver = Book { salt: [2; 16], n256: false, book_size: 11, domains: vec![Domain([8; 32])] };   // one seed
    let shop = Book { salt: [3; 16], n256: false, book_size: 11, domains: vec![Domain([10; 32])] };  // one seed
    let submit = |txs: Vec<bitcheque::tx::Tx>| for t in txs { node.submit_tx(t, None).unwrap(); };

    submit(vec![mine_registration(miner.register(0, 64, Payment::Pow(0)), p.reg_pow_target)]);
    mine(0); mine(1); mine(1); mine(1);                                   // number 1, reward matures
    submit(vec![mine_registration(saver.register(0, 16, Payment::Pow(0)), p.reg_pow_target)]);
    mine(1);
    submit(saver.sign(0, &Message::new(1, 0, 0, 0)));                     // honesty check (zero coins, any number)
    mine(1); mine(1);
    submit(miner.sign(0, &Message::new(2, 2500, 5, 1)));                  // 2.5 coins to the saver
    mine(1);
    submit(vec![mine_registration(shop.register(0, 16, Payment::Pow(0)), p.reg_pow_target)]);
    mine(1); mine(1); mine(1);
    let pieces = saver.sign(1, &Message::new(3, 4000, 4, 2));             // saver pays the shop 0.4 coins, in two parts
    submit(pieces[..12].to_vec()); mine(1);
    submit(pieces[12..].to_vec()); mine(1);
    println!("demo ready: accounts 1 (miner), 2 (saver), 3 (shop); mining continues");
    loop { mine(1); std::thread::sleep(std::time::Duration::from_secs(2)); }
}
