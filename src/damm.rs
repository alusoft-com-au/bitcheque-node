//! Damm check digit (DESIGN.md §10.4). Consensus verifies it over the 12 payee digits.
const TABLE: [[u8; 10]; 10] = [
    [0,3,1,7,5,9,8,6,4,2],[7,0,9,2,1,5,4,8,6,3],[4,2,0,6,8,7,1,3,5,9],[1,7,5,0,9,8,3,4,2,6],
    [6,1,2,3,0,4,5,9,7,8],[3,6,7,4,2,0,9,5,8,1],[5,8,6,9,7,2,0,1,3,4],[8,9,4,5,3,6,2,0,1,7],
    [9,4,3,8,6,1,7,2,0,5],[2,5,8,1,4,3,6,7,9,0]];

pub fn interim(digits: &[u8]) -> u8 {
    digits.iter().fold(0u8, |i, &d| TABLE[i as usize][d as usize])
}
pub fn check_digit(digits: &[u8]) -> u8 { interim(digits) }
pub fn valid(digits_with_check: &[u8]) -> bool { interim(digits_with_check) == 0 }
