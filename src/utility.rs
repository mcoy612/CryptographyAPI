use crate::math::{byte_inverse,circular_left_bit_shift};

use std::io::{self, Write};

pub fn generate_s_box() {
    let inverse = 0;
    print!("0x{:x}, ", inverse ^ circular_left_bit_shift(inverse, 1) ^ circular_left_bit_shift(inverse, 2) ^ circular_left_bit_shift(inverse, 3) ^ circular_left_bit_shift(inverse, 4) ^ 0x63);
    for i in 1..=255 {
        let inverse = byte_inverse(i);
        print!("0x{:x}, ", inverse ^ circular_left_bit_shift(inverse, 1) ^ circular_left_bit_shift(inverse, 2) ^ circular_left_bit_shift(inverse, 3) ^ circular_left_bit_shift(inverse, 4) ^ 0x63);
    }
    io::stdout().flush().unwrap();
}