mod util;
mod math;
mod cipher;

use cipher::{AES_decrypt,AES_encyrpt};

fn main() {
    let state: [[u8; 4]; 4] = [
        [0x6B, 0x2E, 0xE9, 0x73],
        [0xC1, 0x40, 0x3D, 0x93],
        [0xBE, 0x9F, 0x7E, 0x17],
        [0xE2, 0x96, 0x11, 0x2A],
    ];
    let key: [u32; 8] = [0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4];
    let res = AES_decrypt(AES_encyrpt(state, key),key);
    for row in res {
        for col in row {
            print!("0x{:x}, ", col);
        }
        println!();
    }
}
