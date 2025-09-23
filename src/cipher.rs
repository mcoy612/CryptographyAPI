use crate::padding::{PKCS7_padding,PKCS7_unpadding};
use crate::math::{byte_matrix_multiplication};
use crate::util::{block_to_message,message_to_block,rot_word,sub_word};
use crate::util::{RCON,SBOX,INV_SBOX};

#[allow(non_snake_case)]
pub fn AES_encrypt(plain_text: Vec<u8>, key: [u32; 8]) -> Vec<u8> {
    let plain_text = PKCS7_padding(plain_text);
    let n = plain_text.len();

    let mut cipher_text = Vec::with_capacity(n);
    for i in 0..n/16 {
        let message = &plain_text[16*i..(16*(i+1))];
        let message_block = message_to_block(message);
        let encrypted_block = AES_encrypt_block(message_block, key);
        let encrypted_text = block_to_message(encrypted_block);
        cipher_text.extend(encrypted_text);
    }

    cipher_text
}

#[allow(non_snake_case)]
pub fn AES_decrypt(cipher_text: Vec<u8>, key: [u32; 8]) -> Vec<u8> {
    let n = cipher_text.len();

    let mut plain_text = Vec::with_capacity(n);
    for i in 0..n/16 {
        let message = &cipher_text[16*i..(16*(i+1))];
        let message_block = message_to_block(message);
        let encrypted_block = AES_decrypt_block(message_block, key);
        let encrypted_text = block_to_message(encrypted_block);
        plain_text.extend(encrypted_text);
    }

    PKCS7_unpadding(plain_text)
}

#[allow(non_snake_case)]
fn AES_encrypt_block(plain_text: [[u8; 4]; 4], key: [u32; 8]) -> [[u8; 4]; 4] {
    let mut state = plain_text;
    let key_schedule = key_expansion(key);

    add_round_key(&mut state, key_schedule[0]);
    for i in 1..14 {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, key_schedule[i]);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, key_schedule[14]);

    state
}

#[allow(non_snake_case)]
fn AES_decrypt_block(cipher_text: [[u8; 4]; 4], key: [u32; 8]) -> [[u8; 4]; 4] {
    let mut state = cipher_text;
    let key_schedule = key_expansion(key);

    add_round_key(&mut state, key_schedule[14]);
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    for i in (1..14).rev() {
        add_round_key(&mut state, key_schedule[i]);
        inv_mix_columns(&mut state);
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
    }
    add_round_key(&mut state, key_schedule[0]);

    state
}

pub fn key_expansion(key: [u32; 8]) -> [[[u8; 4]; 4]; 15] {
    let mut words: [u32; 60] = [0; 60];
    let n = 8;

    for i in 0..60 {
        if i < n {
            words[i] = key[i]
        } else if i % n == 0 {
            words[i] = words[i-n] ^ sub_word(rot_word(words[i-1])) ^ RCON[i/n - 1];
        } else if n > 6 && i % n == 4 {
            words[i] = words[i-n] ^ sub_word(words[i-1]);
        } else {
            words[i] = words[i-n] ^ words[i-1];
        }
    }

    let mut key_schedule: [[[u8; 4]; 4]; 15]  = [[[0; 4]; 4]; 15];
    for round in 0..15 {
        for j in 0..4 {
            for i in 0..4 {
                key_schedule[round][i][j] = ((words[4*round+j] >> (8*(3-i))) & 0b_1111_1111) as u8;
            }
        }
    }

    key_schedule
}

fn sub_bytes(state: &mut [[u8; 4]; 4]) {
   for row in state {
        for byte in row {
            *byte = SBOX[*byte as usize];
        }
   }
}

fn inv_sub_bytes(state: &mut [[u8; 4]; 4]) {
   for row in state {
        for byte in row {
            *byte = INV_SBOX[*byte as usize];
        }
   }
}

fn shift_rows(state: &mut [[u8; 4]; 4]) {
    // Row 1
    // Nothing

    // Row 2
    let temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // Row 3
    let temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    let temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Row 4
    let temp = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}

fn inv_shift_rows(state: &mut [[u8; 4]; 4]) {
    // Row 1
    // Nothing

    // Row 2
    let temp = state[1][0];
    state[1][0] = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = temp;

    // Row 3
    let temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    let temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Row 4
    let temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

fn mix_columns(state: &mut [[u8; 4]; 4]) {
    let transform:[[u8; 4]; 4] = [
        [2, 3, 1, 1],
        [1, 2, 3, 1],
        [1, 1, 2, 3],
        [3, 1, 1, 2],
    ];

    for j in 0..4 {
        let mut col: [u8; 4] = [0; 4];
        for i in 0..4 {
            col[i] = state[i][j];
        }
        let res = byte_matrix_multiplication(&transform, &col);
        for i in 0..4 {
            state[i][j] = res[i];
        }
    }
}

fn inv_mix_columns(state: &mut [[u8; 4]; 4]) {
    let transform:[[u8; 4]; 4] = [
        [14, 11, 13, 9],
        [9, 14, 11, 13],
        [13, 9, 14, 11],
        [11, 13, 9, 14],
    ];

    for j in 0..4 {
        let mut col: [u8; 4] = [0; 4];
        for i in 0..4 {
            col[i] = state[i][j];
        }
        let res = byte_matrix_multiplication(&transform, &col);
        for i in 0..4 {
            state[i][j] = res[i];
        }
    }
}

fn add_round_key(state: &mut [[u8; 4]; 4], key: [[u8; 4]; 4]) {
    for i in 0..4 {
        for j in 0..4 {
            state[i][j] ^= key[i][j];
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn AES_encrypt_block_test() {
        let state = [
            [0x6b, 0x2e, 0xe9, 0x73],
            [0xc1, 0x40, 0x3d, 0x93],
            [0xbe, 0x9f, 0x7e, 0x17],
            [0xe2, 0x96, 0x11, 0x2a],
        ];
        let key: [u32; 8] = [0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4];
        let res = AES_encrypt_block(state, key);
        let actual = [
            [0xf3, 0xb5, 0x06, 0x3d],
            [0xee, 0xd2, 0x4b, 0xb1],
            [0xd1, 0xa0, 0x5a, 0x81],
            [0xbd, 0x3c, 0x7e, 0xf8],
        ];
        assert_eq!(res, actual)
    }

    #[test]
    #[allow(non_snake_case)]
    fn AES_decrypt_block_test() {
        let state = [
            [0xf3, 0xb5, 0x06, 0x3d],
            [0xee, 0xd2, 0x4b, 0xb1],
            [0xd1, 0xa0, 0x5a, 0x81],
            [0xbd, 0x3c, 0x7e, 0xf8],
        ];
        let key: [u32; 8] = [0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4];
        let res = AES_decrypt_block(state, key);
        let actual = [
            [0x6b, 0x2e, 0xe9, 0x73],
            [0xc1, 0x40, 0x3d, 0x93],
            [0xbe, 0x9f, 0x7e, 0x17],
            [0xe2, 0x96, 0x11, 0x2a],
        ];
        assert_eq!(res, actual)
    }

    #[test]
    fn key_expansion_test() {
        let key: [u32; 8] = [0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4];
        let res = key_expansion(key)[14];
        let actual: [[u8; 4]; 4] = [
            [0xfe, 0xe6, 0x04, 0x70],
            [0x48, 0x18, 0x6d, 0x6c],
            [0x90, 0x8d, 0xf3, 0x63],
            [0xd1, 0x0b, 0x44, 0x1e]
        ];
        assert_eq!(res, actual);
    }

    #[test]
    fn sub_bytes_test() {
        let mut res: [[u8; 4]; 4] = [
            [0x00,0x01,0x02,0x03],
            [0x04,0x05,0x06,0x07],
            [0x08,0x09,0x0A,0x0B],
            [0x0C,0x0D,0x0E,0x0F]
        ];
        sub_bytes(&mut res);
        let actual: [[u8; 4]; 4] = [
            [0x63,0x7C,0x77,0x7B],
            [0xF2,0x6B,0x6F,0xC5],
            [0x30,0x01,0x67,0x2B],
            [0xFE,0xD7,0xAB,0x76]
        ];
        assert_eq!(res, actual);     
    }

    #[test]
    fn inv_sub_bytes_test() {
        let mut res: [[u8; 4]; 4] = [
            [0x63,0x7C,0x77,0x7B],
            [0xF2,0x6B,0x6F,0xC5],
            [0x30,0x01,0x67,0x2B],
            [0xFE,0xD7,0xAB,0x76]
        ];
        inv_sub_bytes(&mut res);
        let actual: [[u8; 4]; 4] = [
            [0x00,0x01,0x02,0x03],
            [0x04,0x05,0x06,0x07],
            [0x08,0x09,0x0A,0x0B],
            [0x0C,0x0D,0x0E,0x0F]
        ];
        assert_eq!(res, actual);     
    }

    #[test]
    fn shift_rows_test() {
        let mut res: [[u8; 4]; 4] = [
            [1,2,3,4],
            [5,6,7,8],
            [9,10,11,12],
            [13,14,15,16]
        ];
        shift_rows(&mut res);
        let actual: [[u8; 4]; 4] = [
            [1,2,3,4],
            [6,7,8,5],
            [11,12,9,10],
            [16,13,14,15]
        ];
        assert_eq!(res, actual);
    }

    #[test]
    fn inv_shift_rows_test() {
        let mut res: [[u8; 4]; 4] = [
            [1,2,3,4],
            [6,7,8,5],
            [11,12,9,10],
            [16,13,14,15]
        ];
        inv_shift_rows(&mut res);
        let actual: [[u8; 4]; 4] = [
            [1,2,3,4],
            [5,6,7,8],
            [9,10,11,12],
            [13,14,15,16]
        ];
        assert_eq!(res, actual);
    }

    #[test]
    fn mix_columns_test() {
        let mut res: [[u8; 4]; 4] = [
            [0x63,0xF2,0x01,0xC6],
            [0x47,0x0A,0x01,0xC6],
            [0xA2,0x22,0x01,0xC6],
            [0xF0,0x5C,0x01,0xC6]
        ];
        mix_columns(&mut res);
        let actual: [[u8; 4]; 4] = [
            [0x5D,0x9F,0x01,0xC6],
            [0xE0,0xDC,0x01,0xC6],
            [0x70,0x58,0x01,0xC6],
            [0xBB,0x9D,0x01,0xC6]
        ];
        assert_eq!(res, actual);
    }

    #[test]
    fn inv_mix_columns_test() {
        let mut res: [[u8; 4]; 4] = [
            [0x5D,0x9F,0x01,0xC6],
            [0xE0,0xDC,0x01,0xC6],
            [0x70,0x58,0x01,0xC6],
            [0xBB,0x9D,0x01,0xC6]
        ];
        inv_mix_columns(&mut res);
        let actual: [[u8; 4]; 4] = [
            [0x63,0xF2,0x01,0xC6],
            [0x47,0x0A,0x01,0xC6],
            [0xA2,0x22,0x01,0xC6],
            [0xF0,0x5C,0x01,0xC6]
        ];
        assert_eq!(res, actual);
    }

    #[test]
    fn add_round_key_test() {
        let mut res: [[u8; 4]; 4] = [
            [1,2,3,4],
            [5,6,7,8],
            [9,10,11,12],
            [13,14,15,16]
        ];
        let key: [[u8; 4]; 4] = [
            [1,2,3,4],
            [5,6,7,8],
            [9,10,11,12],
            [13,14,15,16]
        ];
        add_round_key(&mut res, key);
        let actual: [[u8; 4]; 4] = [[0; 4]; 4];
        assert_eq!(res, actual);
    }
}