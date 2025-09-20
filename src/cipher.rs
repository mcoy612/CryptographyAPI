use crate::math::{byte_matrix_multiplication};
use crate::util::{rot_word,sub_word};
use crate::util::{RCON,SBOX};

#[allow(non_snake_case)]
pub fn AES_encyrpt(state: [[u8; 4]; 4], key: [u32; 8]) -> [[u8; 4]; 4] {
    let mut state = state;
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
    mix_columns(&mut state);

    state
}

#[allow(non_snake_case)]
pub fn AES_decrypt() {
    unimplemented!();
}

fn key_expansion(key: [u32; 8]) -> [[[u8; 4]; 4]; 15] {
    let mut words: [u32; 60] = [0; 60];
    let n = 8;

    for i in 0..60 {
        if i < n {
            words[i] = key[i]
        } else if i >= n && i % n == 0 {
            words[i] = words[i-n] ^ sub_word(rot_word(words[i-1])) ^ RCON[i/n];
        } else if i >= n && n > 6 && i % n == 4 {
            words[i] = words[i-n] ^ sub_word(words[i-1]);
        } else {
            words[i] = words[i-n] ^ words[i-1];
        }
    }

    let mut key_schedule: [[[u8; 4]; 4]; 15]  = [[[0; 4]; 4]; 15] ;
    for key in 0..15 {
        for i in 0..4 {
            for j in 0..4 {
                key_schedule[key][i][j] = ((words[4*key] + i as u32 >> 8*j) & 0b_1111_1111) as u8;
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
        assert_eq!(res,actual);     
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
        assert_eq!(res,actual);
    }

    #[test]
    fn mix_columns_test() {
        let mut res: [[u8; 4]; 4] = [
            [1,2,3,4],
            [5,6,7,8],
            [9,10,11,12],
            [13,14,15,16]
        ];
        mix_columns(&mut res);
        let actual: [[u8; 4]; 4] = [
            [1,2,3,4],
            [6,7,8,5],
            [11,12,9,10],
            [16,13,14,15]
        ];
        assert_eq!(res,actual);
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
        assert_eq!(res,actual);
    }
}