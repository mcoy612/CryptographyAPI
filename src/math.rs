static AES_IRREDUCIBLE_POLYNOMIAL: u16 = 0b_1_0001_1011;

/// Description:
/// Multiplies two bytes assuming the bytes are elements of 2Z[x]/p(x) where p(x) is the irreducible polynomial for AES.
///
/// Arguments:
/// a - (I,REQ) - byte
/// b - (I,REQ) - byte
///
/// Returns:
/// a*b
pub fn byte_multiplication(a: u8, b: u8) -> u8 {
    let a = a as u16;
    let b = b as u16;
    let mut product = 0b_0;

    // Do product in 2Z[x]
    let mut digit1: u16 = 0b_1_0000_0000;
    while digit1 != 0 {
        let mut digit2: u16 = 0b_1_0000_0000;
        while digit2 != 0 {
            product ^= (a & digit1) * (b & digit2);
            digit2 = digit2 >> 1;
        }
        digit1 = digit1 >> 1;
    }

    // Get remainder in 2Z[x]/p(x)
    for i in (8..16).rev() {
        let digit = (product >> i) & 1; // Get ith bit
        if digit == 1 {
            product ^= AES_IRREDUCIBLE_POLYNOMIAL << (i-8);
        }
    }

    product as u8
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_multiplication_test() {
        let a: u8 = 0b_0001_0000;
        let b: u8 = 0b_0001_0000;
        let res = byte_multiplication(a, b);
        let actual: u8 = 0b_0001_1011;
        assert_eq!(res, actual);

        let a: u8 = 0b_1111_1111;
        let b: u8 = 0b_0000_0000;
        let res = byte_multiplication(a, b);
        let actual: u8 = 0b_0000_0000;
        assert_eq!(res, actual);

        let a: u8 = 0b_1111_1111;
        let b: u8 = 0b_0000_0001;
        let res = byte_multiplication(a, b);
        let actual: u8 = 0b_1111_1111;
        assert_eq!(res, actual);
    }
}