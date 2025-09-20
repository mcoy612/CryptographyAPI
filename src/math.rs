pub const AES_IRREDUCIBLE_POLYNOMIAL: u16 = 0b_1_0001_1011;

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

    byte_remainder(product, AES_IRREDUCIBLE_POLYNOMIAL) as u8
}

/// Description:
/// Finds the quotient of a when divided by b. 
/// Finds q in a = bq + r.
///
/// Arguments:
/// a - (I,REQ) - dividend
/// b - (I,REQ) - divisor
///
/// Returns:
/// floor of a/b
#[allow(dead_code)]
pub fn byte_quotient(a: u16, b: u16) -> u16 {
    assert!(b != 0, "Can't divide by 0");

    let mut degree: u16 = 0;
    while b >> degree+1 != 0 {
        degree += 1;
    }

    let mut a = a;
    let mut res = 0;
    for i in (degree..16).rev() {
        let digit = (a >> i) & 1; // Get ith bit
        if digit == 1 {
            res ^= digit << (i-degree);
            a ^= b << (i-degree);
        }
    }

    res
}

/// Description:
/// Finds the remainder of a when divided by b.
/// Finds r in a = bq + r.
/// 
/// Arguments:
/// a - (I,REQ) - dividend
/// b - (I,REQ) - divisor
///
/// Returns:
/// a modulo b
pub fn byte_remainder(a: u16, b: u16) -> u16 {
    assert!(b != 0, "Can't divide by 0");

    let mut degree: u16 = 0;
    while b >> degree+1 != 0 {
        degree += 1;
    }

    let mut a = a;
    for i in (degree..16).rev() {
        let digit = (a >> i) & 1; // Get ith bit
        if digit == 1 {
            a ^= b << (i-degree);
        }
    }

    a
}

/// Description:
/// Does matrix multiplication of a 4x4 matrix of bytes with a vector of bytes of size 4.
///
/// Arguments:
/// A - (I,REQ) - the matrix
/// B - (I,REQ) - the vector
///
/// Returns:
/// A * b
#[allow(dead_code)]
#[allow(non_snake_case)]
pub fn byte_matrix_multiplication(A: &[[u8; 4]; 4], b: &[u8; 4]) -> [u8; 4] {
    let mut res: [u8; 4] = [0; 4];
    for i in 0..4 {
        let mut sum: u8 = 0;
        for j in 0..4 {
            sum ^= byte_multiplication(A[i][j], b[j])
        }
        res[i] = sum;
    }

    res
}

/// Description:
/// Find b such that ab=1.
///
/// Arguments:
/// a - (I,REQ) - The number of find the inverse of.
/// 
/// Constraints:
/// a must be non-zero.
///
/// Returns:
/// The inverse of a.
#[allow(dead_code)]
pub fn byte_inverse(a: u8) -> u8 {
    assert!(a != 0, "0 does not have an inverse");

    let mut p = AES_IRREDUCIBLE_POLYNOMIAL;
    let mut a = a as u16;
    let mut combinations: Vec<u8> = Vec::new(); // (q,r) for each step of calculating GCD

    // Extended euclidean algorithm
    while a != 0 {
        let q = byte_quotient(p, a) as u8;
        let r = byte_remainder(p, a) as u8;
        p = a;
        a = r as u16;
        combinations.push(q);
    }

    let mut u = 0;
    let mut v = 1;
    combinations.pop();
    while let Some(q) = combinations.pop() {
        let temp = v;
        v = u ^ byte_multiplication(q, v);
        u = temp;
    }

    v
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

    #[test]
    fn byte_quotient_test() {
        let a: u16 = 0b_1101_1111_0010;
        let b: u16 = 0b_1_0101;
        let res = byte_quotient(a, b);
        let actual = 0b_1110_1011;
        assert_eq!(res, actual);

        let a: u16 = 0b_1_0101;
        let b: u16 = 0b_1101_1111_0010;
        let res = byte_quotient(a, b);
        let actual = 0b_0;
        assert_eq!(res, actual);
    }

    #[test]
    fn byte_remainder_test() {
        let a: u16 = 0b_1101_1111_0010;
        let b: u16 = 0b_1_0101;
        let res = byte_remainder(a, b);
        let actual = 0b_101;
        assert_eq!(res, actual);

        let a: u16 = 0b_1_0101;
        let b: u16 = 0b_1101_1111_0010;
        let res = byte_remainder(a, b);
        let actual = 0b_1_0101;
        assert_eq!(res, actual);
    }

    #[test]
    fn byte_inverse_test() {
        let a: u8 = 1;
        let res = byte_inverse(a);
        let actual = 1;
        assert_eq!(res, actual);

        let a: u8 = 0b_110_1100;
        let res = byte_inverse(a);
        let actual = 0b_11_0011;
        assert_eq!(res, actual);
    }
}