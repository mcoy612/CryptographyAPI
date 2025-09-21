/// Description:
/// Does PKCS7 padding to a multiple of 16.
///
/// Arguments:
/// plain_text - (I,REQ) - A string of hexadecimals where each digit is padded to length 2
///
/// Returns:
/// The padded plain text
#[allow(non_snake_case)]
pub fn PKCS7_padding(plain_text: String) -> String {
    let n = plain_text.len()/2;
    let empty = 16 - n % 16;
    let empty_str = format!("{:02x}", empty);
    let mut padded = String::with_capacity((n+empty)*2);
    padded.push_str(&plain_text);
    for _ in 0..empty {
        padded.push_str(&empty_str);
    }

    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn PKCS7_padding_test() {
        let s = String::from("003F24F5G2570592A45EEA");
        let res = PKCS7_padding(s);
        let actual = String::from("003F24F5G2570592A45EEA0505050505");
        assert_eq!(res, actual);

        let s = String::from("003F24F5G2570592A45EEA0505050505");
        let res = PKCS7_padding(s);
        let actual = String::from("003F24F5G2570592A45EEA050505050510101010101010101010101010101010");
        assert_eq!(res, actual);
    }
}