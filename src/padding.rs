/// Description:
/// Does PKCS7 padding to a multiple of 16.
///
/// Arguments:
/// text - (I,REQ) - A string of hexadecimals where each digit is padded to length 2
///
/// Returns:
/// The unpadded text
#[allow(non_snake_case)]
pub fn PKCS7_padding(text: String) -> String {
    let n = text.len()/2;
    let padding = 16 - n % 16;
    let pad_str = format!("{:02x}", padding);
    let mut padded_string = String::with_capacity((n+padding)*2);
    padded_string.push_str(&text);
    for _ in 0..padding {
        padded_string.push_str(&pad_str);
    }

    padded_string
}

/// Description:
/// Unpads a string padded to a multiple of 16 with PKCS7.
///
/// Arguments:
/// text - (I,REQ) - A padded string of hexadecimals where each digit is padded to length 2
///
/// Returns:
/// The unpadded text
#[allow(non_snake_case)]
pub fn PKCS7_unpadding(text: String) -> String {
    let n = text.len();
    let padding = usize::from_str_radix(&text[(n-2)..],16).unwrap();

    text[0..(n-padding*2)].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(non_snake_case)]
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

    #[test]
    #[allow(non_snake_case)]
    fn PKCS7_unpadding_test() {
        let s = String::from("003F24F5G2570592A45EEA0505050505");
        let res = PKCS7_unpadding(s);
        let actual = String::from("003F24F5G2570592A45EEA");
        assert_eq!(res, actual);

        let s = String::from("003F24F5G2570592A45EEA050505050510101010101010101010101010101010");
        let res = PKCS7_unpadding(s);
        let actual = String::from("003F24F5G2570592A45EEA0505050505");
        assert_eq!(res, actual);
    }
}