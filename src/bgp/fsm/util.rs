#![allow(dead_code)]

pub fn to_pcap<T: AsRef<[u8]>>(msg: T) -> String {
    let mut res = String::from("000000 ");
    for b in msg.as_ref() {
        res.push_str(&format!("{:02x} ", b));
    }
    res
}
